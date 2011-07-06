/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.core;

import java.math.BigInteger;
import java.util.*;

import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A BlockChain holds a series of {@link Block} objects, links them together, and knows how to verify that the
 * chain follows the rules of the {@link NetworkParameters} for this chain.<p>
 *
 * A BlockChain requires a {@link Wallet} to receive transactions that it finds during the initial download. However,
 * if you don't care about this, you can just pass in an empty wallet and nothing bad will happen.<p>
 *
 * A newly constructed BlockChain is empty. To fill it up, use a {@link Peer} object to download the chain from the
 * network.<p>
 *
 * <b>Notes</b><p>
 *
 * The 'chain' can actually be a tree although in normal operation it can be thought of as a simple list. In such a
 * situation there are multiple stories of the economy competing to become the one true consensus. This can happen
 * naturally when two miners solve a block within a few seconds of each other, or it can happen when the chain is
 * under attack.<p>
 *
 * A reference to the head block of every chain is stored. If you can reach the genesis block by repeatedly walking
 * through the prevBlock pointers, then we say this is a full chain. If you cannot reach the genesis block we say it is
 * an orphan chain.<p>
 *
 * Orphan chains can occur when blocks are solved and received during the initial block chain download,
 * or if we connect to a peer that doesn't send us blocks in order.
 */
public class BlockChain {
    private static final Logger log = LoggerFactory.getLogger(BlockChain.class);

    /** Keeps a map of block hashes to StoredBlocks. */
    protected BlockStore blockStore;

    /**
     * Tracks the top of the best known chain.<p>
     *
     * Following this one down to the genesis block produces the story of the economy from the creation of BitCoin
     * until the present day. The chain head can change if a new set of blocks is received that results in a chain of
     * greater work than the one obtained by following this one down. In that case a reorganize is triggered,
     * potentially invalidating transactions in our wallet.
     */
    protected StoredBlock chainHead;

    protected final NetworkParameters params;
    protected final List<Wallet> wallets;

    // Holds blocks that we have received but can't plug into the chain yet, eg because they were created whilst we
    // were downloading the block chain.
    private final ArrayList<Block> unconnectedBlocks = new ArrayList<Block>();

    /**
     * Constructs a BlockChain connected to the given wallet and store. To obtain a {@link Wallet} you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using {@link Wallet#loadFromFile(java.io.File)}
     * <p>
     *
     * For the store you can use a {@link com.google.bitcoin.store.MemoryBlockStore} if you don't care about saving the downloaded data, or a
     * {@link com.google.bitcoin.store.BoundedOverheadBlockStore} if you'd like to ensure fast startup the next time you run the program.
     */
    public BlockChain(NetworkParameters params, Wallet wallet, BlockStore blockStore) {
        this(params, new ArrayList<Wallet>(), blockStore);
        if (wallet != null)
            addWallet(wallet);
    }

    /**
     * Constructs a BlockChain that has no wallet at all. This is helpful when you don't actually care about sending
     * and receiving coins but rather, just want to explore the network data structures.
     */
    public BlockChain(NetworkParameters params, BlockStore blockStore) {
        this(params, new ArrayList<Wallet>(), blockStore);
    }
    
    /**
     * Constructs a BlockChain connected to the given list of wallets and a store. 
     */
    public BlockChain(NetworkParameters params, List<Wallet> wallets, BlockStore blockStore){
        try {
            this.blockStore = blockStore;
            chainHead = blockStore.getChainHead();
            log.info("chain head is:\n{}", chainHead.getHeader());
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
        }
        this.params = params;
        this.wallets = new ArrayList<Wallet>(wallets);
    }

    /**
     * Add a wallet to the BlockChain. Note that the wallet will be unaffected by any blocks received while it
     * was not part of this BlockChain. This method is useful if the wallet has just been created, and its keys 
     * have never been in use, or if the wallet has been loaded along with the BlockChain
     */
    public synchronized void addWallet(Wallet wallet) {
        wallets.add(wallet);
    }

    /**
     * Processes a received block and tries to add it to the chain. If there's something wrong with the block an
     * exception is thrown. If the block is OK but cannot be connected to the chain at this time, returns false.
     * If the block can be connected to the chain, returns true.
     */
    public synchronized boolean add(Block block) throws VerificationException, ScriptException {
        try {
            return add(block, true);
        } catch (BlockStoreException e) {
            // TODO: Figure out a better way to propagate this exception to the user.
            throw new RuntimeException(e);
        }
    }

    // Stat counters.
    private long statsLastTime = System.currentTimeMillis();
    private long statsBlocksAdded;

    private synchronized boolean add(Block block, boolean tryConnecting)
            throws BlockStoreException, VerificationException, ScriptException {
        if (System.currentTimeMillis() - statsLastTime > 1000) {
            // More than a second passed since last stats logging.
            log.info("{} blocks per second", statsBlocksAdded);
            statsLastTime = System.currentTimeMillis();
            statsBlocksAdded = 0;
        }
        // We check only the chain head for double adds here to avoid potentially expensive block chain misses.
        if (block.equals(chainHead.getHeader())) {
            // Duplicate add of the block at the top of the chain, can be a natural artifact of the download process.
            return true;
        }

        // Prove the block is internally valid: hash is lower than target, merkle root is correct and so on.
        try {
            block.verify();
        } catch (VerificationException e) {
            log.error("Failed to verify block:", e);
            log.error(block.toString());
            throw e;
        }

        // Try linking it to a place in the currently known blocks.
        StoredBlock storedPrev = blockStore.get(block.getPrevBlockHash());

        if (storedPrev == null) {
            // We can't find the previous block. Probably we are still in the process of downloading the chain and a
            // block was solved whilst we were doing it. We put it to one side and try to connect it later when we
            // have more blocks.
            log.warn("Block does not connect: {}", block.getHashAsString());
            unconnectedBlocks.add(block);
            return false;
        } else {
            // It connects to somewhere on the chain. Not necessarily the top of the best known chain.
            //
            // Create a new StoredBlock from this block. It will throw away the transaction data so when block goes
            // out of scope we will reclaim the used memory.
            StoredBlock newStoredBlock = storedPrev.build(block);
            checkDifficultyTransitions(storedPrev, newStoredBlock);
            blockStore.put(newStoredBlock);
            // block.transactions may be null here if we received only a header and not a full block. This does not
            // happen currently but might in future if getheaders is implemented.
            connectBlock(newStoredBlock, storedPrev, block.transactions);
        }

        if (tryConnecting)
            tryConnectingUnconnected();

        statsBlocksAdded++;
        return true;
    }

    private void connectBlock(StoredBlock newStoredBlock, StoredBlock storedPrev, List<Transaction> newTransactions)
            throws BlockStoreException, VerificationException {
        if (storedPrev.equals(chainHead)) {
            // This block connects to the best known block, it is a normal continuation of the system.
            setChainHead(newStoredBlock);
            log.trace("Chain is now {} blocks high", chainHead.getHeight());
            if (newTransactions != null)
                sendTransactionsToWallet(newStoredBlock, NewBlockType.BEST_CHAIN, newTransactions);
        } else {
            // This block connects to somewhere other than the top of the best known chain. We treat these differently.
            //
            // Note that we send the transactions to the wallet FIRST, even if we're about to re-organize this block
            // to become the new best chain head. This simplifies handling of the re-org in the Wallet class.
            boolean haveNewBestChain = newStoredBlock.moreWorkThan(chainHead);
            if (haveNewBestChain) {
                log.info("Block is causing a re-organize");
            } else {
                StoredBlock splitPoint = findSplit(newStoredBlock, chainHead);
                String splitPointHash =
                        splitPoint != null ? splitPoint.getHeader().getHashAsString() : "?";
                log.info("Block forks the chain at {}, but it did not cause a reorganize:\n{}",
                          splitPointHash, newStoredBlock);
            }

            // We may not have any transactions if we received only a header. That never happens today but will in
            // future when getheaders is used as an optimization.
            if (newTransactions != null) {
                sendTransactionsToWallet(newStoredBlock, NewBlockType.SIDE_CHAIN, newTransactions);
            }

            if (haveNewBestChain)
                handleNewBestChain(newStoredBlock);
        }
    }

    /**
     * Called as part of connecting a block when the new block results in a different chain having higher total work.
     */
    private void handleNewBestChain(StoredBlock newChainHead) throws BlockStoreException, VerificationException {
        // This chain has overtaken the one we currently believe is best. Reorganize is required.
        //
        // Firstly, calculate the block at which the chain diverged. We only need to examine the
        // chain from beyond this block to find differences.
        StoredBlock splitPoint = findSplit(newChainHead, chainHead);
        log.info("Re-organize after split at height {}", splitPoint.getHeight());
        log.info("Old chain head: {}", chainHead.getHeader().getHashAsString());
        log.info("New chain head: {}", newChainHead.getHeader().getHashAsString());
        log.info("Split at block: {}", splitPoint.getHeader().getHashAsString());
        // Then build a list of all blocks in the old part of the chain and the new part.
        List<StoredBlock> oldBlocks = getPartialChain(chainHead, splitPoint);
        List<StoredBlock> newBlocks = getPartialChain(newChainHead, splitPoint);
        // Now inform the wallets. This is necessary so the set of currently active transactions (that we can spend)
        // can be updated to take into account the re-organize. We might also have received new coins we didn't have
        // before and our previous spends might have been undone.
        for (Wallet wallet : wallets) {
            wallet.reorganize(oldBlocks, newBlocks);
        }
        // Update the pointer to the best known block.
        setChainHead(newChainHead);
    }

    /**
     * Returns the set of contiguous blocks between 'higher' and 'lower'. Higher is included, lower is not.
     */
    private List<StoredBlock> getPartialChain(StoredBlock higher, StoredBlock lower) throws BlockStoreException {
        assert higher.getHeight() > lower.getHeight();
        LinkedList<StoredBlock> results = new LinkedList<StoredBlock>();
        StoredBlock cursor = higher;
        while (true) {
            results.add(cursor);
            cursor = cursor.getPrev(blockStore);
            assert cursor != null : "Ran off the end of the chain";
            if (cursor.equals(lower)) break;
        }
        return results;
    }

    /**
     * Locates the point in the chain at which newStoredBlock and chainHead diverge. Returns null if no split point was
     * found (ie they are part of the same chain).
     */
    private StoredBlock findSplit(StoredBlock newChainHead, StoredBlock chainHead) throws BlockStoreException {
        StoredBlock currentChainCursor = chainHead;
        StoredBlock newChainCursor = newChainHead;
        // Loop until we find the block both chains have in common. Example:
        //
        //    A -> B -> C -> D
        //         \--> E -> F -> G
        //
        // findSplit will return block B. chainHead = D and newChainHead = G.
        while (!currentChainCursor.equals(newChainCursor)) {
            if (currentChainCursor.getHeight() > newChainCursor.getHeight()) {
                currentChainCursor = currentChainCursor.getPrev(blockStore);
                assert currentChainCursor != null : "Attempt to follow an orphan chain";
            } else {
                newChainCursor = newChainCursor.getPrev(blockStore);
                assert newChainCursor != null : "Attempt to follow an orphan chain";
            }
        }
        return currentChainCursor;
    }

    enum NewBlockType {
        BEST_CHAIN,
        SIDE_CHAIN
    }

    private void sendTransactionsToWallet(StoredBlock block, NewBlockType blockType,
                                          List<Transaction> newTransactions) throws VerificationException {
        // Scan the transactions to find out if any mention addresses we own.
        for (Transaction tx : newTransactions) {
            try {
                scanTransaction(block, tx, blockType);
            } catch (ScriptException e) {
                // We don't want scripts we don't understand to break the block chain,
                // so just note that this tx was not scanned here and continue.
                log.warn("Failed to parse a script: " + e.toString());
            }
        }
    }

    private void setChainHead(StoredBlock chainHead) {
        this.chainHead = chainHead;
        try {
            blockStore.setChainHead(chainHead);
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * For each block in unconnectedBlocks, see if we can now fit it on top of the chain and if so, do so.
     */
    private void tryConnectingUnconnected() throws VerificationException, ScriptException, BlockStoreException {
        // For each block in our unconnected list, try and fit it onto the head of the chain. If we succeed remove it
        // from the list and keep going. If we changed the head of the list at the end of the round try again until
        // we can't fit anything else on the top.
        int blocksConnectedThisRound;
        do {
            blocksConnectedThisRound = 0;
            Iterator<Block> iter = unconnectedBlocks.iterator();
            while (iter.hasNext()) {
                Block block = iter.next();
                // Look up the blocks previous.
                StoredBlock prev = blockStore.get(block.getPrevBlockHash());
                if (prev == null) {
                    // This is still an unconnected/orphan block.
                    continue;
                }
                // Otherwise we can connect it now.
                // False here ensures we don't recurse infinitely downwards when connecting huge chains.
                add(block, false);
                iter.remove();
                blocksConnectedThisRound++;
            }
            if (blocksConnectedThisRound > 0) {
                log.info("Connected {} floating blocks.", blocksConnectedThisRound);
            }
        } while (blocksConnectedThisRound > 0);
    }

    /**
     * Throws an exception if the blocks difficulty is not correct.
     */
    private void checkDifficultyTransitions(StoredBlock storedPrev, StoredBlock storedNext)
            throws BlockStoreException, VerificationException {
        Block prev = storedPrev.getHeader();
        Block next = storedNext.getHeader();
        // Is this supposed to be a difficulty transition point?
        if ((storedPrev.getHeight() + 1) % params.interval != 0) {
            // No ... so check the difficulty didn't actually change.
            if (next.getDifficultyTarget() != prev.getDifficultyTarget())
                throw new VerificationException("Unexpected change in difficulty at height " + storedPrev.getHeight() +
                        ": " + Long.toHexString(next.getDifficultyTarget()) + " vs " +
                        Long.toHexString(prev.getDifficultyTarget()));
            return;
        }

        // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
        // two weeks after the initial block chain download.
        long now = System.currentTimeMillis();
        StoredBlock cursor = blockStore.get(prev.getHash());
        for (int i = 0; i < params.interval - 1; i++) {
            if (cursor == null) {
                // This should never happen. If it does, it means we are following an incorrect or busted chain.
                throw new VerificationException(
                        "Difficulty transition point but we did not find a way back to the genesis block.");
            }
            cursor = blockStore.get(cursor.getHeader().getPrevBlockHash());
        }
        log.info("Difficulty transition traversal took {}msec", System.currentTimeMillis() - now);

        Block blockIntervalAgo = cursor.getHeader();
        int timespan = (int) (prev.getTime() - blockIntervalAgo.getTime());
        // Limit the adjustment step.
        if (timespan < params.targetTimespan / 4)
            timespan = params.targetTimespan / 4;
        if (timespan > params.targetTimespan * 4)
            timespan = params.targetTimespan * 4;

        BigInteger newDifficulty = Utils.decodeCompactBits(blockIntervalAgo.getDifficultyTarget());
        newDifficulty = newDifficulty.multiply(BigInteger.valueOf(timespan));
        newDifficulty = newDifficulty.divide(BigInteger.valueOf(params.targetTimespan));

        if (newDifficulty.compareTo(params.proofOfWorkLimit) > 0) {
            log.warn("Difficulty hit proof of work limit: {}", newDifficulty.toString(16));
            newDifficulty = params.proofOfWorkLimit;
        }

        int accuracyBytes = (int) (next.getDifficultyTarget() >>> 24) - 3;
        BigInteger receivedDifficulty = next.getDifficultyTargetAsInteger();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newDifficulty = newDifficulty.and(mask);

        if (newDifficulty.compareTo(receivedDifficulty) != 0)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    receivedDifficulty.toString(16) + " vs " + newDifficulty.toString(16));
    }

    private void scanTransaction(StoredBlock block, Transaction tx, NewBlockType blockType)
            throws ScriptException, VerificationException {
        for (Wallet wallet : wallets) {
            boolean shouldReceive = false;
            for (TransactionOutput output : tx.outputs) {
                // TODO: Handle more types of outputs, not just regular to address outputs.
                if (output.getScriptPubKey().isSentToIP()) return;
                // This is not thread safe as a key could be removed between the call to isMine and receive.
                if (output.isMine(wallet)) {
                    shouldReceive = true;
                }
            }
    
            // Coinbase transactions don't have anything useful in their inputs (as they create coins out of thin air).
            if (!tx.isCoinBase()) {
                for (TransactionInput i : tx.inputs) {
                    byte[] pubkey = i.getScriptSig().getPubKey();
                    // This is not thread safe as a key could be removed between the call to isPubKeyMine and receive.
                    if (wallet.isPubKeyMine(pubkey)) {
                        shouldReceive = true;
                    }
                }
            }
    
            if (shouldReceive)
                wallet.receive(tx, block, blockType);
            }
    }

    /**
     * Returns the block at the head of the current best chain. This is the block which represents the greatest
     * amount of cumulative work done.
     */
    public synchronized StoredBlock getChainHead() {
        return chainHead;
    }


    /**
     * Returns the most recent unconnected block or null if there are none. This will all have to change.
     */
    public synchronized Block getUnconnectedBlock() {
        if (unconnectedBlocks.size() == 0)
            return null;
        return unconnectedBlocks.get(unconnectedBlocks.size() - 1);
    }
}
