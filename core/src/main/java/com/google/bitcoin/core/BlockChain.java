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

import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.*;

import static com.google.common.base.Preconditions.*;

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
    protected final BlockStore blockStore;

    /**
     * Tracks the top of the best known chain.<p>
     *
     * Following this one down to the genesis block produces the story of the economy from the creation of BitCoin
     * until the present day. The chain head can change if a new set of blocks is received that results in a chain of
     * greater work than the one obtained by following this one down. In that case a reorganize is triggered,
     * potentially invalidating transactions in our wallet.
     */
    protected StoredBlock chainHead;

    // The chainHead field is read/written synchronized with this object rather than BlockChain. However writing is
    // also guaranteed to happen whilst BlockChain is synchronized (see setChainHead). The goal of this is to let
    // clients quickly access the chain head even whilst the block chain is downloading and thus the BlockChain is
    // locked most of the time.
    protected final Object chainHeadLock = new Object();

    protected final NetworkParameters params;
    protected final List<Wallet> wallets;

    // Holds blocks that we have received but can't plug into the chain yet, eg because they were created whilst we
    // were downloading the block chain.
    private final ArrayList<Block> unconnectedBlocks = new ArrayList<Block>();

    /**
     * Constructs a BlockChain connected to the given wallet and store. To obtain a {@link Wallet} you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using {@link Wallet#loadFromFile(java.io.File)}
     * <p/>
     *
     * For the store you can use a {@link com.google.bitcoin.store.MemoryBlockStore} if you don't care about saving the downloaded data, or a
     * {@link com.google.bitcoin.store.BoundedOverheadBlockStore} if you'd like to ensure fast startup the next time you run the program.
     */
    public BlockChain(NetworkParameters params, Wallet wallet, BlockStore blockStore) throws BlockStoreException {
        this(params, new ArrayList<Wallet>(), blockStore);
        if (wallet != null)
            addWallet(wallet);
    }

    /**
     * Constructs a BlockChain that has no wallet at all. This is helpful when you don't actually care about sending
     * and receiving coins but rather, just want to explore the network data structures.
     */
    public BlockChain(NetworkParameters params, BlockStore blockStore) throws BlockStoreException {
        this(params, new ArrayList<Wallet>(), blockStore);
    }

    /**
     * Constructs a BlockChain connected to the given list of wallets and a store.
     */
    public BlockChain(NetworkParameters params, List<Wallet> wallets,
                      BlockStore blockStore) throws BlockStoreException {
        this.blockStore = blockStore;
        chainHead = blockStore.getChainHead();
        log.info("chain head is at height {}:\n{}", chainHead.getHeight(), chainHead.getHeader());
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
     * Returns the {@link BlockStore} the chain was constructed with. You can use this to iterate over the chain.
     */
    public BlockStore getBlockStore() {
        return blockStore;
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
        // Note on locking: this method runs with the block chain locked. All mutations to the chain are serialized.
        // This has the undesirable consequence that during block chain download, it's slow to read the current chain
        // head and other chain info because the accessors are constantly waiting for the chain to become free. To
        // solve this things viewable via accessors must use fine-grained locking as well as being mutated under the
        // chain lock.
        if (System.currentTimeMillis() - statsLastTime > 1000) {
            // More than a second passed since last stats logging.
            if (statsBlocksAdded > 1)
                log.info("{} blocks per second", statsBlocksAdded);
            statsLastTime = System.currentTimeMillis();
            statsBlocksAdded = 0;
        }
        // We check only the chain head for double adds here to avoid potentially expensive block chain misses.
        if (block.equals(getChainHead().getHeader())) {
            // Duplicate add of the block at the top of the chain, can be a natural artifact of the download process.
            log.debug("Chain head added more than once: {}", block.getHash());
            return true;
        }

        // Does this block contain any transactions we might care about? Check this up front before verifying the
        // blocks validity so we can skip the merkle root verification if the contents aren't interesting. This saves
        // a lot of time for big blocks.
        boolean contentsImportant = false;
        if (block.transactions != null) {
            contentsImportant = containsRelevantTransactions(block);
        }

        // Prove the block is internally valid: hash is lower than target, etc. This only checks the block contents
        // if there is a tx sending or receiving coins using an address in one of our wallets. And those transactions
        // are only lightly verified: presence in a valid connecting block is taken as proof of validity. See the
        // article here for more details: http://code.google.com/p/bitcoinj/wiki/SecurityModel
        try {
            block.verifyHeader();
            if (contentsImportant)
                block.verifyTransactions();
        } catch (VerificationException e) {
            log.error("Failed to verify block: ", e);
            log.error(block.getHashAsString());
            throw e;
        }

        // Try linking it to a place in the currently known blocks.
        StoredBlock storedPrev = blockStore.get(block.getPrevBlockHash());

        if (storedPrev == null) {
            // We can't find the previous block. Probably we are still in the process of downloading the chain and a
            // block was solved whilst we were doing it. We put it to one side and try to connect it later when we
            // have more blocks.
            checkState(tryConnecting, "bug in tryConnectingUnconnected");
            log.warn("Block does not connect: {} prev {}", block.getHashAsString(), block.getPrevBlockHash());
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
            connectBlock(newStoredBlock, storedPrev, block.transactions);
        }

        if (tryConnecting)
            tryConnectingUnconnected();

        statsBlocksAdded++;
        return true;
    }

    private void connectBlock(StoredBlock newStoredBlock, StoredBlock storedPrev,
                              List<Transaction> transactions)
            throws BlockStoreException, VerificationException {
        StoredBlock head = getChainHead();
        if (storedPrev.equals(head)) {
            // This block connects to the best known block, it is a normal continuation of the system.
            setChainHead(newStoredBlock);
            log.debug("Chain is now {} blocks high", newStoredBlock.getHeight());
            if (transactions != null)
                sendTransactionsToWallet(newStoredBlock, NewBlockType.BEST_CHAIN, transactions);
        } else {
            // This block connects to somewhere other than the top of the best known chain. We treat these differently.
            //
            // Note that we send the transactions to the wallet FIRST, even if we're about to re-organize this block
            // to become the new best chain head. This simplifies handling of the re-org in the Wallet class.
            boolean haveNewBestChain = newStoredBlock.moreWorkThan(head);
            if (haveNewBestChain) {
                log.info("Block is causing a re-organize");
            } else {
                StoredBlock splitPoint = findSplit(newStoredBlock, head);
                if (splitPoint == newStoredBlock) {
                    // newStoredBlock is a part of the same chain, there's no fork. This happens when we receive a block
                    // that we already saw and linked into the chain previously, which isn't the chain head.
                    // Re-processing it is confusing for the wallet so just skip.
                    log.warn("Saw duplicated block in main chain at height {}: {}",
                            newStoredBlock.getHeight(), newStoredBlock.getHeader().getHash());
                    return;
                }
                if (splitPoint == null) {
                    log.error("Block forks the chain but splitPoint is null");
                } else {
                    int splitPointHeight = splitPoint.getHeight();
                    String splitPointHash = splitPoint.getHeader().getHashAsString();
                    log.info("Block forks the chain at height {}/block {}, but it did not cause a reorganize:\n{}",
                        new Object[]{splitPointHeight, splitPointHash, newStoredBlock});
                }
            }

            // We may not have any transactions if we received only a header, which can happen during fast catchup.
            // If we do, send them to the wallet but state that they are on a side chain so it knows not to try and
            // spend them until they become activated.
            if (transactions != null) {
                sendTransactionsToWallet(newStoredBlock, NewBlockType.SIDE_CHAIN, transactions);
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
        StoredBlock head = getChainHead();
        StoredBlock splitPoint = findSplit(newChainHead, head);
        log.info("Re-organize after split at height {}", splitPoint.getHeight());
        log.info("Old chain head: {}", head.getHeader().getHashAsString());
        log.info("New chain head: {}", newChainHead.getHeader().getHashAsString());
        log.info("Split at block: {}", splitPoint.getHeader().getHashAsString());
        // Then build a list of all blocks in the old part of the chain and the new part.
        List<StoredBlock> oldBlocks = getPartialChain(head, splitPoint);
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
        checkArgument(higher.getHeight() > lower.getHeight(), "higher and lower are reversed");
        LinkedList<StoredBlock> results = new LinkedList<StoredBlock>();
        StoredBlock cursor = higher;
        while (true) {
            results.add(cursor);
            cursor = checkNotNull(cursor.getPrev(blockStore), "Ran off the end of the chain");
            if (cursor.equals(lower)) break;
        }
        return results;
    }

    /**
     * Locates the point in the chain at which newStoredBlock and chainHead diverge. Returns null if no split point was
     * found (ie they are not part of the same chain). Returns newChainHead or chainHead if they don't actually diverge
     * but are part of the same chain.
     */
    private StoredBlock findSplit(StoredBlock newChainHead, StoredBlock oldChainHead) throws BlockStoreException {
        StoredBlock currentChainCursor = oldChainHead;
        StoredBlock newChainCursor = newChainHead;
        // Loop until we find the block both chains have in common. Example:
        //
        //    A -> B -> C -> D
        //         \--> E -> F -> G
        //
        // findSplit will return block B. oldChainHead = D and newChainHead = G.
        while (!currentChainCursor.equals(newChainCursor)) {
            if (currentChainCursor.getHeight() > newChainCursor.getHeight()) {
                currentChainCursor = currentChainCursor.getPrev(blockStore);
                checkNotNull(currentChainCursor, "Attempt to follow an orphan chain");
            } else {
                newChainCursor = newChainCursor.getPrev(blockStore);
                checkNotNull(newChainCursor, "Attempt to follow an orphan chain");
            }
        }
        return currentChainCursor;
    }

    /**
     * @return the height of the best known chain, convenience for <tt>getChainHead().getHeight()</tt>.
     */
    public int getBestChainHeight() {
        return getChainHead().getHeight();
    }

    public enum NewBlockType {
        BEST_CHAIN,
        SIDE_CHAIN
    }

    private void sendTransactionsToWallet(StoredBlock block, NewBlockType blockType,
                                          List<Transaction> transactions) throws VerificationException {
        for (Transaction tx : transactions) {
            for (Wallet wallet : wallets) {
                try {
                    if (wallet.isTransactionRelevant(tx, true))
                        wallet.receiveFromBlock(tx, block, blockType);
                } catch (ScriptException e) {
                    // We don't want scripts we don't understand to break the block chain so just note that this tx was
                    // not scanned here and continue.
                    log.warn("Failed to parse a script: " + e.toString());
                }
            }
        }
    }

    private void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        blockStore.setChainHead(chainHead);
        synchronized (chainHeadLock) {
            this.chainHead = chainHead;
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
                log.debug("Trying to connect {}", block.getHash());
                // Look up the blocks previous.
                StoredBlock prev = blockStore.get(block.getPrevBlockHash());
                if (prev == null) {
                    // This is still an unconnected/orphan block.
                    log.debug("  but it is not connectable right now");
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

    // February 16th 2012
    private static Date testnetDiffDate = new Date(1329264000000L);

    /**
     * Throws an exception if the blocks difficulty is not correct.
     */
    private void checkDifficultyTransitions(StoredBlock storedPrev, StoredBlock storedNext)
            throws BlockStoreException, VerificationException {
        Block prev = storedPrev.getHeader();
        Block next = storedNext.getHeader();

        // Is this supposed to be a difficulty transition point?
        if ((storedPrev.getHeight() + 1) % params.interval != 0) {

            // TODO: Refactor this hack after 0.5 is released and we stop supporting deserialization compatibility.
            // This should be a method of the NetworkParameters, which should in turn be using singletons and a subclass
            // for each network type. Then each network can define its own difficulty transition rules.
            if (params.getId().equals(NetworkParameters.ID_TESTNET) && next.getTime().after(testnetDiffDate)) {
                checkTestnetDifficulty(storedPrev, prev, next);
                return;
            }

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
        int timespan = (int) (prev.getTimeSeconds() - blockIntervalAgo.getTimeSeconds());
        // Limit the adjustment step.
        if (timespan < params.targetTimespan / 4)
            timespan = params.targetTimespan / 4;
        if (timespan > params.targetTimespan * 4)
            timespan = params.targetTimespan * 4;

        BigInteger newDifficulty = Utils.decodeCompactBits(blockIntervalAgo.getDifficultyTarget());
        newDifficulty = newDifficulty.multiply(BigInteger.valueOf(timespan));
        newDifficulty = newDifficulty.divide(BigInteger.valueOf(params.targetTimespan));

        if (newDifficulty.compareTo(params.proofOfWorkLimit) > 0) {
            log.info("Difficulty hit proof of work limit: {}", newDifficulty.toString(16));
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

    private void checkTestnetDifficulty(StoredBlock storedPrev, Block prev, Block next) throws VerificationException, BlockStoreException {
        // After 15th February 2012 the rules on the testnet change to avoid people running up the difficulty
        // and then leaving, making it too hard to mine a block. On non-difficulty transition points, easy
        // blocks are allowed if there has been a span of 20 minutes without one.
        final long timeDelta = next.getTimeSeconds() - prev.getTimeSeconds();
        // There is an integer underflow bug in bitcoin-qt that means mindiff blocks are accepted when time
        // goes backwards.
        if (timeDelta >= 0 && timeDelta <= NetworkParameters.TARGET_SPACING * 2) {
            // Walk backwards until we find a block that doesn't have the easiest proof of work, then check
            // that difficulty is equal to that one.
            StoredBlock cursor = storedPrev;
            while (!cursor.getHeader().equals(params.genesisBlock) &&
                   cursor.getHeight() % params.interval != 0 &&
                   cursor.getHeader().getDifficultyTargetAsInteger().equals(params.proofOfWorkLimit))
                cursor = cursor.getPrev(blockStore);
            BigInteger cursorDifficulty = cursor.getHeader().getDifficultyTargetAsInteger();
            BigInteger newDifficulty = next.getDifficultyTargetAsInteger();
            if (!cursorDifficulty.equals(newDifficulty))
                throw new VerificationException("Testnet block transition that is not allowed: " +
                    Long.toHexString(cursor.getHeader().getDifficultyTarget()) + " vs " +
                    Long.toHexString(next.getDifficultyTarget()));
        }
    }

    /**
     * For the transactions in the given block, update the txToWalletMap such that each wallet maps to a list of
     * transactions for which it is relevant.
     */
    private void scanTransactions(Block block, HashMap<Wallet, List<Transaction>> walletToTxMap)
            throws VerificationException {
        for (Transaction tx : block.transactions) {
            try {
                for (Wallet wallet : wallets) {
                    if (tx.isCoinBase())
                        continue;
                    boolean shouldReceive = wallet.isTransactionRelevant(tx, true);
                    if (!shouldReceive) continue;
                    List<Transaction> txList = walletToTxMap.get(wallet);
                    if (txList == null) {
                        txList = new LinkedList<Transaction>();
                        walletToTxMap.put(wallet, txList);
                    }
                    txList.add(tx);
                }
            } catch (ScriptException e) {
                // We don't want scripts we don't understand to break the block chain so just note that this tx was
                // not scanned here and continue.
                log.warn("Failed to parse a script: " + e.toString());
            }
        }
    }

    /**
     * Returns true if any connected wallet considers any transaction in the block to be relevant.
     */
    private boolean containsRelevantTransactions(Block block) {
        for (Transaction tx : block.transactions) {
            try {
                for (Wallet wallet : wallets) {
                    if (wallet.isTransactionRelevant(tx, true)) return true;
                }
            } catch (ScriptException e) {
                // We don't want scripts we don't understand to break the block chain so just note that this tx was
                // not scanned here and continue.
                log.warn("Failed to parse a script: " + e.toString());
            }
        }
        return false;
    }

    /**
     * Returns the block at the head of the current best chain. This is the block which represents the greatest
     * amount of cumulative work done.
     */
    public StoredBlock getChainHead() {
        synchronized (chainHeadLock) {
            return chainHead;
        }
    }

    /**
     * Returns the most recent unconnected block or null if there are none. This will all have to change. It's used
     * only in processing of inv messages.
     */
    synchronized Block getUnconnectedBlock() {
        if (unconnectedBlocks.size() == 0)
            return null;
        return unconnectedBlocks.get(unconnectedBlocks.size() - 1);
    }
}
