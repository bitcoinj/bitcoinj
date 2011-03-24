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
import java.util.ArrayList;
import java.util.Arrays;

import static com.google.bitcoin.core.Utils.LOG;

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
    protected final Wallet wallet;

    // Holds blocks that we have received but can't plug into the chain yet, eg because they were created whilst we
    // were downloading the block chain.
    private final ArrayList<Block> unconnectedBlocks = new ArrayList<Block>();

    public BlockChain(NetworkParameters params, Wallet wallet) {
        // TODO: Let the user pass in a BlockStore object so they can choose how to store the headers.
        blockStore = new MemoryBlockStore();
        try {
            // Set up the genesis block. When we start out fresh, it is by definition the top of the chain.
            Block genesisHeader = params.genesisBlock.cloneAsHeader();
            chainHead = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
            blockStore.put(chainHead);
        } catch (BlockStoreException e) {
            // Cannot happen.
        } catch (VerificationException e) {
            // Genesis block always verifies.
        }

        this.params = params;
        this.wallet = wallet;
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

    private synchronized boolean add(Block block, boolean tryConnecting)
            throws BlockStoreException, VerificationException, ScriptException {
        try {
            // Prove the block is internally valid: hash is lower than target, merkle root is correct and so on.
            block.verify();
        } catch (VerificationException e) {
            LOG("Failed to verify block: " + e.toString());
            LOG(block.toString());
            throw e;
        }
        // If this block is a full block, scan, otherwise it's just headers (eg from getheaders or a unit test).
        if (block.transactions != null) {
            // Scan the transactions to find out if any sent money to us. We don't care about the rest.
            // TODO: We should also scan to see if any of our own keys sent money to somebody else and became spent.
            for (Transaction tx : block.transactions) {
                try {
                    scanTransaction(tx);
                } catch (ScriptException e) {
                    // We don't want scripts we don't understand to break the block chain,
                    // so just note that this tx was not scanned here and continue.
                    LOG("Failed to parse a script: " + e.toString());
                }
            }
        }
        // We don't need the transaction data anymore. Free up some memory.
        block.transactions = null;

        if (blockStore.get(block.getHash()) != null) {
            LOG("Already have block");
            return true;
        }
        StoredBlock storedPrev = blockStore.get(block.getPrevBlockHash());
        if (storedPrev == null) {
            // We can't find the previous block. Probably we are still in the process of downloading the chain and a
            // block was solved whilst we were doing it. We put it to one side and try to connect it later when we
            // have more blocks.
            LOG("Block does not connect: " + block.getHashAsString());
            unconnectedBlocks.add(block);
            return false;
        } else {
            // The block connects to somewhere on the chain. Not necessarily the top of the best known chain.
            checkDifficultyTransitions(storedPrev, block);
            StoredBlock newStoredBlock = buildStoredBlock(storedPrev, block);
            // Store it.
            blockStore.put(newStoredBlock);
            if (storedPrev.equals(chainHead)) {
                // This block connects to the best known block, it is a normal continuation of the system.
                chainHead = newStoredBlock;
                LOG("Received new block, chain is now " + chainHead.height + " blocks high");
            } else {
                // This block connects to somewhere other than the top of the chain.
                if (newStoredBlock.moreWorkThan(chainHead)) {
                    // This chain has overtaken the one we currently believe is best. Reorganize is required.
                    wallet.reorganize(chainHead, newStoredBlock);
                    // Update the pointer to the best known block.
                    chainHead = newStoredBlock;
                } else {
                    LOG("Received a block which forks the chain, but it did not cause a reorganize.");
                }
            }
        }

        if (tryConnecting)
            tryConnectingUnconnected();

        return true;
    }

    /**
     * Calculates the additional fields a StoredBlock holds given the previous block in the chain and the new block.
     */
    private StoredBlock buildStoredBlock(StoredBlock storedPrev, Block block) throws VerificationException {
        // Stored blocks track total work done in this chain, because the canonical chain is the one that represents
        // the largest amount of work done not the tallest.
        BigInteger chainWork = storedPrev.chainWork.add(block.getWork());
        int height = storedPrev.height + 1;
        return new StoredBlock(block, chainWork, height);
    }

    /**
     * For each block in unconnectedBlocks, see if we can now fit it on top of the chain and if so, do so.
     */
    private void tryConnectingUnconnected() throws VerificationException, ScriptException, BlockStoreException {
        // For each block in our unconnected list, try and fit it onto the head of the chain. If we succeed remove it
        // from the list and keep going. If we changed the head of the list at the end of the round,
        // try again until we can't fit anything else on the top.
        int blocksConnectedThisRound;
        do {
            blocksConnectedThisRound = 0;
            for (int i = 0; i < unconnectedBlocks.size(); i++) {
                Block block = unconnectedBlocks.get(i);
                // Look up the blocks previous.
                StoredBlock prev = blockStore.get(block.getPrevBlockHash());
                if (prev == null) {
                    // This is still an unconnected/orphan block.
                    continue;
                }
                // Otherwise we can connect it now.
                // False here ensures we don't recurse infinitely downwards when connecting huge chains.
                add(block, false);
                unconnectedBlocks.remove(i);
                i--;  // The next iteration of the for loop will make "i" point to the right index again.
                blocksConnectedThisRound++;
            }
            if (blocksConnectedThisRound > 0) {
                LOG("Connected " + blocksConnectedThisRound + " floating blocks.");
            }
        } while (blocksConnectedThisRound > 0);
    }

    /**
     * Throws an exception if the blocks difficulty is not correct.
     */
    private void checkDifficultyTransitions(StoredBlock storedPrev, Block next)
            throws BlockStoreException, VerificationException {
        Block prev = storedPrev.header;
        // Is this supposed to be a difficulty transition point?
        if ((storedPrev.height + 1) % params.interval != 0) {
            // No ... so check the difficulty didn't actually change.
            if (next.getDifficultyTarget() != prev.getDifficultyTarget())
                throw new VerificationException("Unexpected change in difficulty at height " + storedPrev.height +
                        ": " + Long.toHexString(next.getDifficultyTarget()) + " vs " +
                        Long.toHexString(prev.getDifficultyTarget()));
            return;
        }

        // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
        // two weeks after the initial block chain download.
        StoredBlock cursor = blockStore.get(prev.getHash());
        for (int i = 0; i < params.interval - 1; i++) {
            if (cursor == null) {
                // This should never happen. If it does, it means we are following an incorrect or busted chain.
                throw new VerificationException(
                        "Difficulty transition point but we did not find a way back to the genesis block.");
            }
            cursor = blockStore.get(cursor.header.getPrevBlockHash());
        }

        Block blockIntervalAgo = cursor.header;
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
            LOG("Difficulty hit proof of work limit: " + newDifficulty.toString(16));
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

    private void scanTransaction(Transaction tx) throws ScriptException, VerificationException {
        for (TransactionOutput i : tx.outputs) {
            // TODO: Handle more types of outputs, not just regular to address outputs.
            if (i.getScriptPubKey().isSentToIP()) return;
            byte[] pubKeyHash;
            pubKeyHash = i.getScriptPubKey().getPubKeyHash();
            synchronized (wallet) {
                for (ECKey key : wallet.keychain) {
                    if (Arrays.equals(pubKeyHash, key.getPubKeyHash())) {
                        // We found a transaction that sends us money.
                        if (!wallet.isTransactionPresent(tx)) {
                            wallet.receive(tx);
                        }
                    }
                }
            }
        }

        // Coinbase transactions don't have anything useful in their inputs (as they create coins out of thin air),
        // so we can stop scanning at this point.
        if (tx.isCoinBase()) return;

        for (TransactionInput i : tx.inputs) {
            byte[] pubkey = i.getScriptSig().getPubKey();
            synchronized (wallet) {
                for (ECKey key : wallet.keychain) {
                    if (Arrays.equals(pubkey, key.getPubKey())) {
                        // We found a transaction where we spent money.
                        if (wallet.isTransactionPresent(tx)) {
                            // TODO: Implement catching up with a set of pre-generated keys using the blockchain.
                        }
                    }
                }
            }
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
