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
import java.util.LinkedList;

import static com.google.bitcoin.core.Utils.LOG;
import static com.google.bitcoin.core.Utils.bytesToHexString;

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
    // This is going away.
    private final LinkedList<Block> blockChain = new LinkedList<Block>();

    /** Each chain head that we saw so far. */
    private final ArrayList<Block> chainHeads = new ArrayList<Block>();

    private final NetworkParameters params;
    private final Wallet wallet;

    // Holds blocks that we have received but can't plug into the chain yet, eg because they were created whilst we
    // were downloading the block chain.
    private final ArrayList<Block> unconnectedBlocks = new ArrayList<Block>();

    public BlockChain(NetworkParameters params, Wallet wallet) {
        blockChain.add(params.genesisBlock);
        this.params = params;
        this.wallet = wallet;
    }

    /**
     * Processes a received block and tries to add it to the chain. If there's something wrong with the block an
     * exception is thrown. If the block is OK but cannot be connected to the chain at this time, returns false.
     * If the block can be connected to the chain, returns true.
     */
    public synchronized boolean add(Block block) throws VerificationException, ScriptException {
        return add(block, true);
    }

    private synchronized boolean add(Block block, boolean tryConnecting) throws VerificationException, ScriptException {
        try {
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
        // We know prev is OK because it's in the blockMap, that means we accepted it.
        Block prev = blockChain.getLast();
        if (prev.equals(block)) {
            LOG("Re-received block that is currently on top of the chain.");
            return true;
        }
        if (!Arrays.equals(block.getPrevBlockHash(), prev.getHash())) {
            // The block does not fit onto the top of the chain. It can either be:
            //   - Entirely unconnected. This can happen when a new block is solved and broadcast whilst we are in
            //     the process of downloading the block chain.
            //   - Connected to an earlier block in the chain than the top one. This can happen when there is a
            //     split in the chain.
            //   - Connected as part of an orphan chain, ie a chain of blocks that does not connect to the genesis
            //     block.
            // TODO: We don't support most of these cases today and it's a high priority to do so.
            unconnectedBlocks.add(block);
            return false;
        }
        checkDifficultyTransitions(block);
        // The block is OK so let's build the rest of the chain on it.
        block.prevBlock = prev;
        blockChain.add(block);
        if (tryConnecting)
            tryConnectingUnconnected();
        return true;
    }

    /**
     * For each block in unconnectedBlocks, see if we can now fit it on top of the chain and if so, do so.
     */
    private void tryConnectingUnconnected() throws VerificationException, ScriptException {
        // For each block in our unconnected list, try and fit it onto the head of the chain. If we succeed remove it
        // from the list and keep going. If we changed the head of the list at the end of the round,
        // try again until we can't fit anything else on the top.
        int blocksConnectedThisRound;
        do {
            blocksConnectedThisRound = 0;
            for (int i = 0; i < unconnectedBlocks.size(); i++) {
                Block block = unconnectedBlocks.get(i);
                if (Arrays.equals(block.getPrevBlockHash(), blockChain.getLast().getHash())) {
                    // False here ensures we don't recurse infinitely downwards when connecting huge chains.
                    add(block, false);
                    unconnectedBlocks.remove(i);
                    i--;  // The next iteration of the for loop will make "i" point to the right index again.
                    blocksConnectedThisRound++;
                }
            }
            if (blocksConnectedThisRound > 0) {
                LOG("Connected " + blocksConnectedThisRound + " floating blocks.");
            }
        } while (blocksConnectedThisRound > 0);
    }

    static private final int TARGET_TIMESPAN = 14 * 24 * 60 * 60;
    static private final int TARGET_SPACING = 10 * 60;
    static private final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;

    private void checkDifficultyTransitions(Block top) throws VerificationException {
        Block prev = blockChain.getLast();
        // Is this supposed to be a difficulty transition point?
        if (blockChain.size() % INTERVAL != 0) {
            // No ... so check the difficulty didn't actually change.
            if (top.getDifficultyTarget() != prev.getDifficultyTarget())
                throw new VerificationException("Unexpected change in difficulty at height " + blockChain.size() +
                        ": " + Long.toHexString(top.getDifficultyTarget()) + " vs " +
                        Long.toHexString(prev.getDifficultyTarget()));
            return;
        }

        Block blockIntervalAgo = blockChain.get(blockChain.size() - INTERVAL);
        int timespan = (int) (prev.getTime() - blockIntervalAgo.getTime());
        // Limit the adjustment step.
        if (timespan < TARGET_TIMESPAN / 4)
            timespan = TARGET_TIMESPAN / 4;
        if (timespan > TARGET_TIMESPAN * 4)
            timespan = TARGET_TIMESPAN * 4;

        BigInteger newDifficulty = Utils.decodeCompactBits(blockIntervalAgo.getDifficultyTarget());
        newDifficulty = newDifficulty.multiply(BigInteger.valueOf(timespan));
        newDifficulty = newDifficulty.divide(BigInteger.valueOf(TARGET_TIMESPAN));

        if (newDifficulty.compareTo(params.proofOfWorkLimit) > 0) {
            newDifficulty = params.proofOfWorkLimit;
        }

        int accuracyBytes = (int) (top.getDifficultyTarget() >>> 24) - 3;
        BigInteger receivedDifficulty = top.getDifficultyTargetBI();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newDifficulty = newDifficulty.and(mask);

        if (newDifficulty.compareTo(receivedDifficulty) != 0)
            throw new VerificationException("Calculated difficulty bits do not match what network provided: " +
                    receivedDifficulty.toString(16) + " vs " + newDifficulty.toString(16));
    }

    private void scanTransaction(Transaction tx) throws ScriptException, VerificationException {
        if (tx.isCoinBase()) return;
        for (TransactionOutput i : tx.outputs) {
            if (i.getScriptPubKey().isSentToIP()) return;
            byte[] pubKeyHash;
            pubKeyHash = i.getScriptPubKey().getPubKeyHash();
            synchronized (wallet) {
                for (ECKey key : wallet.keychain) {
                    if (Arrays.equals(pubKeyHash, key.getPubKeyHash())) {
                        // We found a transaction that sends us money.
                        if (!wallet.isTransactionPresent(tx))
                            wallet.receive(tx);
                    }
                }
            }
        }
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
     * Returns the highest known block or null if the chain is empty (top block is genesis).
     */
    public synchronized Block getTopBlock() {
        return blockChain.getLast();
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
