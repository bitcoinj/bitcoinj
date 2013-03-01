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

import java.util.List;

/**
 * Implementors can be connected to a {@link BlockChain} and have its methods called when various things
 * happen that modify the state of the chain, for example: new blocks being received, a re-org occurring, or the
 * best chain head changing.
 */
public interface BlockChainListener {
    /**
     * <p>Called by the {@link BlockChain} when a new block on the best chain is seen, AFTER relevant
     * transactions are extracted and sent to us UNLESS the new block caused a re-org, in which case this will
     * not be called (the {@link Wallet#reorganize(StoredBlock, java.util.List, java.util.List)} method will
     * call this one in that case).</p>
     * @param block
     */
    void notifyNewBestBlock(StoredBlock block) throws VerificationException;

    /**
     * Called by the {@link BlockChain} when the best chain (representing total work done) has changed. In this case,
     * we need to go through our transactions and find out if any have become invalid. It's possible for our balance
     * to go down in this case: money we thought we had can suddenly vanish if the rest of the network agrees it
     * should be so.<p>
     *
     * The oldBlocks/newBlocks lists are ordered height-wise from top first to bottom last.
     */
    void reorganize(StoredBlock splitPoint, List<StoredBlock> oldBlocks,
                    List<StoredBlock> newBlocks) throws VerificationException;

    /**
     * Returns true if the given transaction is interesting to the listener. If yes, then the transaction will
     * be provided via the receiveFromBlock method. This method is essentially an optimization that lets BlockChain
     * bypass verification of a blocks merkle tree if no listeners are interested, which can save time when processing
     * full blocks on mobile phones. It's likely the method will be removed in future and replaced with an alternative
     * mechanism that involves listeners providing all keys that are interesting.
     */
    boolean isTransactionRelevant(Transaction tx) throws ScriptException;

    /**
     * <p>Called by the {@link BlockChain} when we receive a new block that contains a relevant transaction.</p>
     *
     * <p>A transaction may be received multiple times if is included into blocks in parallel chains. The blockType
     * parameter describes whether the containing block is on the main/best chain or whether it's on a presently
     * inactive side chain.</p>
     */
    void receiveFromBlock(Transaction tx, StoredBlock block,
                          BlockChain.NewBlockType blockType) throws VerificationException;
    
    /**
     * <p>Called by the {@link BlockChain} when we receive a new filtered block that contains the given transaction
     * hash in its merkle tree.</p>
     *
     * <p>A transaction may be received multiple times if is included into blocks in parallel chains. The blockType
     * parameter describes whether the containing block is on the main/best chain or whether it's on a presently
     * inactive side chain.</p>
     */
    void notifyTransactionIsInBlock(Sha256Hash txHash, StoredBlock block,
                                    BlockChain.NewBlockType blockType) throws VerificationException;
}
