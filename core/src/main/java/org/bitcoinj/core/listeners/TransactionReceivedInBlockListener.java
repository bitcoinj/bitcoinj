/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core.listeners;

import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.FilteredBlock;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.VerificationException;

/**
 * Listener interface for when we receive a new block that contains a relevant
 * transaction.
 */
public interface TransactionReceivedInBlockListener {
    /**
     * <p>Called by the {@link BlockChain} when we receive a new block that contains a relevant transaction.</p>
     *
     * <p>A transaction may be received multiple times if is included into blocks in parallel chains. The blockType
     * parameter describes whether the containing block is on the main/best chain or whether it's on a presently
     * inactive side chain.</p>
     *
     * <p>The relativityOffset parameter is an arbitrary number used to establish an ordering between transactions
     * within the same block. In the case where full blocks are being downloaded, it is simply the index of the
     * transaction within that block. When Bloom filtering is in use, we don't find out the exact offset into a block
     * that a transaction occurred at, so the relativity count is not reflective of anything in an absolute sense but
     * rather exists only to order the transaction relative to the others.</p>
     */
    void receiveFromBlock(Transaction tx, StoredBlock block,
                          BlockChain.NewBlockType blockType,
                          int relativityOffset) throws VerificationException;
    /**
     * <p>Called by the {@link BlockChain} when we receive a new {@link FilteredBlock} that contains the given
     * transaction hash in its merkle tree.</p>
     *
     * <p>A transaction may be received multiple times if is included into blocks in parallel chains. The blockType
     * parameter describes whether the containing block is on the main/best chain or whether it's on a presently
     * inactive side chain.</p>
     *
     * <p>The relativityOffset parameter in this case is an arbitrary (meaningless) number, that is useful only when
     * compared to the relativity count of another transaction received inside the same block. It is used to establish
     * an ordering of transactions relative to one another.</p>
     *
     * <p>This method should return false if the given tx hash isn't known about, e.g. because the the transaction was
     * a Bloom false positive. If it was known about and stored, it should return true. The caller may need to know
     * this to calculate the effective FP rate.</p>
     *
     * @return whether the transaction is known about i.e. was considered relevant previously.
     */
    boolean notifyTransactionIsInBlock(Sha256Hash txHash, StoredBlock block,
                                       BlockChain.NewBlockType blockType,
                                       int relativityOffset) throws VerificationException;
}
