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

import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.VerificationException;

/**
 * Listener interface for when a new block on the best chain is seen.
 */
public interface NewBestBlockListener {
    /**
     * Called when a new block on the best chain is seen, after relevant
     * transactions are extracted and sent to us via either
     * {@link ReceiveFromBlockListener#receiveFromBlock(Transaction, StoredBlock, org.bitcoinj.core.BlockChain.NewBlockType, int)}
     * or {@link TransactionIsInBlockListener#notifyTransactionIsInBlock(Sha256Hash, StoredBlock, org.bitcoinj.core.BlockChain.NewBlockType, int)}.
     * If this block is causing a re-organise to a new chain, this method is NOT
     * called even though the block may be the new best block: your reorganize
     * implementation is expected to do whatever would normally be done do for a
     * new best block in this case.
     */
    void notifyNewBestBlock(final StoredBlock block) throws VerificationException;
}
