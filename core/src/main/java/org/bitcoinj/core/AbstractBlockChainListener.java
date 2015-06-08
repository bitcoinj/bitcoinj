/**
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.core;

import java.util.List;

/**
 * Default no-op implementation of {@link BlockChainListener}.
 */
public class AbstractBlockChainListener implements BlockChainListener {
    @Override
    public void notifyNewBestBlock(StoredBlock block) throws VerificationException {
    }

    @Override
    public void reorganize(StoredBlock splitPoint, List<StoredBlock> oldBlocks, List<StoredBlock> newBlocks) throws VerificationException {
    }

    @Override
    public boolean isTransactionRelevant(Transaction tx) throws ScriptException {
        return false;
    }

    @Override
    public void receiveFromBlock(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType,
                                 int relativityOffset) throws VerificationException {
    }

    @Override
    public boolean notifyTransactionIsInBlock(Sha256Hash txHash, StoredBlock block, BlockChain.NewBlockType blockType,
                                              int relativityOffset) throws VerificationException {
        return false;
    }
}
