/**
 * Copyright 2012 Matt Corallo.
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

import java.io.Serializable;
import java.util.List;

/**
 * TransactionOutputChanges is used as a return value for BlockChainBase.connectInputs.
 * It contains the full list of transaction outputs created and spent in a block.
 * It does contain outputs created that were spent later in the block, as those are needed for
 * BIP30 (no duplicate txid creation if the previous one was not fully spent prior to this block) verification.
 */
public class TransactionOutputChanges implements Serializable {
    private static final long serialVersionUID = -6169346729324181905L;

    public final List<StoredTransactionOutput> txOutsCreated;
    public final List<StoredTransactionOutput> txOutsSpent;
    
    public TransactionOutputChanges(List<StoredTransactionOutput> txOutsCreated, List<StoredTransactionOutput> txOutsSpent) {
        this.txOutsCreated = txOutsCreated;
        this.txOutsSpent = txOutsSpent;
    }
}
