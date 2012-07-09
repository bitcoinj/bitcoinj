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
import java.util.LinkedList;
import java.util.List;

//TODO: Move this to MemoryFullPrunedBlockStore and use a different method for on-disk storage (bitcoin serialization?)
/**
 * A StoredTransaction message contains the information necessary to check a transaction later (ie after a reorg).
 * It is used to avoid having to store the entire transaction when we only need its inputs+outputs.
 * Its only really useful for MemoryFullPrunedBlockStore, and should probably be moved there
 */
public class StoredTransaction implements Serializable {
    private static final long serialVersionUID = 6243881368122528323L;

    /**
     *  A transaction has some value and a script used for authenticating that the redeemer is allowed to spend
     *  this output.
     */
    private List<StoredTransactionOutput> outputs;
    private List<TransactionInput> inputs;
    private long version;
    private long lockTime;
    private Sha256Hash hash;
    
    public StoredTransaction(Transaction tx, int height) {
        inputs = new LinkedList<TransactionInput>();
        outputs = new LinkedList<StoredTransactionOutput>();
        for (TransactionInput in : tx.getInputs())
            inputs.add(new TransactionInput(in.params, null, in.getScriptBytes(), in.getOutpoint()));
        for (TransactionOutput out : tx.getOutputs())
            outputs.add(new StoredTransactionOutput(null, out, height, tx.isCoinBase()));
        this.version = tx.getVersion();
        this.lockTime = tx.getLockTime();
        this.hash = tx.getHash();
    }

    /**
     * The lits of inputs in this transaction
     */
    public List<TransactionInput> getInputs() {
        return inputs;
    }
    
    /**
     * The lits of outputs in this transaction
     * Note that the hashes of all of these are null
     */
    public List<StoredTransactionOutput> getOutputs() {
        return outputs;
    }
    
    /**
     * The hash of this stored transaction
     */
    public Sha256Hash getHash() {
        return hash;
    }
    
    /**
     * The lockTime of the stored transaction
     */
    public long getLockTime() {
        return lockTime;
    }
    
    /**
     * The version of the stored transaction
     */
    public long getVersion() {
        return version;
    }
    
    /**
     * A coinbase transaction is one that creates a new coin. They are the first transaction in each block and their
     * value is determined by a formula that all implementations of BitCoin share. In 2011 the value of a coinbase
     * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined not only by its
     * position in a block but by the data in the inputs.
     */
    public boolean isCoinBase() {
        return inputs.get(0).isCoinBase();
    }
    
    public String toString() {
        return "Stored Transaction: " + hash.toString();
    }
    
    public int hashCode() {
        return getHash().hashCode();
    }
    
    public boolean equals(Object o) {
        if (!(o instanceof StoredTransaction)) return false;
        return ((StoredTransaction) o).getHash().equals(this.getHash());
    }
}