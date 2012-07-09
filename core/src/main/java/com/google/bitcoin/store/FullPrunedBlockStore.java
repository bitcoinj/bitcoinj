/*
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

package com.google.bitcoin.store;

import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.StoredBlock;
import com.google.bitcoin.core.StoredTransactionOutput;
import com.google.bitcoin.core.StoredUndoableBlock;

/**
 * <p>An implementor of FullPrunedBlockStore saves StoredBlock objects to some storage mechanism.</p>
 * 
 * <p>It should store the {@link StoredUndoableBlock}s of a number of recent blocks.
 * It is advisable to store any {@link StoredUndoableBlock} which has a height > head.height - N.
 * Because N determines the memory usage, it is recommended that N be customizable. N should be chosen such that
 * re-orgs beyond that point are vanishingly unlikely, for example, a few thousand blocks is a reasonable choice.</p>
 * 
 * <p>It must store the {@link StoredBlock} of all blocks.</p>
 *
 * <p>A FullPrunedBlockStore contains a map of hashes to [Full]StoredBlock. The hash is the double digest of the
 * Bitcoin serialization of the block header, <b>not</b> the header with the extra data as well.</p>
 * 
 * <p>A FullPrunedBlockStore also contains a map of hash+index to StoredTransactionOutput.  Again, the hash is
 * a standard Bitcoin double-SHA256 hash of the transaction.</p>
 *
 * <p>FullPrunedBlockStores are thread safe.</p>
 */
public interface FullPrunedBlockStore extends BlockStore {
    /**
     * Saves the given {@link StoredUndoableBlock} and {@link StoredBlock}. Calculates keys from the {@link StoredBlock}
     * Note that a call to put(StoredBlock) will throw a BlockStoreException if its height is > head.height - N
     * @throws BlockStoreException if there is a problem with the underlying storage layer, such as running out of disk space.
     */
    void put(StoredBlock storedBlock, StoredUndoableBlock undoableBlock) throws BlockStoreException;

    /**
     * Returns a {@link StoredUndoableBlock} who's block.getHash() method will be equal to the
     * parameter. If no such block is found, returns null.
     * Note that this may return null more often than get(Sha256Hash hash) as not all {@link StoredBlock}s have a
     * {@link StoredUndoableBlock} copy stored as well.
     */
    StoredUndoableBlock getUndoBlock(Sha256Hash hash) throws BlockStoreException;
    
    /**
     * Gets a {@link StoredTransactionOutput} with the given hash and index, or null if none is found
     */
    StoredTransactionOutput getTransactionOutput(Sha256Hash hash, long index) throws BlockStoreException;
    
    /**
     * Adds a {@link StoredTransactionOutput} to the list of unspent TransactionOutputs
     */
    void addUnspentTransactionOutput(StoredTransactionOutput out) throws BlockStoreException;
    
    /**
     * Removes a {@link StoredTransactionOutput} from the list of unspent TransactionOutputs
     * @throws BlockStoreException if there is an underlying storage issue, or out was not in the list.
     */
    void removeUnspentTransactionOutput(StoredTransactionOutput out) throws BlockStoreException;
    
    /**
     * True if this store has any unspent outputs from a transaction with a hash equal to the first parameter
     * @param numOutputs the number of outputs the given transaction has
     */
    boolean hasUnspentOutputs(Sha256Hash hash, int numOutputs) throws BlockStoreException;
    
    /**
     * <p>Begins/Commits/Aborts a database transaction.</p>
     *
     * <p>If abortDatabaseBatchWrite() is called by the same thread that called beginDatabaseBatchWrite(),
     * any data writes between this call and abortDatabaseBatchWrite() made by the same thread
     * should be discarded.</p>
     *
     * <p>Furthermore, any data written after a call to beginDatabaseBatchWrite() should not be readable
     * by any other threads until commitDatabaseBatchWrite() has been called by this thread.
     * Multiple calls to beginDatabaseBatchWrite() in any given thread should be ignored and treated as one call.</p>
     */
    void beginDatabaseBatchWrite() throws BlockStoreException;
    void commitDatabaseBatchWrite() throws BlockStoreException;
    void abortDatabaseBatchWrite() throws BlockStoreException;
}
