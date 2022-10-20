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

package org.bitcoinj.store;

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.StoredUndoableBlock;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.core.UTXOProvider;


/**
 * <p>An implementor of FullPrunedBlockStore saves StoredBlock objects to some storage mechanism.</p>
 * 
 * <p>In addition to keeping track of a chain using {@link StoredBlock}s, it should also keep track of a second
 * copy of the chain which holds {@link StoredUndoableBlock}s. In this way, an application can perform a
 * headers-only initial sync and then use that information to more efficiently download a locally verified
 * full copy of the block chain.</p>
 * 
 * <p>A FullPrunedBlockStore should function well as a standard {@link BlockStore} and then be able to
 * trivially switch to being used as a FullPrunedBlockStore.</p>
 * 
 * <p>It should store the {@link StoredUndoableBlock}s of a number of recent blocks before verifiedHead.height and
 * all those after verifiedHead.height.
 * It is advisable to store any {@link StoredUndoableBlock} which has a {@code height > verifiedHead.height - N}.
 * Because N determines the memory usage, it is recommended that N be customizable. N should be chosen such that
 * re-orgs beyond that point are vanishingly unlikely, for example, a few thousand blocks is a reasonable choice.</p>
 * 
 * <p>It must store the {@link StoredBlock} of all blocks.</p>
 *
 * <p>A FullPrunedBlockStore contains a map of hashes to [Full]StoredBlock. The hash is the double digest of the
 * Bitcoin serialization of the block header, <b>not</b> the header with the extra data as well.</p>
 * 
 * <p>A FullPrunedBlockStore also contains a map of hash+index to UTXO.  Again, the hash is
 * a standard Bitcoin double-SHA256 hash of the transaction.</p>
 *
 * <p>FullPrunedBlockStores are thread safe.</p>
 */
public interface FullPrunedBlockStore extends BlockStore, UTXOProvider {
    /**
     * <p>Saves the given {@link StoredUndoableBlock} and {@link StoredBlock}. Calculates keys from the {@link StoredBlock}</p>
     * 
     * <p>Though not required for proper function of a FullPrunedBlockStore, any user of a FullPrunedBlockStore should ensure
     * that a StoredUndoableBlock for each block up to the fully verified chain head has been added to this block store using
     * this function (not put(StoredBlock)), so that the ability to perform reorgs is maintained.</p>
     * 
     * @throws BlockStoreException if there is a problem with the underlying storage layer, such as running out of disk space.
     */
    void put(StoredBlock storedBlock, StoredUndoableBlock undoableBlock) throws BlockStoreException;
    
    /**
     * Returns the StoredBlock that was added as a StoredUndoableBlock given a hash. The returned values block.getHash()
     * method will be equal to the parameter. If no such block is found, returns null.
     */
    StoredBlock getOnceUndoableStoredBlock(Sha256Hash hash) throws BlockStoreException;

    /**
     * Returns a {@link StoredUndoableBlock} whose block.getHash() method will be equal to the parameter. If no such
     * block is found, returns null. Note that this may return null more often than get(Sha256Hash hash) as not all
     * {@link StoredBlock}s have a {@link StoredUndoableBlock} copy stored as well.
     */
    StoredUndoableBlock getUndoBlock(Sha256Hash hash) throws BlockStoreException;
    
    /**
     * Gets a {@link UTXO} with the given hash and index, or null if none is found
     */
    UTXO getTransactionOutput(Sha256Hash hash, long index) throws BlockStoreException;
    
    /**
     * Adds a {@link UTXO} to the list of unspent TransactionOutputs
     */
    void addUnspentTransactionOutput(UTXO out) throws BlockStoreException;
    
    /**
     * Removes a {@link UTXO} from the list of unspent TransactionOutputs
     * Note that the coinbase of the genesis block should NEVER be spendable and thus never in the list.
     * @throws BlockStoreException if there is an underlying storage issue, or out was not in the list.
     */
    void removeUnspentTransactionOutput(UTXO out) throws BlockStoreException;
    
    /**
     * True if this store has any unspent outputs from a transaction with a hash equal to the first parameter
     * @param numOutputs the number of outputs the given transaction has
     */
    boolean hasUnspentOutputs(Sha256Hash hash, int numOutputs) throws BlockStoreException;
    
    /**
     * Returns the {@link StoredBlock} that represents the top of the chain of greatest total work that has
     * been fully verified and the point in the chain at which the unspent transaction output set in this
     * store represents.
     */
    StoredBlock getVerifiedChainHead() throws BlockStoreException;

    /**
     * Sets the {@link StoredBlock} that represents the top of the chain of greatest total work that has been
     * fully verified. It should generally be set after a batch of updates to the transaction unspent output set,
     * before a call to commitDatabaseBatchWrite.
     * 
     * If chainHead has a greater height than the non-verified chain head (ie that set with
     * {@link BlockStore#setChainHead}) the non-verified chain head should be set to the one set here.
     * In this way a class using a FullPrunedBlockStore only in full-verification mode can ignore the regular
     * {@link BlockStore} functions implemented as a part of a FullPrunedBlockStore.
     */
    void setVerifiedChainHead(StoredBlock chainHead) throws BlockStoreException;
    
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
