/*
 * Copyright 2012 Google Inc.
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

import org.bitcoinj.core.*;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;

import javax.annotation.Nullable;
import java.util.*;

/**
 * Used as a key for memory map (to avoid having to think about NetworkParameters,
 * which is required for {@link TransactionOutPoint}
 */
class StoredTransactionOutPoint {

    /** Hash of the transaction to which we refer. */
    Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    long index;
    
    StoredTransactionOutPoint(Sha256Hash hash, long index) {
        this.hash = hash;
        this.index = index;
    }
    
    StoredTransactionOutPoint(UTXO out) {
        this.hash = out.getHash();
        this.index = out.getIndex();
    }
    
    /**
     * The hash of the transaction to which we refer
     */
    Sha256Hash getHash() {
        return hash;
    }
    
    /**
     * The index of the output in transaction to which we refer
     */
    long getIndex() {
        return index;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getIndex(), getHash());
    }
    
    @Override
    public String toString() {
        return "Stored transaction out point: " + hash + ":" + index;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StoredTransactionOutPoint other = (StoredTransactionOutPoint) o;
        return getIndex() == other.getIndex() && Objects.equal(getHash(), other.getHash());
    }
}

/**
 * A HashMap<KeyType, ValueType> that is DB transaction-aware
 * This class is not thread-safe.
 */
class TransactionalHashMap<KeyType, ValueType> {
    ThreadLocal<HashMap<KeyType, ValueType>> tempMap;
    ThreadLocal<HashSet<KeyType>> tempSetRemoved;
    private ThreadLocal<Boolean> inTransaction;
    
    HashMap<KeyType, ValueType> map;
    
    public TransactionalHashMap() {
        tempMap = new ThreadLocal<HashMap<KeyType, ValueType>>();
        tempSetRemoved = new ThreadLocal<HashSet<KeyType>>();
        inTransaction = new ThreadLocal<Boolean>();
        map = new HashMap<KeyType, ValueType>();
    }
    
    public void beginDatabaseBatchWrite() {
        inTransaction.set(true);
    }

    public void commitDatabaseBatchWrite() {
        if (tempSetRemoved.get() != null)
            for(KeyType key : tempSetRemoved.get())
                map.remove(key);
        if (tempMap.get() != null)
            for (Map.Entry<KeyType, ValueType> entry : tempMap.get().entrySet())
                map.put(entry.getKey(), entry.getValue());
        abortDatabaseBatchWrite();
    }

    public void abortDatabaseBatchWrite() {
        inTransaction.set(false);
        tempSetRemoved.remove();
        tempMap.remove();
    }

    @Nullable
    public ValueType get(KeyType key) {
        if (Boolean.TRUE.equals(inTransaction.get())) {
            if (tempMap.get() != null) {
                ValueType value = tempMap.get().get(key);
                if (value != null)
                    return value;
            }
            if (tempSetRemoved.get() != null && tempSetRemoved.get().contains(key))
                return null;
        }
        return map.get(key);
    }

    public List<ValueType> values() {
        List<ValueType> valueTypes = new ArrayList<ValueType>();
        for (KeyType keyType : map.keySet()) {
            valueTypes.add(get(keyType));
        }
        return valueTypes;
    }
    
    public void put(KeyType key, ValueType value) {
        if (Boolean.TRUE.equals(inTransaction.get())) {
            if (tempSetRemoved.get() != null)
                tempSetRemoved.get().remove(key);
            if (tempMap.get() == null)
                tempMap.set(new HashMap<KeyType, ValueType>());
            tempMap.get().put(key, value);
        }else{
            map.put(key, value);
        }
    }
    
    @Nullable
    public ValueType remove(KeyType key) {
        if (Boolean.TRUE.equals(inTransaction.get())) {
            ValueType retVal = map.get(key);
            if (retVal != null) {
                if (tempSetRemoved.get() == null)
                    tempSetRemoved.set(new HashSet<KeyType>());
                tempSetRemoved.get().add(key);
            }
            if (tempMap.get() != null) {
                ValueType tempVal = tempMap.get().remove(key);
                if (tempVal != null)
                    return tempVal;
            }
            return retVal;
        }else{
            return map.remove(key);
        }
    }
}

/**
 * A Map with multiple key types that is DB per-thread-transaction-aware.
 * However, this class is not thread-safe.
 * @param <UniqueKeyType> is a key that must be unique per object
 * @param <MultiKeyType> is a key that can have multiple values
 */
class TransactionalMultiKeyHashMap<UniqueKeyType, MultiKeyType, ValueType> {
    TransactionalHashMap<UniqueKeyType, ValueType> mapValues;
    HashMap<MultiKeyType, Set<UniqueKeyType>> mapKeys;
    
    public TransactionalMultiKeyHashMap() {
        mapValues = new TransactionalHashMap<UniqueKeyType, ValueType>();
        mapKeys = new HashMap<MultiKeyType, Set<UniqueKeyType>>();
    }
    
    public void BeginTransaction() {
        mapValues.beginDatabaseBatchWrite();
    }

    public void CommitTransaction() {
        mapValues.commitDatabaseBatchWrite();
    }

    public void AbortTransaction() {
        mapValues.abortDatabaseBatchWrite();
    }

    @Nullable
    public ValueType get(UniqueKeyType key) {
        return mapValues.get(key);
    }
    
    public void put(UniqueKeyType uniqueKey, MultiKeyType multiKey, ValueType value) {
        mapValues.put(uniqueKey, value);
        Set<UniqueKeyType> set = mapKeys.get(multiKey);
        if (set == null) {
            set = new HashSet<UniqueKeyType>();
            set.add(uniqueKey);
            mapKeys.put(multiKey, set);
        }else{
            set.add(uniqueKey);
        }
    }
    
    @Nullable
    public ValueType removeByUniqueKey(UniqueKeyType key) {
        return mapValues.remove(key);
    }
    
    public void removeByMultiKey(MultiKeyType key) {
        Set<UniqueKeyType> set = mapKeys.remove(key);
        if (set != null)
            for (UniqueKeyType uniqueKey : set)
                removeByUniqueKey(uniqueKey);
    }
}

/**
 * Keeps {@link StoredBlock}s, {@link StoredUndoableBlock}s and {@link org.bitcoinj.core.UTXO}s in memory.
 * Used primarily for unit testing.
 */
public class MemoryFullPrunedBlockStore implements FullPrunedBlockStore {
    protected static class StoredBlockAndWasUndoableFlag {
        public StoredBlock block;
        public boolean wasUndoable;
        public StoredBlockAndWasUndoableFlag(StoredBlock block, boolean wasUndoable) { this.block = block; this.wasUndoable = wasUndoable; }
    }
    private TransactionalHashMap<Sha256Hash, StoredBlockAndWasUndoableFlag> blockMap;
    private TransactionalMultiKeyHashMap<Sha256Hash, Integer, StoredUndoableBlock> fullBlockMap;
    //TODO: Use something more suited to remove-heavy use?
    private TransactionalHashMap<StoredTransactionOutPoint, UTXO> transactionOutputMap;
    private StoredBlock chainHead;
    private StoredBlock verifiedChainHead;
    private int fullStoreDepth;
    private NetworkParameters params;
    
    /**
     * Set up the MemoryFullPrunedBlockStore
     * @param params The network parameters of this block store - used to get genesis block
     * @param fullStoreDepth The depth of blocks to keep FullStoredBlocks instead of StoredBlocks
     */
    public MemoryFullPrunedBlockStore(NetworkParameters params, int fullStoreDepth) {
        blockMap = new TransactionalHashMap<Sha256Hash, StoredBlockAndWasUndoableFlag>();
        fullBlockMap = new TransactionalMultiKeyHashMap<Sha256Hash, Integer, StoredUndoableBlock>();
        transactionOutputMap = new TransactionalHashMap<StoredTransactionOutPoint, UTXO>();
        this.fullStoreDepth = fullStoreDepth > 0 ? fullStoreDepth : 1;
        // Insert the genesis block.
        try {
            StoredBlock storedGenesisHeader = new StoredBlock(params.getGenesisBlock().cloneAsHeader(), params.getGenesisBlock().getWork(), 0);
            // The coinbase in the genesis block is not spendable
            List<Transaction> genesisTransactions = Lists.newLinkedList();
            StoredUndoableBlock storedGenesis = new StoredUndoableBlock(params.getGenesisBlock().getHash(), genesisTransactions);
            put(storedGenesisHeader, storedGenesis);
            setChainHead(storedGenesisHeader);
            setVerifiedChainHead(storedGenesisHeader);
            this.params = params;
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    public synchronized void put(StoredBlock block) throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        Sha256Hash hash = block.getHeader().getHash();
        blockMap.put(hash, new StoredBlockAndWasUndoableFlag(block, false));
    }
    
    @Override
    public synchronized final void put(StoredBlock storedBlock, StoredUndoableBlock undoableBlock) throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        Sha256Hash hash = storedBlock.getHeader().getHash();
        fullBlockMap.put(hash, storedBlock.getHeight(), undoableBlock);
        blockMap.put(hash, new StoredBlockAndWasUndoableFlag(storedBlock, true));
    }

    @Override
    @Nullable
    public synchronized StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        StoredBlockAndWasUndoableFlag storedBlock = blockMap.get(hash);
        return storedBlock == null ? null : storedBlock.block;
    }
    
    @Override
    @Nullable
    public synchronized StoredBlock getOnceUndoableStoredBlock(Sha256Hash hash) throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        StoredBlockAndWasUndoableFlag storedBlock = blockMap.get(hash);
        return (storedBlock != null && storedBlock.wasUndoable) ? storedBlock.block : null;
    }
    
    @Override
    @Nullable
    public synchronized StoredUndoableBlock getUndoBlock(Sha256Hash hash) throws BlockStoreException {
        Preconditions.checkNotNull(fullBlockMap, "MemoryFullPrunedBlockStore is closed");
        return fullBlockMap.get(hash);
    }

    @Override
    public synchronized StoredBlock getChainHead() throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        return chainHead;
    }

    @Override
    public synchronized final void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        this.chainHead = chainHead;
    }
    
    @Override
    public synchronized StoredBlock getVerifiedChainHead() throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        return verifiedChainHead;
    }

    @Override
    public synchronized final void setVerifiedChainHead(StoredBlock chainHead) throws BlockStoreException {
        Preconditions.checkNotNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        this.verifiedChainHead = chainHead;
        if (this.chainHead.getHeight() < chainHead.getHeight())
            setChainHead(chainHead);
        // Potential leak here if not all blocks get setChainHead'd
        // Though the FullPrunedBlockStore allows for this, the current AbstractBlockChain will not do it.
        fullBlockMap.removeByMultiKey(chainHead.getHeight() - fullStoreDepth);
    }
    
    @Override
    public void close() {
        blockMap = null;
        fullBlockMap = null;
        transactionOutputMap = null;
    }
    
    @Override
    @Nullable
    public synchronized UTXO getTransactionOutput(Sha256Hash hash, long index) throws BlockStoreException {
        Preconditions.checkNotNull(transactionOutputMap, "MemoryFullPrunedBlockStore is closed");
        return transactionOutputMap.get(new StoredTransactionOutPoint(hash, index));
    }

    @Override
    public synchronized void addUnspentTransactionOutput(UTXO out) throws BlockStoreException {
        Preconditions.checkNotNull(transactionOutputMap, "MemoryFullPrunedBlockStore is closed");
        transactionOutputMap.put(new StoredTransactionOutPoint(out), out);
    }

    @Override
    public synchronized void removeUnspentTransactionOutput(UTXO out) throws BlockStoreException {
        Preconditions.checkNotNull(transactionOutputMap, "MemoryFullPrunedBlockStore is closed");
        if (transactionOutputMap.remove(new StoredTransactionOutPoint(out)) == null)
            throw new BlockStoreException("Tried to remove a UTXO from MemoryFullPrunedBlockStore that it didn't have!");
    }

    @Override
    public synchronized void beginDatabaseBatchWrite() throws BlockStoreException {
        blockMap.beginDatabaseBatchWrite();
        fullBlockMap.BeginTransaction();
        transactionOutputMap.beginDatabaseBatchWrite();
    }

    @Override
    public synchronized void commitDatabaseBatchWrite() throws BlockStoreException {
        blockMap.commitDatabaseBatchWrite();
        fullBlockMap.CommitTransaction();
        transactionOutputMap.commitDatabaseBatchWrite();
    }

    @Override
    public synchronized void abortDatabaseBatchWrite() throws BlockStoreException {
        blockMap.abortDatabaseBatchWrite();
        fullBlockMap.AbortTransaction();
        transactionOutputMap.abortDatabaseBatchWrite();
    }

    @Override
    public synchronized boolean hasUnspentOutputs(Sha256Hash hash, int numOutputs) throws BlockStoreException {
        for (int i = 0; i < numOutputs; i++)
            if (getTransactionOutput(hash, i) != null)
                return true;
        return false;
    }

    @Override
    public NetworkParameters getParams() {
        return params;
    }

    @Override
    public int getChainHeadHeight() throws UTXOProviderException {
        try {
            return getVerifiedChainHead().getHeight();
        } catch (BlockStoreException e) {
            throw new UTXOProviderException(e);
        }
    }

    @Override
    public List<UTXO> getOpenTransactionOutputs(List<Address> addresses) throws UTXOProviderException {
        // This is *NOT* optimal: We go through all the outputs and select the ones we are looking for.
        // If someone uses this store for production then they have a lot more to worry about than an inefficient impl :)
        List<UTXO> foundOutputs = new ArrayList<UTXO>();
        List<UTXO> outputsList = transactionOutputMap.values();
        for (UTXO output : outputsList) {
            for (Address address : addresses) {
                if (output.getAddress().equals(address.toString())) {
                    foundOutputs.add(output);
                }
            }
        }
        return foundOutputs;
    }
}
