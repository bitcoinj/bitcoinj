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

import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Address;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.StoredUndoableBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.core.UTXOProviderException;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptPattern;

import org.jspecify.annotations.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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
        tempMap = new ThreadLocal<>();
        tempSetRemoved = new ThreadLocal<>();
        inTransaction = new ThreadLocal<>();
        map = new HashMap<>();
    }
    
    public void beginDatabaseBatchWrite() {
        inTransaction.set(true);
    }

    public void commitDatabaseBatchWrite() {
        if (tempSetRemoved.get() != null)
            for(KeyType key : tempSetRemoved.get())
                map.remove(key);
        if (tempMap.get() != null)
            map.putAll(tempMap.get());
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
        List<ValueType> valueTypes = new ArrayList<>();
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
 * A map of {@link Sha256Hash} to {@link StoredUndoableBlock} that is also indexed by a height {@link Integer} that
 * is DB per-thread-transaction-aware. However, this class is not thread-safe.
 */
class TransactionalFullBlockMap {
    TransactionalHashMap<Sha256Hash, StoredUndoableBlock> mapValues;
    HashMap<Integer, Set<Sha256Hash>> mapKeys;
    
    public TransactionalFullBlockMap() {
        mapValues = new TransactionalHashMap<>();
        mapKeys = new HashMap<>();
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
    public StoredUndoableBlock get(Sha256Hash key) {
        return mapValues.get(key);
    }
    
    public void put(Sha256Hash hash, int height, StoredUndoableBlock block) {
        mapValues.put(hash, block);
        Set<Sha256Hash> set = mapKeys.get(height);
        if (set == null) {
            set = new HashSet<>();
            set.add(hash);
            mapKeys.put(height, set);
        }else{
            set.add(hash);
        }
    }
    
    public void removeByHeight(int height) {
        Set<Sha256Hash> set = mapKeys.remove(height);
        if (set != null)
            for (Sha256Hash hash : set)
                mapValues.remove(hash);
    }
}

/**
 * Keeps {@link StoredBlock}s, {@link StoredUndoableBlock}s and {@link UTXO}s in memory.
 * Used primarily for unit testing.
 */
public class MemoryFullPrunedBlockStore implements FullPrunedBlockStore {
    protected static class StoredBlockAndWasUndoableFlag {
        public StoredBlock block;
        public boolean wasUndoable;
        public StoredBlockAndWasUndoableFlag(StoredBlock block, boolean wasUndoable) { this.block = block; this.wasUndoable = wasUndoable; }
    }
    private TransactionalHashMap<Sha256Hash, StoredBlockAndWasUndoableFlag> blockMap;
    private TransactionalFullBlockMap fullBlockMap;
    //TODO: Use something more suited to remove-heavy use?
    private TransactionalHashMap<TransactionOutPoint, UTXO> transactionOutputMap;
    private StoredBlock chainHead;
    private StoredBlock verifiedChainHead;
    private final int fullStoreDepth;
    private final Network network;
    
    /**
     * Set up the MemoryFullPrunedBlockStore
     * @param params The network parameters of this block store - used to get genesis block
     * @param fullStoreDepth The depth of blocks to keep FullStoredBlocks instead of StoredBlocks
     */
    public MemoryFullPrunedBlockStore(NetworkParameters params, int fullStoreDepth) {
        blockMap = new TransactionalHashMap<>();
        fullBlockMap = new TransactionalFullBlockMap();
        transactionOutputMap = new TransactionalHashMap<>();
        this.fullStoreDepth = fullStoreDepth > 0 ? fullStoreDepth : 1;
        // Insert the genesis block.
        try {
            StoredBlock storedGenesisHeader = new StoredBlock(params.getGenesisBlock().asHeader(), params.getGenesisBlock().getWork(), 0);
            // The coinbase in the genesis block is not spendable
            List<Transaction> genesisTransactions = new LinkedList<>();
            StoredUndoableBlock storedGenesis = new StoredUndoableBlock(params.getGenesisBlock().getHash(), genesisTransactions);
            put(storedGenesisHeader, storedGenesis);
            setChainHead(storedGenesisHeader);
            setVerifiedChainHead(storedGenesisHeader);
            network = params.network();
        } catch (BlockStoreException | VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    public synchronized void put(StoredBlock block) throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        Sha256Hash hash = block.getHeader().getHash();
        blockMap.put(hash, new StoredBlockAndWasUndoableFlag(block, false));
    }
    
    @Override
    public synchronized final void put(StoredBlock storedBlock, StoredUndoableBlock undoableBlock) throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        Sha256Hash hash = storedBlock.getHeader().getHash();
        fullBlockMap.put(hash, storedBlock.getHeight(), undoableBlock);
        blockMap.put(hash, new StoredBlockAndWasUndoableFlag(storedBlock, true));
    }

    @Override
    @Nullable
    public synchronized StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        StoredBlockAndWasUndoableFlag storedBlock = blockMap.get(hash);
        return storedBlock == null ? null : storedBlock.block;
    }
    
    @Override
    @Nullable
    public synchronized StoredBlock getOnceUndoableStoredBlock(Sha256Hash hash) throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        StoredBlockAndWasUndoableFlag storedBlock = blockMap.get(hash);
        return (storedBlock != null && storedBlock.wasUndoable) ? storedBlock.block : null;
    }
    
    @Override
    @Nullable
    public synchronized StoredUndoableBlock getUndoBlock(Sha256Hash hash) throws BlockStoreException {
        Objects.requireNonNull(fullBlockMap, "MemoryFullPrunedBlockStore is closed");
        return fullBlockMap.get(hash);
    }

    @Override
    public synchronized StoredBlock getChainHead() throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        return chainHead;
    }

    @Override
    public synchronized final void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        this.chainHead = chainHead;
    }
    
    @Override
    public synchronized StoredBlock getVerifiedChainHead() throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        return verifiedChainHead;
    }

    @Override
    public synchronized final void setVerifiedChainHead(StoredBlock chainHead) throws BlockStoreException {
        Objects.requireNonNull(blockMap, "MemoryFullPrunedBlockStore is closed");
        this.verifiedChainHead = chainHead;
        if (this.chainHead.getHeight() < chainHead.getHeight())
            setChainHead(chainHead);
        // Potential leak here if not all blocks get setChainHead'd
        // Though the FullPrunedBlockStore allows for this, the current AbstractBlockChain will not do it.
        fullBlockMap.removeByHeight(chainHead.getHeight() - fullStoreDepth);
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
        Objects.requireNonNull(transactionOutputMap, "MemoryFullPrunedBlockStore is closed");
        return transactionOutputMap.get(new TransactionOutPoint(index, hash));
    }

    @Override
    public synchronized void addUnspentTransactionOutput(UTXO out) throws BlockStoreException {
        Objects.requireNonNull(transactionOutputMap, "MemoryFullPrunedBlockStore is closed");
        transactionOutputMap.put(new TransactionOutPoint(out.getIndex(), out.getHash()), out);
    }

    @Override
    public synchronized void removeUnspentTransactionOutput(UTXO out) throws BlockStoreException {
        Objects.requireNonNull(transactionOutputMap, "MemoryFullPrunedBlockStore is closed");
        if (transactionOutputMap.remove(new TransactionOutPoint(out.getIndex(), out.getHash())) == null)
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
    public Network network() {
        return network;
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
    public List<UTXO> getOpenTransactionOutputs(List<ECKey> keys) throws UTXOProviderException {
        // This is *NOT* optimal: We go through all the outputs and select the ones we are looking for.
        // If someone uses this store for production then they have a lot more to worry about than an inefficient impl :)
        List<UTXO> foundOutputs = new ArrayList<>();
        List<UTXO> outputsList = transactionOutputMap.values();
        for (UTXO output : outputsList) {
            for (ECKey key : keys) {
                // TODO switch to pubKeyHash in order to support native segwit addresses
                Script script = output.getScript();
                if (ScriptPattern.isP2PKH(script) || ScriptPattern.isP2PK(script)) {
                    Address outputAddress = script.getToAddress(network, true);
                    Address keyAddress = key.toAddress(ScriptType.P2PKH, network);
                    if (outputAddress.equals(keyAddress)) {
                        foundOutputs.add(output);
                    }
                }
            }
        }
        return foundOutputs;
    }
}
