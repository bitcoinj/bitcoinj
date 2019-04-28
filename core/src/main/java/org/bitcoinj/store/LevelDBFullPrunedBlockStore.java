/*
 * Copyright 2016 Robin Owens
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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.io.*;
import java.nio.ByteBuffer;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.StoredUndoableBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutputChanges;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.core.UTXOProviderException;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.iq80.leveldb.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.fusesource.leveldbjni.JniDBFactory.*;

import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;

/**
 * <p>
 * An implementation of a Fully Pruned Block Store using a leveldb implementation as the backing data store.
 * </p>
 * 
 * <p>
 * Includes number of caches to optimise the initial blockchain download.
 * </p>
 */

public class LevelDBFullPrunedBlockStore implements FullPrunedBlockStore {
    private static final Logger log = LoggerFactory.getLogger(LevelDBFullPrunedBlockStore.class);

    NetworkParameters params;

    // LevelDB reference.
    DB db = null;

    // Standard blockstore properties
    protected Sha256Hash chainHeadHash;
    protected StoredBlock chainHeadBlock;
    protected Sha256Hash verifiedChainHeadHash;
    protected StoredBlock verifiedChainHeadBlock;
    protected int fullStoreDepth;
    // Indicates if we track and report runtime for each method
    // this is very useful to focus performance tuning on correct areas.
    protected boolean instrument = false;
    // instrumentation stats
    Stopwatch totalStopwatch;
    protected long hit;
    protected long miss;
    Map<String, Stopwatch> methodStartTime;
    Map<String, Long> methodCalls;
    Map<String, Long> methodTotalTime;
    int exitBlock; // Must be multiple of 1000 and causes code to exit at this
                   // block!
    // ONLY used for performance benchmarking.

    // LRU Cache for getTransactionOutput
    protected Map<ByteBuffer, UTXO> utxoCache;
    // Additional cache to cope with case when transactions are rolled back
    // e.g. when block fails to verify.
    protected Map<ByteBuffer, UTXO> utxoUncommittedCache;
    protected Set<ByteBuffer> utxoUncommittedDeletedCache;

    // Database folder
    protected String filename;

    // Do we auto commit transactions.
    protected boolean autoCommit = true;

    // Datastructures to allow us to search for uncommited inserts/deletes.
    // leveldb does not support dirty reads so we have to
    // do it ourselves.
    Map<ByteBuffer, byte[]> uncommited;
    Set<ByteBuffer> uncommitedDeletes;

    // Sizes of leveldb caches.
    protected long leveldbReadCache;
    protected int leveldbWriteCache;

    // Size of cache for getTransactionOutput
    protected int openOutCache;
    // Bloomfilter for caching calls to hasUnspentOutputs
    protected BloomFilter bloom;

    // Defaults for cache sizes
    static final long LEVELDB_READ_CACHE_DEFAULT = 100 * 1048576; // 100 meg
    static final int LEVELDB_WRITE_CACHE_DEFAULT = 10 * 1048576; // 10 meg
    static final int OPENOUT_CACHE_DEFAULT = 100000;

    // LRUCache
    public class LRUCache extends LinkedHashMap<ByteBuffer, UTXO> {
        private static final long serialVersionUID = 1L;
        private int capacity;

        public LRUCache(int capacity, float loadFactor) {
            super(capacity, loadFactor, true);
            this.capacity = capacity;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<ByteBuffer, UTXO> eldest) {
            return size() > this.capacity;
        }
    }

    // Simple bloomfilter. We take advantage of fact that a Transaction Hash
    // can be split into 3 30bit numbers that are all random and uncorrelated
    // so ideal to use as the input to a 3 function bloomfilter. No has function
    // needed.
    private class BloomFilter {
        private byte[] cache;
        public long returnedTrue;
        public long returnedFalse;
        public long added;

        public BloomFilter() {
            // 2^27 so since 8 bits in a byte this is
            // 1,073,741,824 bits
            cache = new byte[134217728];
            // This size chosen as with 3 functions we should only get 4% errors
            // with 150m entries.
        }

        // Called to prime cache.
        // Might be idea to call periodically to flush out removed keys.
        // Would need to benchmark 1st though.
        public void reloadCache(DB db) {
            // LevelDB is great at scanning consecutive keys.
            // This take seconds even with 20m keys to add.
            log.info("Loading Bloom Filter");
            DBIterator iterator = db.iterator();
            byte[] key = getKey(KeyType.OPENOUT_ALL);
            for (iterator.seek(key); iterator.hasNext(); iterator.next()) {
                ByteBuffer bbKey = ByteBuffer.wrap(iterator.peekNext().getKey());
                byte firstByte = bbKey.get(); // remove the KeyType.OPENOUT_ALL
                                              // byte.
                if (key[0] != firstByte) {
                    printStat();
                    return;
                }

                byte[] hash = new byte[32];
                bbKey.get(hash);
                add(hash);
            }
            try {
                iterator.close();
            } catch (IOException e) {
                log.error("Error closing iterator", e);
            }
            printStat();
        }

        public void printStat() {
            log.info("Bloom Added: " + added + " T: " + returnedTrue + " F: " + returnedFalse);
        }

        // Add a txhash to the filter.
        public void add(byte[] hash) {
            byte[] firstHash = new byte[4];
            added++;
            for (int i = 0; i < 3; i++) {
                System.arraycopy(hash, i * 4, firstHash, 0, 4);
                setBit(firstHash);
            }
        }

        public void add(Sha256Hash hash) {
            add(hash.getBytes());
        }

        // check if hash was added.
        // if returns false then 100% sure never added
        // if returns true need to check what state is in DB as can
        // not be 100% sure.
        public boolean wasAdded(Sha256Hash hash) {

            byte[] firstHash = new byte[4];
            for (int i = 0; i < 3; i++) {
                System.arraycopy(hash.getBytes(), i * 4, firstHash, 0, 4);
                boolean result = getBit(firstHash);
                if (!result) {
                    returnedFalse++;
                    return false;
                }
            }
            returnedTrue++;
            return true;
        }

        private void setBit(byte[] entry) {
            int arrayIndex = (entry[0] & 0x3F) << 21 | (entry[1] & 0xFF) << 13 | (entry[2] & 0xFF) << 5
                    | (entry[3] & 0xFF) >> 3;
            int bit = (entry[3] & 0x07);
            int orBit = (0x1 << bit);
            byte newEntry = (byte) ((int) cache[arrayIndex] | orBit);
            cache[arrayIndex] = newEntry;
        }

        private boolean getBit(byte[] entry) {
            int arrayIndex = (entry[0] & 0x3F) << 21 | (entry[1] & 0xFF) << 13 | (entry[2] & 0xFF) << 5
                    | (entry[3] & 0xFF) >> 3;
            int bit = (entry[3] & 0x07);
            int orBit = (0x1 << bit);
            byte arrayEntry = cache[arrayIndex];

            int result = arrayEntry & orBit;
            if (result == 0) {
                return false;

            } else {
                return true;
            }
        }
    }

    public LevelDBFullPrunedBlockStore(NetworkParameters params, String filename, int blockCount) {
        this(params, filename, blockCount, LEVELDB_READ_CACHE_DEFAULT, LEVELDB_WRITE_CACHE_DEFAULT,
                OPENOUT_CACHE_DEFAULT, false, Integer.MAX_VALUE);
    }

    public LevelDBFullPrunedBlockStore(NetworkParameters params, String filename, int blockCount, long leveldbReadCache,
            int leveldbWriteCache, int openOutCache, boolean instrument, int exitBlock) {
        this.params = params;
        fullStoreDepth = blockCount;
        this.instrument = instrument;
        this.exitBlock = exitBlock;
        methodStartTime = new HashMap<>();
        methodCalls = new HashMap<>();
        methodTotalTime = new HashMap<>();

        this.filename = filename;
        this.leveldbReadCache = leveldbReadCache;
        this.leveldbWriteCache = leveldbWriteCache;
        this.openOutCache = openOutCache;
        bloom = new BloomFilter();
        totalStopwatch = Stopwatch.createStarted();
        openDB();
        bloom.reloadCache(db);

        // Reset after bloom filter loaded
        totalStopwatch = Stopwatch.createStarted();
    }

    private void openDB() {
        Options options = new Options();
        options.createIfMissing(true);
        // options.compressionType(CompressionType.NONE);
        options.cacheSize(leveldbReadCache);
        options.writeBufferSize(leveldbWriteCache);
        options.maxOpenFiles(10000);
        // options.blockSize(1024*1024*50);
        try {
            db = factory.open(new File(filename), options);
        } catch (IOException e) {
            throw new RuntimeException("Can not open DB", e);
        }

        utxoCache = new LRUCache(openOutCache, 0.75f);
        try {
            if (batchGet(getKey(KeyType.CREATED)) == null) {
                createNewStore(params);
            } else {
                initFromDb();
            }
        } catch (BlockStoreException e) {
            throw new RuntimeException("Can not init/load db", e);
        }
    }

    private void initFromDb() throws BlockStoreException {
        Sha256Hash hash = Sha256Hash.wrap(batchGet(getKey(KeyType.CHAIN_HEAD_SETTING)));
        this.chainHeadBlock = get(hash);
        this.chainHeadHash = hash;
        if (this.chainHeadBlock == null) {
            throw new BlockStoreException("corrupt database block store - head block not found");
        }

        hash = Sha256Hash.wrap(batchGet(getKey(KeyType.VERIFIED_CHAIN_HEAD_SETTING)));
        this.verifiedChainHeadBlock = get(hash);
        this.verifiedChainHeadHash = hash;
        if (this.verifiedChainHeadBlock == null) {
            throw new BlockStoreException("corrupt database block store - verified head block not found");
        }
    }

    private void createNewStore(NetworkParameters params) throws BlockStoreException {
        try {
            // Set up the genesis block. When we start out fresh, it is by
            // definition the top of the chain.
            StoredBlock storedGenesisHeader = new StoredBlock(params.getGenesisBlock().cloneAsHeader(),
                    params.getGenesisBlock().getWork(), 0);
            // The coinbase in the genesis block is not spendable. This is
            // because of how the reference client inits
            // its database - the genesis transaction isn't actually in the db
            // so its spent flags can never be updated.
            List<Transaction> genesisTransactions = Lists.newLinkedList();
            StoredUndoableBlock storedGenesis = new StoredUndoableBlock(params.getGenesisBlock().getHash(),
                    genesisTransactions);
            beginDatabaseBatchWrite();
            put(storedGenesisHeader, storedGenesis);
            setChainHead(storedGenesisHeader);
            setVerifiedChainHead(storedGenesisHeader);
            batchPut(getKey(KeyType.CREATED), bytes("done"));
            commitDatabaseBatchWrite();
        } catch (VerificationException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    void beginMethod(String name) {
        methodStartTime.put(name, Stopwatch.createStarted());
    }

    void endMethod(String name) {
        if (methodCalls.containsKey(name)) {
            methodCalls.put(name, methodCalls.get(name) + 1);
            methodTotalTime.put(name,
                    methodTotalTime.get(name) + methodStartTime.get(name).elapsed(TimeUnit.NANOSECONDS));
        } else {
            methodCalls.put(name, 1l);
            methodTotalTime.put(name, methodStartTime.get(name).elapsed(TimeUnit.NANOSECONDS));
        }
    }

    // Debug method to display stats on runtime of each method
    // and cache hit rates etc..
    void dumpStats() {
        long wallTimeNanos = totalStopwatch.elapsed(TimeUnit.NANOSECONDS);
        long dbtime = 0;
        for (String name : methodCalls.keySet()) {
            long calls = methodCalls.get(name);
            long time = methodTotalTime.get(name);
            dbtime += time;
            long average = time / calls;
            double proportion = (time + 0.0) / (wallTimeNanos + 0.0);
            log.info(name + " c:" + calls + " r:" + time + " a:" + average + " p:" + String.format("%.2f", proportion));
        }
        double dbproportion = (dbtime + 0.0) / (wallTimeNanos + 0.0);
        double hitrate = (hit + 0.0) / (hit + miss + 0.0);
        log.info("Cache size:" + utxoCache.size() + " hit:" + hit + " miss:" + miss + " rate:"
                + String.format("%.2f", hitrate));
        bloom.printStat();
        log.info("hasTxOut call:" + hasCall + " True:" + hasTrue + " False:" + hasFalse);
        log.info("Wall:" + totalStopwatch + " percent:" + String.format("%.2f", dbproportion));
        String stats = db.getProperty("leveldb.stats");
        System.out.println(stats);

    }

    @Override
    public void put(StoredBlock block) throws BlockStoreException {
        putUpdateStoredBlock(block, false);
    }

    @Override
    public StoredBlock getChainHead() throws BlockStoreException {
        return chainHeadBlock;
    }

    @Override
    public void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        if (instrument)
            beginMethod("setChainHead");
        Sha256Hash hash = chainHead.getHeader().getHash();
        this.chainHeadHash = hash;
        this.chainHeadBlock = chainHead;
        batchPut(getKey(KeyType.CHAIN_HEAD_SETTING), hash.getBytes());
        if (instrument)
            endMethod("setChainHead");
    }

    @Override
    public void close() throws BlockStoreException {
        try {
            db.close();
        } catch (IOException e) {
            throw new BlockStoreException("Could not close db", e);
        }
    }

    @Override
    public NetworkParameters getParams() {
        return params;
    }

    @Override
    public List<UTXO> getOpenTransactionOutputs(List<ECKey> keys) throws UTXOProviderException {
        // Run this on a snapshot of database so internally consistent result
        // This is critical or if one address paid another could get incorrect
        // results

        List<UTXO> results = new LinkedList<>();
        for (ECKey key : keys) {
            ByteBuffer bb = ByteBuffer.allocate(21);
            bb.put((byte) KeyType.ADDRESS_HASHINDEX.ordinal());
            bb.put(key.getPubKeyHash());

            ReadOptions ro = new ReadOptions();
            Snapshot sn = db.getSnapshot();
            ro.snapshot(sn);

            // Scanning over iterator very fast

            DBIterator iterator = db.iterator(ro);
            for (iterator.seek(bb.array()); iterator.hasNext(); iterator.next()) {
                ByteBuffer bbKey = ByteBuffer.wrap(iterator.peekNext().getKey());
                bbKey.get(); // remove the address_hashindex byte.
                byte[] addressKey = new byte[20];
                bbKey.get(addressKey);
                if (!Arrays.equals(addressKey, key.getPubKeyHash())) {
                    break;
                }
                byte[] hashBytes = new byte[32];
                bbKey.get(hashBytes);
                int index = bbKey.getInt();
                Sha256Hash hash = Sha256Hash.wrap(hashBytes);
                UTXO txout;
                try {
                    // TODO this should be on the SNAPSHOT too......
                    // this is really a BUG.
                    txout = getTransactionOutput(hash, index);
                } catch (BlockStoreException e) {
                    throw new UTXOProviderException("block store execption", e);
                }
                if (txout != null) {
                    Script sc = txout.getScript();
                    Address address = sc.getToAddress(params, true);
                    UTXO output = new UTXO(txout.getHash(), txout.getIndex(), txout.getValue(), txout.getHeight(),
                            txout.isCoinbase(), txout.getScript(), address.toString());
                    results.add(output);
                }
            }
            try {
                iterator.close();
                ro = null;
                sn.close();
                sn = null;
            } catch (IOException e) {
                log.error("Error closing snapshot/iterator?", e);
            }
        }
        return results;
    }

    @Override
    public int getChainHeadHeight() throws UTXOProviderException {
        try {
            return getVerifiedChainHead().getHeight();
        } catch (BlockStoreException e) {
            throw new UTXOProviderException(e);
        }
    }

    protected void putUpdateStoredBlock(StoredBlock storedBlock, boolean wasUndoable) {
        // We put as one record as then the get is much faster.
        if (instrument)
            beginMethod("putUpdateStoredBlock");
        Sha256Hash hash = storedBlock.getHeader().getHash();
        ByteBuffer bb = ByteBuffer.allocate(97);
        storedBlock.serializeCompact(bb);
        bb.put((byte) (wasUndoable ? 1 : 0));
        batchPut(getKey(KeyType.HEADERS_ALL, hash), bb.array());
        if (instrument)
            endMethod("putUpdateStoredBlock");
    }

    @Override
    public void put(StoredBlock storedBlock, StoredUndoableBlock undoableBlock) throws BlockStoreException {
        if (instrument)
            beginMethod("put");
        int height = storedBlock.getHeight();
        byte[] transactions = null;
        byte[] txOutChanges = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (undoableBlock.getTxOutChanges() != null) {
                undoableBlock.getTxOutChanges().serializeToStream(bos);
                txOutChanges = bos.toByteArray();
            } else {
                int numTxn = undoableBlock.getTransactions().size();
                Utils.uint32ToByteStreamLE(numTxn, bos);
                for (Transaction tx : undoableBlock.getTransactions())
                    tx.bitcoinSerialize(bos);
                transactions = bos.toByteArray();
            }
            bos.close();
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }

        Sha256Hash hash = storedBlock.getHeader().getHash();

        ByteBuffer keyBuf = ByteBuffer.allocate(33);
        keyBuf.put((byte) KeyType.HEIGHT_UNDOABLEBLOCKS.ordinal());
        keyBuf.putInt(height);
        keyBuf.put(hash.getBytes(), 4, 28);
        batchPut(keyBuf.array(), new byte[1]);

        if (transactions == null) {
            ByteBuffer undoBuf = ByteBuffer.allocate(4 + 4 + txOutChanges.length + 4 + 0);
            undoBuf.putInt(height);
            undoBuf.putInt(txOutChanges.length);
            undoBuf.put(txOutChanges);
            undoBuf.putInt(0);
            batchPut(getKey(KeyType.UNDOABLEBLOCKS_ALL, hash), undoBuf.array());
        } else {
            ByteBuffer undoBuf = ByteBuffer.allocate(4 + 4 + 0 + 4 + transactions.length);
            undoBuf.putInt(height);
            undoBuf.putInt(0);
            undoBuf.putInt(transactions.length);
            undoBuf.put(transactions);
            batchPut(getKey(KeyType.UNDOABLEBLOCKS_ALL, hash), undoBuf.array());
        }
        if (instrument)
            endMethod("put");
        putUpdateStoredBlock(storedBlock, true);
    }

    // Since LevelDB is a key value store we do not have "tables".
    // So these keys are the 1st byte of each key to indicate the "table" it is
    // in.
    // Do wonder if grouping each "table" like this is efficient or not...
    enum KeyType {
        CREATED, CHAIN_HEAD_SETTING, VERIFIED_CHAIN_HEAD_SETTING, VERSION_SETTING, HEADERS_ALL, UNDOABLEBLOCKS_ALL, HEIGHT_UNDOABLEBLOCKS, OPENOUT_ALL, ADDRESS_HASHINDEX
    }

    // These helpers just get the key for an input
    private byte[] getKey(KeyType keytype) {
        byte[] key = new byte[1];
        key[0] = (byte) keytype.ordinal();
        return key;
    }

    private byte[] getTxKey(KeyType keytype, Sha256Hash hash) {
        byte[] key = new byte[33];

        key[0] = (byte) keytype.ordinal();
        System.arraycopy(hash.getBytes(), 0, key, 1, 32);
        return key;
    }

    private byte[] getTxKey(KeyType keytype, Sha256Hash hash, int index) {
        byte[] key = new byte[37];

        key[0] = (byte) keytype.ordinal();
        System.arraycopy(hash.getBytes(), 0, key, 1, 32);
        byte[] heightBytes = ByteBuffer.allocate(4).putInt(index).array();
        System.arraycopy(heightBytes, 0, key, 33, 4);
        return key;
    }

    private byte[] getKey(KeyType keytype, Sha256Hash hash) {
        byte[] key = new byte[29];

        key[0] = (byte) keytype.ordinal();
        System.arraycopy(hash.getBytes(), 4, key, 1, 28);
        return key;
    }

    private byte[] getKey(KeyType keytype, byte[] hash) {
        byte[] key = new byte[29];

        key[0] = (byte) keytype.ordinal();
        System.arraycopy(hash, 4, key, 1, 28);
        return key;
    }

    @Override
    public StoredBlock getOnceUndoableStoredBlock(Sha256Hash hash) throws BlockStoreException {
        return get(hash, true);
    }

    @Override
    public StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        return get(hash, false);
    }

    public StoredBlock get(Sha256Hash hash, boolean wasUndoableOnly) throws BlockStoreException {

        // Optimize for chain head
        if (chainHeadHash != null && chainHeadHash.equals(hash))
            return chainHeadBlock;
        if (verifiedChainHeadHash != null && verifiedChainHeadHash.equals(hash))
            return verifiedChainHeadBlock;

        if (instrument)
            beginMethod("get");// ignore optimised case as not interesting for
                               // tuning.
        boolean undoableResult;

        byte[] result = batchGet(getKey(KeyType.HEADERS_ALL, hash));
        if (result == null) {
            if (instrument)
                endMethod("get");
            return null;
        }
        undoableResult = (result[96] == 1 ? true : false);
        if (wasUndoableOnly && !undoableResult) {
            if (instrument)
                endMethod("get");
            return null;
        }
        // TODO Should I chop the last byte off? Seems to work with it left
        // there...
        StoredBlock stored = StoredBlock.deserializeCompact(params, ByteBuffer.wrap(result));
        stored.getHeader().verifyHeader();

        if (instrument)
            endMethod("get");
        return stored;
    }

    @Override
    public StoredUndoableBlock getUndoBlock(Sha256Hash hash) throws BlockStoreException {
        try {
            if (instrument)
                beginMethod("getUndoBlock");

            byte[] result = batchGet(getKey(KeyType.UNDOABLEBLOCKS_ALL, hash));

            if (result == null) {
                if (instrument)
                    endMethod("getUndoBlock");
                return null;
            }
            ByteBuffer bb = ByteBuffer.wrap(result);
            bb.getInt();// TODO Read height - but seems to be unused - maybe can
                        // skip storing it but only 4 bytes!
            int txOutSize = bb.getInt();

            StoredUndoableBlock block;
            if (txOutSize == 0) {
                int txSize = bb.getInt();
                byte[] transactions = new byte[txSize];
                bb.get(transactions);
                int numTxn = (int) Utils.readUint32(transactions, 0);
                int offset = 4;
                List<Transaction> transactionList = new LinkedList<>();
                for (int i = 0; i < numTxn; i++) {
                    Transaction tx = new Transaction(params, transactions, offset);
                    transactionList.add(tx);
                    offset += tx.getMessageSize();
                }
                block = new StoredUndoableBlock(hash, transactionList);
            } else {
                byte[] txOutChanges = new byte[txOutSize];
                bb.get(txOutChanges);
                TransactionOutputChanges outChangesObject = new TransactionOutputChanges(
                        new ByteArrayInputStream(txOutChanges));
                block = new StoredUndoableBlock(hash, outChangesObject);
            }
            if (instrument)
                endMethod("getUndoBlock");
            return block;
        } catch (IOException e) {
            // Corrupted database.
            if (instrument)
                endMethod("getUndoBlock");
            throw new BlockStoreException(e);
        }

    }

    @Override
    public UTXO getTransactionOutput(Sha256Hash hash, long index) throws BlockStoreException {
        if (instrument)
            beginMethod("getTransactionOutput");

        try {
            UTXO result = null;
            byte[] key = getTxKey(KeyType.OPENOUT_ALL, hash, (int) index);
            // Use cache
            if (autoCommit) {
                // Simple case of auto commit on so cache is consistent.
                result = utxoCache.get(ByteBuffer.wrap(key));
            } else {
                // Check if we have an uncommitted delete.
                if (utxoUncommittedDeletedCache.contains(ByteBuffer.wrap(key))) {
                    // has been deleted so return null;
                    hit++;
                    if (instrument)
                        endMethod("getTransactionOutput");
                    return result;
                }
                // Check if we have an uncommitted entry
                result = utxoUncommittedCache.get(ByteBuffer.wrap(key));
                if (result == null)
                    result = utxoCache.get(ByteBuffer.wrap(key));
                // And lastly above check if we have a committed cached entry

            }
            if (result != null) {
                hit++;
                if (instrument)
                    endMethod("getTransactionOutput");
                return result;
            }
            miss++;
            // If we get here have to hit the database.
            byte[] inbytes = batchGet(key);
            if (inbytes == null) {
                if (instrument)
                    endMethod("getTransactionOutput");
                return null;
            }
            ByteArrayInputStream bis = new ByteArrayInputStream(inbytes);
            UTXO txout = new UTXO(bis);

            if (instrument)
                endMethod("getTransactionOutput");
            return txout;
        } catch (DBException e) {
            log.error("Exception in getTransactionOutput.", e);
            if (instrument)
                endMethod("getTransactionOutput");
        } catch (IOException e) {
            log.error("Exception in getTransactionOutput.", e);
            if (instrument)
                endMethod("getTransactionOutput");
        }
        throw new BlockStoreException("problem");
    }

    @Override
    public void addUnspentTransactionOutput(UTXO out) throws BlockStoreException {

        if (instrument)
            beginMethod("addUnspentTransactionOutput");

        // Add to bloom filter - is very fast to add.
        bloom.add(out.getHash());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            out.serializeToStream(bos);
        } catch (IOException e) {
            throw new BlockStoreException("problem serialising utxo", e);
        }

        byte[] key = getTxKey(KeyType.OPENOUT_ALL, out.getHash(), (int) out.getIndex());
        batchPut(key, bos.toByteArray());

        if (autoCommit) {
            utxoCache.put(ByteBuffer.wrap(key), out);
        } else {
            utxoUncommittedCache.put(ByteBuffer.wrap(key), out);
            // leveldb just stores the last key/value added.
            // So if we do an add must remove any previous deletes.
            utxoUncommittedDeletedCache.remove(ByteBuffer.wrap(key));
        }

        // Could run this in parallel with above too.
        // Should update instrumentation to see if worth while.
        Address a;
        if (out.getAddress() == null || out.getAddress().equals("")) {
            if (instrument)
                endMethod("addUnspentTransactionOutput");
            return;
        } else {
            try {
                a = LegacyAddress.fromBase58(params, out.getAddress());
            } catch (AddressFormatException e) {
                if (instrument)
                    endMethod("addUnspentTransactionOutput");
                return;
            }
        }
        ByteBuffer bb = ByteBuffer.allocate(57);
        bb.put((byte) KeyType.ADDRESS_HASHINDEX.ordinal());
        bb.put(a.getHash());
        bb.put(out.getHash().getBytes());
        bb.putInt((int) out.getIndex());
        byte[] value = new byte[0];
        batchPut(bb.array(), value);
        if (instrument)
            endMethod("addUnspentTransactionOutput");
    }

    private void batchPut(byte[] key, byte[] value) {
        if (autoCommit) {
            db.put(key, value);
        } else {
            // Add this so we can get at uncommitted inserts which
            // leveldb does not support
            uncommited.put(ByteBuffer.wrap(key), value);
            batch.put(key, value);
        }
    }

    private byte[] batchGet(byte[] key) {
        ByteBuffer bbKey = ByteBuffer.wrap(key);

        // This is needed to cope with deletes that are not yet committed to db.
        if (!autoCommit && uncommitedDeletes != null && uncommitedDeletes.contains(bbKey))
            return null;

        byte[] value = null;
        // And this to handle uncommitted inserts (dirty reads)
        if (!autoCommit && uncommited != null) {
            value = uncommited.get(bbKey);
            if (value != null)
                return value;
        }
        try {
            value = db.get(key);
        } catch (DBException e) {
            log.error("Caught error opening file", e);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e1) {
            }
            value = db.get(key);
        }
        return value;
    }

    private void batchDelete(byte[] key) {
        if (!autoCommit) {
            batch.delete(key);
            uncommited.remove(ByteBuffer.wrap(key));
            uncommitedDeletes.add(ByteBuffer.wrap(key));
        } else {
            db.delete(key);
        }
    }

    @Override
    public void removeUnspentTransactionOutput(UTXO out) throws BlockStoreException {
        if (instrument)
            beginMethod("removeUnspentTransactionOutput");

        byte[] key = getTxKey(KeyType.OPENOUT_ALL, out.getHash(), (int) out.getIndex());

        if (autoCommit) {
            utxoCache.remove(ByteBuffer.wrap(key));
        } else {
            utxoUncommittedDeletedCache.add(ByteBuffer.wrap(key));
            utxoUncommittedCache.remove(ByteBuffer.wrap(key));
        }

        batchDelete(key);
        // could run this and the above in parallel
        // Need to update instrumentation to check if worth the effort

        // TODO storing as byte[] hash to save space. But think should just
        // store as String of address. Might be faster. Need to test.
        ByteBuffer bb = ByteBuffer.allocate(57);
        Address a;
        byte[] hashBytes = null;
        try {
            String address = out.getAddress();
            if (address == null || address.equals("")) {
                Script sc = out.getScript();
                a = sc.getToAddress(params);
                hashBytes = a.getHash();
            } else {
                a = LegacyAddress.fromBase58(params, out.getAddress());
                hashBytes = a.getHash();
            }
        } catch (AddressFormatException e) {
            if (instrument)
                endMethod("removeUnspentTransactionOutput");
            return;
        } catch (ScriptException e) {
            if (instrument)
                endMethod("removeUnspentTransactionOutput");
            return;
        }
        bb.put((byte) KeyType.ADDRESS_HASHINDEX.ordinal());
        bb.put(hashBytes);
        bb.put(out.getHash().getBytes());
        bb.putInt((int) out.getIndex());
        batchDelete(bb.array());

        if (instrument)
            endMethod("removeUnspentTransactionOutput");
    }

    // Instrumentation of bloom filter to check theory
    // matches reality. Without this initial chain sync takes
    // 50-75% longer.
    long hasCall;
    long hasTrue;
    long hasFalse;

    @Override
    public boolean hasUnspentOutputs(Sha256Hash hash, int numOutputs) throws BlockStoreException {
        if (instrument)
            beginMethod("hasUnspentOutputs");
        hasCall++;
        if (!bloom.wasAdded(hash)) {
            if (instrument)
                endMethod("hasUnspentOutputs");
            hasFalse++;
            return false;
        }
        // no index is fine as will find any entry with any index...
        // TODO should I be checking uncommitted inserts/deletes???
        byte[] key = getTxKey(KeyType.OPENOUT_ALL, hash);
        byte[] subResult = new byte[key.length];
        DBIterator iterator = db.iterator();
        for (iterator.seek(key); iterator.hasNext();) {
            byte[] result = iterator.peekNext().getKey();
            System.arraycopy(result, 0, subResult, 0, subResult.length);
            if (Arrays.equals(key, subResult)) {
                hasTrue++;
                try {
                    iterator.close();
                } catch (IOException e) {
                    log.error("Error closing iterator", e);
                }
                if (instrument)
                    endMethod("hasUnspentOutputs");
                return true;
            } else {
                hasFalse++;
                try {
                    iterator.close();
                } catch (IOException e) {
                    log.error("Error closing iterator", e);
                }
                if (instrument)
                    endMethod("hasUnspentOutputs");
                return false;
            }
        }
        try {
            iterator.close();
        } catch (IOException e) {
            log.error("Error closing iterator", e);
        }
        hasFalse++;
        if (instrument)
            endMethod("hasUnspentOutputs");
        return false;
    }

    @Override
    public StoredBlock getVerifiedChainHead() throws BlockStoreException {
        return verifiedChainHeadBlock;
    }

    @Override
    public void setVerifiedChainHead(StoredBlock chainHead) throws BlockStoreException {
        if (instrument)
            beginMethod("setVerifiedChainHead");
        Sha256Hash hash = chainHead.getHeader().getHash();
        this.verifiedChainHeadHash = hash;
        this.verifiedChainHeadBlock = chainHead;
        batchPut(getKey(KeyType.VERIFIED_CHAIN_HEAD_SETTING), hash.getBytes());
        if (this.chainHeadBlock.getHeight() < chainHead.getHeight())
            setChainHead(chainHead);
        removeUndoableBlocksWhereHeightIsLessThan(chainHead.getHeight() - fullStoreDepth);
        if (instrument)
            endMethod("setVerifiedChainHead");
    }

    void removeUndoableBlocksWhereHeightIsLessThan(int height) {
        if (height < 0)
            return;
        DBIterator iterator = db.iterator();
        ByteBuffer keyBuf = ByteBuffer.allocate(5);
        keyBuf.put((byte) KeyType.HEIGHT_UNDOABLEBLOCKS.ordinal());
        keyBuf.putInt(height);

        for (iterator.seek(keyBuf.array()); iterator.hasNext(); iterator.next()) {

            byte[] bytekey = iterator.peekNext().getKey();
            ByteBuffer buff = ByteBuffer.wrap(bytekey);
            buff.get(); // Just remove byte from buffer.
            int keyHeight = buff.getInt();

            byte[] hashbytes = new byte[32];
            buff.get(hashbytes, 4, 28);

            if (keyHeight > height)
                break;

            batchDelete(getKey(KeyType.UNDOABLEBLOCKS_ALL, hashbytes));
            batchDelete(bytekey);
        }
        try {
            iterator.close();
        } catch (IOException e) {
            log.error("Error closing iterator", e);
        }

    }

    WriteBatch batch;

    @Override
    public void beginDatabaseBatchWrite() throws BlockStoreException {
        // This is often called twice in row! But they are not nested
        // transactions!
        // We just ignore the second call.
        if (!autoCommit) {
            return;
        }
        if (instrument)
            beginMethod("beginDatabaseBatchWrite");

        batch = db.createWriteBatch();
        uncommited = new HashMap<>();
        uncommitedDeletes = new HashSet<>();
        utxoUncommittedCache = new HashMap<>();
        utxoUncommittedDeletedCache = new HashSet<>();
        autoCommit = false;
        if (instrument)
            endMethod("beginDatabaseBatchWrite");
    }

    @Override
    public void commitDatabaseBatchWrite() throws BlockStoreException {
        uncommited = null;
        uncommitedDeletes = null;
        if (instrument)
            beginMethod("commitDatabaseBatchWrite");

        db.write(batch);
        // order of these is not important as we only allow entry to be in one
        // or the other.
        // must update cache with uncommitted adds/deletes.
        for (Map.Entry<ByteBuffer, UTXO> entry : utxoUncommittedCache.entrySet()) {

            utxoCache.put(entry.getKey(), entry.getValue());
        }
        utxoUncommittedCache = null;
        for (ByteBuffer entry : utxoUncommittedDeletedCache) {
            utxoCache.remove(entry);
        }
        utxoUncommittedDeletedCache = null;

        autoCommit = true;

        try {
            batch.close();
            batch = null;
        } catch (IOException e) {
            log.error("Error in db commit.", e);
            throw new BlockStoreException("could not close batch.");
        }

        if (instrument)
            endMethod("commitDatabaseBatchWrite");

        if (instrument && verifiedChainHeadBlock.getHeight() % 1000 == 0) {
            log.info("Height: " + verifiedChainHeadBlock.getHeight());
            dumpStats();
            if (verifiedChainHeadBlock.getHeight() == exitBlock) {
                System.err.println("Exit due to exitBlock set");
                System.exit(1);
            }
        }
    }

    @Override
    public void abortDatabaseBatchWrite() throws BlockStoreException {
        try {
            uncommited = null;
            uncommitedDeletes = null;
            utxoUncommittedCache = null;
            utxoUncommittedDeletedCache = null;
            autoCommit = true;
            if (batch != null) {
                batch.close();
                batch = null;
            }
        } catch (IOException e) {
            throw new BlockStoreException("could not close batch in abort.", e);
        }
    }

    public void resetStore() {
        // only used in unit tests.
        // bit dangerous and deletes files!
        try {
            db.close();
            uncommited = null;
            uncommitedDeletes = null;
            autoCommit = true;
            bloom = new BloomFilter();
            utxoCache = new LRUCache(openOutCache, 0.75f);
        } catch (IOException e) {
            log.error("Exception in resetStore.", e);
        }

        File f = new File(filename);
        if (f.isDirectory()) {
            for (File c : f.listFiles())
                c.delete();
        }
        openDB();
    }
}
