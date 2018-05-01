/*
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

package org.bitcoinj.store;

import org.bitcoinj.core.*;
import org.bitcoinj.utils.*;
import org.slf4j.*;

import javax.annotation.*;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.locks.*;

import static com.google.common.base.Preconditions.*;

// TODO: Lose the mmap in this class. There are too many platform bugs that require odd workarounds.

/**
 * An SPVBlockStore holds a limited number of block headers in a memory mapped ring buffer. With such a store, you
 * may not be able to process very deep re-orgs and could be disconnected from the chain (requiring a replay),
 * but as they are virtually unheard of this is not a significant risk.
 */
public class SPVBlockStore implements BlockStore {
    private static final Logger log = LoggerFactory.getLogger(SPVBlockStore.class);

    /** The default number of headers that will be stored in the ring buffer. */
    public static final int DEFAULT_CAPACITY = 5000;
    public static final String HEADER_MAGIC = "SPVB";

    protected volatile MappedByteBuffer buffer;
    protected final NetworkParameters params;

    protected ReentrantLock lock = Threading.lock("SPVBlockStore");

    // The entire ring-buffer is mmapped and accessing it should be as fast as accessing regular memory once it's
    // faulted in. Unfortunately, in theory practice and theory are the same. In practice they aren't.
    //
    // MMapping a file in Java does not give us a byte[] as you may expect but rather a ByteBuffer, and whilst on
    // the OpenJDK/Oracle JVM calls into the get() methods are compiled down to inlined native code on Android each
    // get() call is actually a full-blown JNI method under the hood, meaning it's unbelievably slow. The caches
    // below let us stay in the JIT-compiled Java world without expensive JNI transitions and make a 10x difference!
    protected LinkedHashMap<Sha256Hash, StoredBlock> blockCache = new LinkedHashMap<Sha256Hash, StoredBlock>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Sha256Hash, StoredBlock> entry) {
            return size() > 2050;  // Slightly more than the difficulty transition period.
        }
    };
    // Use a separate cache to track get() misses. This is to efficiently handle the case of an unconnected block
    // during chain download. Each new block will do a get() on the unconnected block so if we haven't seen it yet we
    // must efficiently respond.
    //
    // We don't care about the value in this cache. It is always notFoundMarker. Unfortunately LinkedHashSet does not
    // provide the removeEldestEntry control.
    private static final Object NOT_FOUND_MARKER = new Object();
    protected LinkedHashMap<Sha256Hash, Object> notFoundCache = new LinkedHashMap<Sha256Hash, Object>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Sha256Hash, Object> entry) {
            return size() > 100;  // This was chosen arbitrarily.
        }
    };
    // Used to stop other applications/processes from opening the store.
    protected FileLock fileLock = null;
    protected RandomAccessFile randomAccessFile = null;
    private int fileLength;

    /**
     * Creates and initializes an SPV block store that can hold {@link #DEFAULT_CAPACITY} block headers. Will create the
     * given file if it's missing. This operation will block on disk.
     * @param file file to use for the block store
     * @throws BlockStoreException if something goes wrong
     */
    public SPVBlockStore(NetworkParameters params, File file) throws BlockStoreException {
        this(params, file, DEFAULT_CAPACITY, false);
    }

    /**
     * Creates and initializes an SPV block store that can hold a given amount of blocks. Will create the given file if
     * it's missing. This operation will block on disk.
     * @param file file to use for the block store
     * @param capacity custom capacity in number of block headers
     * @param grow wether or not to migrate an existing block store of different capacity
     * @throws BlockStoreException if something goes wrong
     */
    public SPVBlockStore(NetworkParameters params, File file, int capacity, boolean grow) throws BlockStoreException {
        checkNotNull(file);
        this.params = checkNotNull(params);
        checkArgument(capacity > 0);
        try {
            boolean exists = file.exists();
            // Set up the backing file.
            randomAccessFile = new RandomAccessFile(file, "rw");
            fileLength = getFileSize(capacity);
            if (!exists) {
                log.info("Creating new SPV block chain file " + file);
                randomAccessFile.setLength(fileLength);
            } else {
                final long currentLength = randomAccessFile.length();
                if (currentLength != fileLength) {
                    if ((currentLength - FILE_PROLOGUE_BYTES) % RECORD_SIZE != 0)
                        throw new BlockStoreException(
                                "File size on disk indicates this is not a block store: " + currentLength);
                    else if (!grow)
                        throw new BlockStoreException("File size on disk does not match expected size: " + currentLength
                                + " vs " + fileLength);
                    else if (fileLength < randomAccessFile.length())
                        throw new BlockStoreException(
                                "Shrinking is unsupported: " + currentLength + " vs " + fileLength);
                    else
                        randomAccessFile.setLength(fileLength);
                }
            }

            FileChannel channel = randomAccessFile.getChannel();
            fileLock = channel.tryLock();
            if (fileLock == null)
                throw new ChainFileLockedException("Store file is already locked by another process");

            // Map it into memory read/write. The kernel will take care of flushing writes to disk at the most
            // efficient times, which may mean that until the map is deallocated the data on disk is randomly
            // inconsistent. However the only process accessing it is us, via this mapping, so our own view will
            // always be correct. Once we establish the mmap the underlying file and channel can go away. Note that
            // the details of mmapping vary between platforms.
            buffer = channel.map(FileChannel.MapMode.READ_WRITE, 0, fileLength);

            // Check or initialize the header bytes to ensure we don't try to open some random file.
            if (exists) {
                byte[] header = new byte[4];
                buffer.get(header);
                if (!new String(header, StandardCharsets.US_ASCII).equals(HEADER_MAGIC))
                    throw new BlockStoreException("Header bytes do not equal " + HEADER_MAGIC);
            } else {
                initNewStore(params);
            }
        } catch (Exception e) {
            try {
                if (randomAccessFile != null) randomAccessFile.close();
            } catch (IOException e2) {
                throw new BlockStoreException(e2);
            }
            throw new BlockStoreException(e);
        }
    }

    private void initNewStore(NetworkParameters params) throws Exception {
        byte[] header;
        header = HEADER_MAGIC.getBytes("US-ASCII");
        buffer.put(header);
        // Insert the genesis block.
        lock.lock();
        try {
            setRingCursor(buffer, FILE_PROLOGUE_BYTES);
        } finally {
            lock.unlock();
        }
        Block genesis = params.getGenesisBlock().cloneAsHeader();
        StoredBlock storedGenesis = new StoredBlock(genesis, genesis.getWork(), 0);
        put(storedGenesis);
        setChainHead(storedGenesis);
    }

    /** Returns the size in bytes of the file that is used to store the chain with the current parameters. */
    public static final int getFileSize(int capacity) {
        return RECORD_SIZE * capacity + FILE_PROLOGUE_BYTES /* extra kilobyte for stuff */;
    }

    @Override
    public void put(StoredBlock block) throws BlockStoreException {
        final MappedByteBuffer buffer = this.buffer;
        if (buffer == null) throw new BlockStoreException("Store closed");

        lock.lock();
        try {
            int cursor = getRingCursor(buffer);
            if (cursor == fileLength) {
                // Wrapped around.
                cursor = FILE_PROLOGUE_BYTES;
            }
            buffer.position(cursor);
            Sha256Hash hash = block.getHeader().getHash();
            notFoundCache.remove(hash);
            buffer.put(hash.getBytes());
            block.serializeCompact(buffer);
            setRingCursor(buffer, buffer.position());
            blockCache.put(hash, block);
        } finally { lock.unlock(); }
    }

    @Override
    @Nullable
    public StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        final MappedByteBuffer buffer = this.buffer;
        if (buffer == null) throw new BlockStoreException("Store closed");

        lock.lock();
        try {
            StoredBlock cacheHit = blockCache.get(hash);
            if (cacheHit != null)
                return cacheHit;
            if (notFoundCache.get(hash) != null)
                return null;

            // Starting from the current tip of the ring work backwards until we have either found the block or
            // wrapped around.
            int cursor = getRingCursor(buffer);
            final int startingPoint = cursor;
            final byte[] targetHashBytes = hash.getBytes();
            byte[] scratch = new byte[32];
            do {
                cursor -= RECORD_SIZE;
                if (cursor < FILE_PROLOGUE_BYTES) {
                    // We hit the start, so wrap around.
                    cursor = fileLength - RECORD_SIZE;
                }
                // Cursor is now at the start of the next record to check, so read the hash and compare it.
                buffer.position(cursor);
                buffer.get(scratch);
                if (Arrays.equals(scratch, targetHashBytes)) {
                    // Found the target.
                    StoredBlock storedBlock = StoredBlock.deserializeCompact(params, buffer);
                    blockCache.put(hash, storedBlock);
                    return storedBlock;
                }
            } while (cursor != startingPoint);
            // Not found.
            notFoundCache.put(hash, NOT_FOUND_MARKER);
            return null;
        } catch (ProtocolException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } finally { lock.unlock(); }
    }

    protected StoredBlock lastChainHead = null;

    @Override
    public StoredBlock getChainHead() throws BlockStoreException {
        final MappedByteBuffer buffer = this.buffer;
        if (buffer == null) throw new BlockStoreException("Store closed");

        lock.lock();
        try {
            if (lastChainHead == null) {
                byte[] headHash = new byte[32];
                buffer.position(8);
                buffer.get(headHash);
                Sha256Hash hash = Sha256Hash.wrap(headHash);
                StoredBlock block = get(hash);
                if (block == null)
                    throw new BlockStoreException("Corrupted block store: could not find chain head: " + hash);
                lastChainHead = block;
            }
            return lastChainHead;
        } finally { lock.unlock(); }
    }

    @Override
    public void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        final MappedByteBuffer buffer = this.buffer;
        if (buffer == null) throw new BlockStoreException("Store closed");

        lock.lock();
        try {
            lastChainHead = chainHead;
            byte[] headHash = chainHead.getHeader().getHash().getBytes();
            buffer.position(8);
            buffer.put(headHash);
        } finally { lock.unlock(); }
    }

    @Override
    public void close() throws BlockStoreException {
        try {
            buffer.force();
            buffer = null;  // Allow it to be GCd and the underlying file mapping to go away.
            randomAccessFile.close();
            blockCache.clear();
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }
    }

    @Override
    public NetworkParameters getParams() {
        return params;
    }

    protected static final int RECORD_SIZE = 32 /* hash */ + StoredBlock.COMPACT_SERIALIZED_SIZE;

    // File format:
    //   4 header bytes = "SPVB"
    //   4 cursor bytes, which indicate the offset from the first kb where the next block header should be written.
    //   32 bytes for the hash of the chain head
    //
    // For each header (128 bytes)
    //   32 bytes hash of the header
    //   12 bytes of chain work
    //    4 bytes of height
    //   80 bytes of block header data
    protected static final int FILE_PROLOGUE_BYTES = 1024;

    /** Returns the offset from the file start where the latest block should be written (end of prev block). */
    private int getRingCursor(ByteBuffer buffer) {
        int c = buffer.getInt(4);
        checkState(c >= FILE_PROLOGUE_BYTES, "Integer overflow");
        return c;
    }

    private void setRingCursor(ByteBuffer buffer, int newCursor) {
        checkArgument(newCursor >= 0);
        buffer.putInt(4, newCursor);
    }
}
