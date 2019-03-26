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

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.utils.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.*;

/**
 * An SPVBlockStore holds a limited number of block headers in a memory mapped ring buffer. With such a store, you
 * may not be able to process very deep re-orgs and could be disconnected from the chain (requiring a replay),
 * but as they are virtually unheard of this is not a significant risk.
 */
public class SPVBlockStore implements BlockStore {
    private static final Logger log = LoggerFactory.getLogger(SPVBlockStore.class);

    /** The default number of headers that will be stored in the ring buffer. */
    public static final int DEFAULT_CAPACITY = 5000;
    public static final String HEADER_MAGIC = "SPV2";

    protected volatile MappedByteBuffer buffer;
    protected final NetworkParameters params;

    protected Map<Sha256Hash, ChainMap> chainMaps = new HashMap<>();

    protected ReentrantLock lock = Threading.lock("SPVBlockStore");

    // Used to stop other applications/processes from opening the store.
    protected FileLock fileLock = null;

    protected RandomAccessFile randomAccessFile = null;

    protected StoredBlock lastChainHead = null;

    private int height;

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
                if(new String(header).equals("SPVB")){
                    byte[] hash = new byte[32];
                    buffer.position(4);
                    int cursor = buffer.getInt();
                    buffer.get(hash);
                    buffer.position(cursor-96);
                    int serHeight = StoredBlock.deserializeCompact(params, buffer).getHeight();
                    System.out.println(serHeight);
                    buffer.put(HEADER_MAGIC.getBytes(StandardCharsets.US_ASCII));
                    buffer.putInt(cursor);
                    buffer.putInt(serHeight);
                    buffer.put(hash);
                }else if (!new String(header, StandardCharsets.US_ASCII).equals(HEADER_MAGIC))
                    throw new BlockStoreException("Header bytes do not equal " + HEADER_MAGIC);
                buffer.position(8);
                height = buffer.getInt();
                buffer.position(FILE_PROLOGUE_BYTES);
                int last;
                for (int i = 0; i < height; i++) {
                    byte[] hash = new byte[32];
                    last = buffer.position();
                    buffer.get(hash);
                    buffer.position(last + 128);
                    chainMaps.put(Sha256Hash.wrap(hash), new ChainMap(last, (last + 128)));
                }
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

    /**
     * Returns the size in bytes of the file that is used to store the chain with the current parameters.
     */
    public static final int getFileSize(int capacity) {
        return RECORD_SIZE * capacity + FILE_PROLOGUE_BYTES /* extra kilobyte for stuff */;
    }

    private void initNewStore(NetworkParameters params) throws Exception {
        byte[] header;
        header = HEADER_MAGIC.getBytes("US-ASCII");
        buffer.put(header);
        buffer.position(8);
        buffer.putInt(0);
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

    @Override
    public void put(StoredBlock block) throws BlockStoreException {
        final MappedByteBuffer buffer = this.buffer;
        if (buffer == null) throw new BlockStoreException("Store closed");
        lock.lock();
        try {
            int cursor = getRingCursor(buffer);
            buffer.position(cursor);
            Sha256Hash hash = block.getHeader().getHash();
            chainMaps.put(hash, new ChainMap(cursor, cursor + 128));
            buffer.put(hash.getBytes());
            block.serializeCompact(buffer);
            height++;
            setRingCursor(buffer, buffer.position());
        } finally {
            lock.unlock();
        }
    }

    @Override
    @Nullable
    public StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        lock.lock();
        StoredBlock block;
        try {
            final MappedByteBuffer buffer = this.buffer;
            if (buffer == null) throw new BlockStoreException("Store closed");
            ChainMap map = chainMaps.get(hash);
            if (map == null) return null;
            byte[] hashdat = new byte[32];
            buffer.position(map.start);
            buffer.get(hashdat);
            block = StoredBlock.deserializeCompact(params, buffer);
        } finally {
            lock.unlock();
        }
        return block;
    }

    @Override
    public StoredBlock getChainHead() throws BlockStoreException {
        final MappedByteBuffer buffer = this.buffer;
        if (buffer == null) throw new BlockStoreException("Store closed");
        lock.lock();
        try {
            if (lastChainHead == null) {
                byte[] headHash = new byte[32];
                buffer.position(12);
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
            buffer.position(12);
            buffer.put(headHash);
        } finally { lock.unlock(); }
    }

    @Override
    public void close() throws BlockStoreException {
        try {
            buffer.position(8);
            buffer.putInt(height);
            buffer.force();
            buffer = null;  // Allow it to be GCd and the underlying file mapping to go away.
            fileLock.release();
            randomAccessFile.close();
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
    //   4 header bytes = "SPV2" legacy "SPVB"
    //   4 cursor bytes, which indicate the offset from the first kb where the next block header should be written.
    //   4 height bytes
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

    private class ChainMap {
        private int start;

        private int end;

        ChainMap(int start, int end) {

            this.start = start;
            this.end = end;
        }

        public int getStart() {
            return start;
        }

        public int getEnd() {
            return end;
        }
    }
}
