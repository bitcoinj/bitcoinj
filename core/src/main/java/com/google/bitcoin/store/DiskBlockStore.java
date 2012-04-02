/**
 * Copyright 2011 Google Inc.
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

import com.google.bitcoin.core.*;
import com.google.bitcoin.utils.NamedSemaphores;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.checkState;

/**
 * Stores the block chain to disk but still holds it in memory. This is intended for desktop apps and tests.
 * Constrained environments like mobile phones probably won't want to or be able to store all the block headers in RAM.
 */
public class DiskBlockStore implements BlockStore {
    private static final Logger log = LoggerFactory.getLogger(DiskBlockStore.class);

    private RandomAccessFile file;
    private Map<Sha256Hash, StoredBlock> blockMap;
    private Sha256Hash chainHead;
    private NetworkParameters params;
    private FileLock lock;
    private String fileName;

    private static NamedSemaphores semaphores = new NamedSemaphores();

    public DiskBlockStore(NetworkParameters params, File theFile) throws BlockStoreException {
        this.params = params;
        try {
            this.fileName = theFile.getCanonicalPath();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        blockMap = new HashMap<Sha256Hash, StoredBlock>();
        try {
            file = new RandomAccessFile(theFile, "rwd");
            // Lock the file from other processes.
            lock();
            // The file position is at BOF
            load(theFile);
            // The file position is at EOF
        } catch (IOException e) {
            log.error("failed to load block store from file", e);
            createNewStore(params);
            // The file position is at EOF
        }
    }
    
    public void close() throws BlockStoreException {
        ensureOpen();
        try {
            file.close();
        } catch (IOException e) {
            throw new BlockStoreException(e);
        } finally {
            semaphores.release(this.fileName);
            file = null;
        }
    }

    private void createNewStore(NetworkParameters params) throws BlockStoreException {
        // Create a new block store if the file wasn't found or anything went wrong whilst reading.
        blockMap.clear();
        try {
            file.write(1);  // Version.
        } catch (IOException e1) {
            // We could not load a block store nor could we create a new one!
            throw new BlockStoreException(e1);
        }
        try {
            // Set up the genesis block. When we start out fresh, it is by definition the top of the chain.
            Block genesis = params.genesisBlock.cloneAsHeader();
            StoredBlock storedGenesis = new StoredBlock(genesis, genesis.getWork(), 0);
            this.chainHead = storedGenesis.getHeader().getHash();
            file.write(this.chainHead.getBytes());
            put(storedGenesis);
        } catch (VerificationException e1) {
            throw new RuntimeException(e1);  // Cannot happen.
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }
    }

    private void load(File theFile) throws IOException, BlockStoreException {
        log.info("Reading block store from {}", theFile);
        try {
            // Read a version byte.
            int version = file.read();
            if (version == -1) {
                // No such file or the file was empty.
                throw new FileNotFoundException(theFile.getName() + " is empty");
            }
            if (version != 1) {
                throw new BlockStoreException("Bad version number: " + version);
            }
            // Chain head pointer is the first thing in the file.
            byte[] chainHeadHash = new byte[32];
            if (file.read(chainHeadHash) < chainHeadHash.length)
                throw new BlockStoreException("Truncated block store: cannot read chain head hash");
            this.chainHead = new Sha256Hash(chainHeadHash);
            log.info("Read chain head from disk: {}", this.chainHead);
            long now = System.currentTimeMillis();
            // Rest of file is raw block headers.
            byte[] headerBytes = new byte[Block.HEADER_SIZE];
            try {
                while (true) {
                    // Read a block from disk.
                    int read = file.read(headerBytes);
                    if (read == -1) {
                        // End of file.
                        break;
                    }
                    if (read < headerBytes.length) {
                        throw new BlockStoreException("Truncated block store: partial block read");
                    }
                    // Parse it.
                    Block b = new Block(params, headerBytes);
                    // Look up the previous block it connects to.
                    StoredBlock prev = get(b.getPrevBlockHash());
                    StoredBlock s;
                    if (prev == null) {
                        // First block in the stored chain has to be treated specially.
                        if (b.equals(params.genesisBlock)) {
                            s = new StoredBlock(params.genesisBlock.cloneAsHeader(), params.genesisBlock.getWork(), 0);
                        } else {
                            throw new BlockStoreException("Could not connect " + b.getHash().toString() + " to "
                                    + b.getPrevBlockHash().toString());
                        }
                    } else {
                        // Don't try to verify the genesis block to avoid upsetting the unit tests.
                        b.verifyHeader();
                        // Calculate its height and total chain work.
                        s = prev.build(b);
                    }
                    // Save in memory.
                    blockMap.put(b.getHash(), s);
                }
            } catch (ProtocolException e) {
                // Corrupted file.
                throw new BlockStoreException(e);
            } catch (VerificationException e) {
                // Should not be able to happen unless the file contains bad blocks.
                throw new BlockStoreException(e);
            }
            long elapsed = System.currentTimeMillis() - now;
            log.info("Block chain read complete in {}ms", elapsed);
        } finally {
        }
    }

    private void ensureOpen() throws BlockStoreException {
        if (file == null) {
            throw new BlockStoreException("BlockStore was closed");
        }
    }

    public synchronized void put(StoredBlock block) throws BlockStoreException {
        ensureOpen();
        try {
            Sha256Hash hash = block.getHeader().getHash();
            checkState(blockMap.get(hash) == null, "Attempt to insert duplicate");
            // Append to the end of the file. The other fields in StoredBlock will be recalculated when it's reloaded.
            byte[] bytes = block.getHeader().bitcoinSerialize();
            file.write(bytes);
            blockMap.put(hash, block);
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }
    }

    public synchronized StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        ensureOpen();
        return blockMap.get(hash);
    }

    public synchronized StoredBlock getChainHead() throws BlockStoreException {
        ensureOpen();
        return blockMap.get(chainHead);
    }

    public synchronized void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        ensureOpen();
        try {
            this.chainHead = chainHead.getHeader().getHash();
            // Write out new hash to the first 32 bytes of the file past one (first byte is version number).
            file.getChannel().write(ByteBuffer.wrap(this.chainHead.getBytes()), 1);
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }
    }

    private void lock() throws IOException, BlockStoreException {
        if (!semaphores.tryAcquire(fileName)) {
            throw new BlockStoreException("File in use");
        }
        try {
            lock = file.getChannel().tryLock();
        } catch (OverlappingFileLockException e) {
            semaphores.release(fileName);
            lock = null;
        }
        if (lock == null) {
            try {
                this.file.close();
            } finally {
                this.file = null;
            }
            throw new BlockStoreException("Could not lock file");
        }
    }
}
