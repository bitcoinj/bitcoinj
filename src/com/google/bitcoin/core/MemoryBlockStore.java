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

package com.google.bitcoin.core;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Keeps {@link StoredBlock}s in memory. Used primarily for unit testing.
 */
public class MemoryBlockStore implements BlockStore {
    // We use a ByteBuffer to hold hashes here because the Java array equals()/hashcode() methods do not operate on
    // the contents of the array but just inherit the default Object behavior. ByteBuffer provides the functionality
    // needed to act as a key in a map.
    //
    // The StoredBlocks are also stored as serialized objects to ensure we don't have assumptions that would make
    // things harder for disk based implementations.
    private Map<ByteBuffer, byte[]> blockMap;
    private StoredBlock chainHead;

    public MemoryBlockStore(NetworkParameters params) {
        blockMap = new HashMap<ByteBuffer, byte[]>();
        // Insert the genesis block.
        try {
            Block genesisHeader = params.genesisBlock.cloneAsHeader();
            StoredBlock storedGenesis = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
            put(storedGenesis);
            setChainHead(storedGenesis);
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public synchronized void put(StoredBlock block) throws BlockStoreException {
        byte[] hash = block.getHeader().getHash();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(block);
            oos.close();
            blockMap.put(ByteBuffer.wrap(hash), bos.toByteArray());
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }
    }

    public synchronized StoredBlock get(byte[] hash) throws BlockStoreException {
        try {
            byte[] serializedBlock = blockMap.get(ByteBuffer.wrap(hash));
            if (serializedBlock == null)
                return null;
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedBlock));
            StoredBlock storedBlock = (StoredBlock) ois.readObject();
            return storedBlock;
        } catch (IOException e) {
            throw new BlockStoreException(e);
        } catch (ClassNotFoundException e) {
            throw new BlockStoreException(e);
        }
    }

    public StoredBlock getChainHead() {
        return chainHead;
    }

    public void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        this.chainHead = chainHead;
    }
}
