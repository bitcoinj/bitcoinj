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

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Keeps {@link StoredBlock}s in memory. Used primarily for unit testing.
 */
class MemoryBlockStore implements BlockStore {
    // We use a ByteBuffer to hold hashes here because the Java array equals()/hashcode() methods do not operate on
    // the contents of the array but just inherit the default Object behavior. ByteBuffer provides the functionality
    // needed to act as a key in a map.
    private Map<ByteBuffer, StoredBlock> blockMap;

    MemoryBlockStore() {
        blockMap = new HashMap<ByteBuffer, StoredBlock>();
    }

    public synchronized void put(StoredBlock block) throws BlockStoreException {
        byte[] hash = block.header.getHash();
        blockMap.put(ByteBuffer.wrap(hash), block);
    }

    public synchronized StoredBlock get(byte[] hash) throws BlockStoreException {
        return blockMap.get(ByteBuffer.wrap(hash));
    }
}
