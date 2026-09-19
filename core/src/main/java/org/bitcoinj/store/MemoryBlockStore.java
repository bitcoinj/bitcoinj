/*
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

package org.bitcoinj.store;

import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.base.Network;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.VerificationException;
import org.jspecify.annotations.Nullable;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keeps {@link StoredBlock}s in memory. Used primarily for unit testing.
 */
public class MemoryBlockStore implements BlockStore {
    private @Nullable LinkedHashMap<Sha256Hash, StoredBlock> blockMap = new LinkedHashMap<Sha256Hash, StoredBlock>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Sha256Hash, StoredBlock> eldest) {
            return this.size() > 5000;
        }
    };
    private StoredBlock chainHead;

    /**
     * Construct a {@code MemoryBlockStore} for a network.
     * @param network Network this store will use.
     */
    public MemoryBlockStore(Network network) {
        try {
            Block genesisHeader = Block.getGenesis(network);
            StoredBlock storedGenesis = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
            put(storedGenesis);
            chainHead = storedGenesis;
        } catch (BlockStoreException | VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Construct a {@code MemoryBlockStore} from a genesis block. For use in tests only.
     * Use this class with {@link org.bitcoinj.params.UnitTestParams#getGenesisBlock()} for testing with
     * reduced proof-of-work.
     * @param genesisBlock Network this store will use.
     */
    @VisibleForTesting
    public MemoryBlockStore(Block genesisBlock) {
        try {
            Block genesisHeader = genesisBlock.asHeader();
            StoredBlock storedGenesis = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
            put(storedGenesis);
            chainHead = storedGenesis;
        } catch (BlockStoreException | VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    public synchronized final void put(StoredBlock block) throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        Sha256Hash hash = block.getHeader().getHash();
        blockMap.put(hash, block);
    }

    @Override
    @Nullable
    public synchronized StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        return blockMap.get(hash);
    }

    @Override
    public StoredBlock getChainHead() throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        return chainHead;
    }

    @Override
    public final void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        if (blockMap == null) throw new BlockStoreException("MemoryBlockStore is closed");
        this.chainHead = chainHead;
    }
    
    @Override
    public void close() {
        blockMap = null;
    }
}
