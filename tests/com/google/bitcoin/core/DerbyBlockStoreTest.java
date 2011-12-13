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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class DerbyBlockStoreTest {
    /**
     * 
     */
    private static final String DB_NAME = ".bitcoinj.unittest.derby";

    @Test
    public void testStorage() throws Exception {
        NetworkParameters params = NetworkParameters.unitTests();
        Address to = new ECKey().toAddress(params);
        DerbyBlockStore store = new DerbyBlockStore(params, DB_NAME);
        store.resetStore();
        store.dump();
        // Check the first block in a new store is the genesis block.
        StoredBlock genesis = store.getChainHead();
        assertEquals(params.genesisBlock, genesis.getHeader());

        // Build a new block.
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        store.dump();
        // Check we can get it back out again if we rebuild the store object.
        store = new DerbyBlockStore(params, DB_NAME);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        assertEquals(b1, store.getChainHead());
        store.dump();
    }
}
