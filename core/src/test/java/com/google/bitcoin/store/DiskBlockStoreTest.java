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

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.StoredBlock;

import com.google.bitcoin.params.UnitTestParams;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class DiskBlockStoreTest {
    private NetworkParameters params;
    private Address to;
    private File temp;
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void setUp() throws IOException {
        temp = folder.newFile("bitcoinj-test");
        System.out.println(temp.getAbsolutePath());

        params = UnitTestParams.get();
        to = new ECKey().toAddress(params);
    }
    
    @Test
    public void testStorage() throws Exception {
        DiskBlockStore store = new DiskBlockStore(params, temp);
        // Check the first block in a new store is the genesis block.
        StoredBlock genesis = store.getChainHead();
        assertEquals(params.getGenesisBlock(), genesis.getHeader());

        // Build a new block.
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        store.close();
        // Check we can get it back out again if we rebuild the store object.
        store = new DiskBlockStore(params, temp);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        assertEquals(b1, store.getChainHead());
        store.close();
    }

    @Test
    public void testStorage_existing() throws Exception {
        DiskBlockStore store = new DiskBlockStore(params, temp);
        // Check the first block in a new store is the genesis block.
        
        StoredBlock genesis = store.getChainHead();
        
        // Test locking
        try {
            store = new DiskBlockStore(params, temp);
            fail();
        } catch (BlockStoreException ex) {
            // expected
        }
        store.close();

        // Reopen.
        store = new DiskBlockStore(params, temp);
        
        // Build a new block.
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        store.close();
        
        // Check we can get it back out again if we reopen the store.
        store = new DiskBlockStore(params, temp);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        assertEquals(b1, store.getChainHead());
        store.close();
    }
}
