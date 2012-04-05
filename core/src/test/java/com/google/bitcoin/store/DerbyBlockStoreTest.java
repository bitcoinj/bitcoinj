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
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;

import static org.junit.Assert.assertEquals;

public class DerbyBlockStoreTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void shutUp() {
        // Prevent Derby writing a useless error log file.
        System.getProperties().setProperty("derby.stream.error.file", "");
    }

    @Test
    public void testStorage() throws Exception {
        File file = new File(folder.getRoot(), "derby");
        String path = file.getAbsolutePath();
        NetworkParameters params = NetworkParameters.unitTests();
        Address to = new ECKey().toAddress(params);
        DerbyBlockStore store = new DerbyBlockStore(params, path);
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
        store = new DerbyBlockStore(params, path);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        assertEquals(b1, store.getChainHead());

        StoredBlock g1 = store.get(params.genesisBlock.getHash());
        assertEquals(params.genesisBlock, g1.getHeader());
        store.dump();
        store.close();
    }
}
