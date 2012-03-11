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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class DerbyBlockStoreTest {
    /**
     * This path will be deleted recursively!
     */
    private static final String DB_NAME = "target/bitcoinj.unittest.derby";

    @Before
    public void shutUp() {
        // Prevent Derby writing a useless error log file.
        System.getProperties().setProperty("derby.stream.error.file", "");
    }
    
    @After
    public void clear() {
        try {
            deleteRecursively(new File(DB_NAME));
        } catch (IOException e) {
            e.printStackTrace();
            // Does not really matter.
        }
    }

    @Test
    public void testStorage() throws Exception {
        deleteRecursively(new File(DB_NAME));
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

        StoredBlock g1 = store.get(params.genesisBlock.getHash());
        assertEquals(params.genesisBlock, g1.getHeader());
        store.dump();
        store.close();
    }
    
    void deleteRecursively(File f) throws IOException {
        if (f.isDirectory()) {
            for (File c : f.listFiles())
                deleteRecursively(c);
        }
        
        if (f.exists() && !f.delete())
            throw new FileNotFoundException("Failed to delete file: " + f);
    }
}
