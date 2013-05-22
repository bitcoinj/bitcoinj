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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@SuppressWarnings("deprecation")
public class BoundedOverheadBlockStoreTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testStorage() throws Exception {
        File temp = folder.newFile("bitcoinj-test");
        System.out.println(temp.getAbsolutePath());

        NetworkParameters params = UnitTestParams.get();
        Address to = new ECKey().toAddress(params);
        BoundedOverheadBlockStore store = new BoundedOverheadBlockStore(params, temp);
        // Check the first block in a new store is the genesis block.
        StoredBlock genesis = store.getChainHead();
        assertEquals(params.getGenesisBlock(), genesis.getHeader());

        // Build a new block.
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        store.close();
        
        // Check we can get it back out again if we rebuild the store object.
        store = new BoundedOverheadBlockStore(params, temp);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        assertEquals(b1, store.getChainHead());
    }
    
    @Test
    public void testLocking() throws Exception {
        File temp = folder.newFile("bitcoinj-test");
        System.out.println(temp.getAbsolutePath());

        NetworkParameters params = UnitTestParams.get();
        BoundedOverheadBlockStore store = new BoundedOverheadBlockStore(params, temp);
        try {
            BoundedOverheadBlockStore store1 = new BoundedOverheadBlockStore(params, temp);
            fail();
        } catch (BlockStoreException e) {
            // Expected
        }
    }
}
