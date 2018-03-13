/*
 * Copyright 2013 Google Inc.
 * Copyright 2018 Andreas Schildbach
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

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.params.UnitTestParams;
import org.junit.Before;
import org.junit.Test;

public class SPVBlockStoreTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private File blockStoreFile;

    @Before
    public void setup() throws Exception {
        blockStoreFile = File.createTempFile("spvblockstore", null);
        blockStoreFile.delete();
        blockStoreFile.deleteOnExit();
    }

    @Test
    public void basics() throws Exception {
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile);

        Address to = new ECKey().toAddress(UNITTEST);
        // Check the first block in a new store is the genesis block.
        StoredBlock genesis = store.getChainHead();
        assertEquals(UNITTEST.getGenesisBlock(), genesis.getHeader());
        assertEquals(0, genesis.getHeight());

        // Build a new block.
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        store.close();

        // Check we can get it back out again if we rebuild the store object.
        store = new SPVBlockStore(UNITTEST, blockStoreFile);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        StoredBlock chainHead = store.getChainHead();
        assertEquals(b1, chainHead);
    }

    @Test(expected = BlockStoreException.class)
    public void twoStores_onSameFile() throws Exception {
        new SPVBlockStore(UNITTEST, blockStoreFile);
        new SPVBlockStore(UNITTEST, blockStoreFile);
    }

    @Test
    public void twoStores_butSequentially() throws Exception {
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile);
        store.close();
        store = new SPVBlockStore(UNITTEST, blockStoreFile);
    }
}
