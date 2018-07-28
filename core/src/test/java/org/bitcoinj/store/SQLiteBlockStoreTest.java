/*
 * Copyright (c) 2018.
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.bitcoinj.store;

import org.bitcoinj.core.*;
import org.bitcoinj.params.UnitTestParams;
import org.junit.Test;
import org.spongycastle.util.Store;

import java.io.File;

import static org.junit.Assert.assertEquals;

public class SQLiteBlockStoreTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();

    @Test
    public void basics() throws Exception {
        String filePath = File.createTempFile("asd", "t").getAbsolutePath();
        NetworkParameters params = UnitTestParams.get();
        SQLiteBlockStore store = new SQLiteBlockStore(params, filePath);
        StoredBlock genesis = store.getChainHead();
        assertEquals(UNITTEST.getGenesisBlock(), genesis.getHeader());
        assertEquals(0, genesis.getHeight());
        Address to = LegacyAddress.fromBase58(UNITTEST, "mrj2K6txjo2QBcSmuAzHj4nD1oXSEJE1Qo");
        StoredBlock bl = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(bl);
        assertEquals(bl , store.get(bl.getHeader().getHash()));
        store.close();
        store = new SQLiteBlockStore(params, filePath);
        assertEquals(bl , store.get(bl.getHeader().getHash()));
        assertEquals(genesis, store.getChainHead());
    }
}
