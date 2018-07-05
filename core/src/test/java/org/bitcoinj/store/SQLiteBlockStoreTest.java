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
