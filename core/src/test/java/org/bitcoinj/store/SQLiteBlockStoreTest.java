package org.bitcoinj.store;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.params.UnitTestParams;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertEquals;

public class SQLiteBlockStoreTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();

    @Test
    public void basics() throws Exception {
        NetworkParameters params = UnitTestParams.get();
        SQLiteBlockStore store = new SQLiteBlockStore(params, File.createTempFile("asd", "t").getAbsolutePath());
        StoredBlock genesis = store.getChainHead();
        assertEquals(UNITTEST.getGenesisBlock(), genesis.getHeader());
        assertEquals(0, genesis.getHeight());
    }
}
