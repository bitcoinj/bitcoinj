package com.google.bitcoin.core;

import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.FullPrunedBlockStore;
import com.google.bitcoin.store.PostgresFullPrunedBlockStore;
import org.junit.Ignore;

/**
 * A Postgres implementation of the {@link AbstractFullPrunedBlockChainTest}
 */
@Ignore("enable the postgres driver dependency in the maven POM")
public class PostgresFullPrunedBlockChainTest extends AbstractFullPrunedBlockChainTest
{
    // Replace these with your postgres location/credentials and remove @Ignore to test
    private static final String DB_HOSTNAME = "localhost";
    private static final String DB_NAME = "bitcoinj_test";
    private static final String DB_USERNAME = "bitcoinj";
    private static final String DB_PASSWORD = "password";

    @Override
    public FullPrunedBlockStore createStore(NetworkParameters params, int blockCount)
            throws BlockStoreException {
        return new PostgresFullPrunedBlockStore(params, blockCount, DB_HOSTNAME, DB_NAME, DB_USERNAME, DB_PASSWORD);
    }

    @Override
    public void resetStore(FullPrunedBlockStore store) throws BlockStoreException {
        ((PostgresFullPrunedBlockStore)store).resetStore();
    }
}
