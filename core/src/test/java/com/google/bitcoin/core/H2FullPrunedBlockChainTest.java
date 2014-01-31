package com.google.bitcoin.core;

import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.FullPrunedBlockStore;
import com.google.bitcoin.store.H2FullPrunedBlockStore;

/**
 * An H2 implementation of the FullPrunedBlockStoreTest
 */
public class H2FullPrunedBlockChainTest extends AbstractFullPrunedBlockChainTest
{
    @Override
    public FullPrunedBlockStore createStoreFromParamsAndBlockCount(NetworkParameters params, int blockCount) throws BlockStoreException
    {
        return new H2FullPrunedBlockStore(params, "test.h2", blockCount);
    }

    @Override
    public void resetStore(FullPrunedBlockStore store) throws BlockStoreException
    {
        ((H2FullPrunedBlockStore)store).resetStore();
    }
}
