package org.bitcoinj.core.strategies;

import org.bitcoinj.core.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.FullPrunedBlockStore;
import org.bitcoinj.store.MemoryFullPrunedBlockStore;
import org.bitcoinj.utils.BlockFileLoader;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class DenseThenSparseStrategyTest {

    private DenseThenSparseStrategy denseThenSparseStrategy;
    private FullPrunedBlockChain blockChain;
    private BlockFileLoader loader;

    @Before
    public void setUp() throws Exception {
        NetworkParameters params = MainNetParams.get();
        Context context = new Context(params);
        URL resource = this.getClass().getResource("/org/bitcoinj/core/first-100k-blocks.dat");
        File blockFile = new File(resource.toURI());
        loader = new BlockFileLoader(params, Arrays.asList(blockFile));
        FullPrunedBlockStore blockStore = new MemoryFullPrunedBlockStore(params, 100);
        blockChain =  new FullPrunedBlockChain(context, blockStore);

        denseThenSparseStrategy = new DenseThenSparseStrategy();
        denseThenSparseStrategy.setNetworkParameters(params);
    }

    @Test
    public void testCreateBlockLocatorFullHeight() throws Exception {
        for (Block block : loader) {
            blockChain.add(block);
        }
        List<Sha256Hash> blockLocator = denseThenSparseStrategy.createBlockLocator(blockChain);
        assertEquals(11,blockLocator.size());
        assertEquals("00000000fa6066998c588e2c3933e036ed64907a65ec593fd8ab37316fed0e8f",blockLocator.get(5).toString());
        assertEquals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",blockLocator.get(10).toString());
    }

    @Test
    public void testCreateBlockLocatorShortHeight() throws Exception {
        int i = 0;
        for (Block block : loader) {
            blockChain.add(block);
            i++;
            if (i > 10) break;
        }
        List<Sha256Hash> blockLocator = denseThenSparseStrategy.createBlockLocator(blockChain);
        assertEquals(7,blockLocator.size());
        assertEquals("000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",blockLocator.get(5).toString());
    }
}