package org.bitcoinj.core.strategies;

import org.bitcoinj.core.*;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * This class does not do the exponential thinning as suggested here:
 *
 *   https://en.bitcoin.it/wiki/Protocol_specification#getblocks
 *
 * This is because it requires scanning all the block chain headers, which is very slow. Instead we add the top
 * 100 block headers. If there is a re-org deeper than that, we'll end up downloading the entire chain. We
 * must always put the genesis block as the first entry.
 */
public class LinearBlockLocatorStrategy implements BlockLocatorStrategy {
    private static final Logger log = LoggerFactory.getLogger(LinearBlockLocatorStrategy.class);
    private NetworkParameters params;

    public List<Sha256Hash> createBlockLocator(AbstractBlockChain chain) {
        List<Sha256Hash> blockLocator = null;
        try {
            BlockStore store = checkNotNull(chain).getBlockStore();
            blockLocator = new ArrayList<Sha256Hash>(51);
            StoredBlock cursor = store.getChainHead();
            for (int i = 100; cursor != null && i > 0; i--) {
                blockLocator.add(cursor.getHeader().getHash());
                cursor = cursor.getPrev(store);
            }
            // Only add the locator if we didn't already do so. If the chain is < 50 blocks we already reached it.
            if (cursor != null)
                blockLocator.add(checkNotNull(params).getGenesisBlock().getHash());
        } catch (BlockStoreException e) {
            log.error("Failed to walk the block chain whilst constructing a locator");
        }
        return blockLocator;
    }

    @Override
    public void setNetworkParameters(NetworkParameters params) {
        this.params = checkNotNull(params, "NetworkParameters cannot be null");
    }
}