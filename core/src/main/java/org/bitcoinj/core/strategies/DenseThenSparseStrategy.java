package org.bitcoinj.core.strategies;

import com.google.common.base.Stopwatch;
import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Constructs a block locator using the strategy described on the <a href="https://en.bitcoin.it/wiki/Protocol_specification#getblocks">bitcoin wiki</a>
 */
public class DenseThenSparseStrategy implements BlockLocatorStrategy {

    private static final Logger log = LoggerFactory.getLogger(DenseThenSparseStrategy.class);
    private NetworkParameters params;

    @Override
    public List<Sha256Hash> createBlockLocator(AbstractBlockChain chain) {

        //make a list of the block heights that we want to send
        int height = chain.getBestChainHeight();
        Set<Integer> indexes = new HashSet<Integer>();
        int step = 1;
        int minIndex = 0;
        int maxDepth = getMaxDepth();
        // stop once we reach a maximum depth
        for (Integer index = height;index > 0 && (height - index) < maxDepth; index = index - step) {
            if (indexes.size() >= 4) {
                step = step * 2;
            }
            indexes.add(index);
            minIndex = index;
        }

        //make a list of the hashes of the blocks we just selected
        List<Sha256Hash> blockLocator = null;
        try {
            BlockStore store = checkNotNull(chain).getBlockStore();
            blockLocator = new ArrayList<Sha256Hash>(indexes.size());
            StoredBlock cursor = store.getChainHead();
            //add hashes, stop when we reach the lowest index selected above
            Stopwatch stopwatch = Stopwatch.createStarted();
            for (int i = height; cursor != null && i >= minIndex; i--) {
                if (indexes.contains(i)) {
                    Sha256Hash hash = cursor.getHeader().getHash();
                    log.debug("adding block {} height, {} hash", i, hash);
                    blockLocator.add(hash);
                }
                cursor = cursor.getPrev(store);
            }

            //no harm in adding the Genesis block
            blockLocator.add(checkNotNull(params).getGenesisBlock().getHash());

            log.info("Built list of {} locator hashes in {} ms",blockLocator.size(),stopwatch.stop().elapsed(TimeUnit.MILLISECONDS));
        } catch (BlockStoreException e) {
            log.error("Failed to walk the block chain whilst constructing a locator");
        }
        return blockLocator;
    }

    @Override
    public void setNetworkParameters(NetworkParameters params) {
        this.params = checkNotNull(params);
    }

    protected int getMaxDepth() {
        return 100;
    }
}
