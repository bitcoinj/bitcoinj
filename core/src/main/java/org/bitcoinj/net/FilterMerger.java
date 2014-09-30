package org.bitcoinj.net;

import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.PeerFilterProvider;
import com.google.common.collect.ImmutableList;

import java.util.LinkedList;
import java.util.concurrent.locks.Lock;

// This code is unit tested by the PeerGroup tests.

/**
 * <p>A reusable object that will calculate, given a list of {@link org.bitcoinj.core.PeerFilterProvider}s, a merged
 * {@link org.bitcoinj.core.BloomFilter} and earliest key time for all of them.
 * Used by the {@link org.bitcoinj.core.PeerGroup} class internally.</p>
 *
 * <p>Thread safety: this class tracks the element count of the last filter it calculated and so must be synchronised
 * externally or used from only one thread. It will acquire a lock on each filter in turn before performing the
 * calculation because the providers may be mutated in other threads in parallel, but global consistency is required
 * to produce a merged filter.</p>
 */
public class FilterMerger {
    // We use a constant tweak to avoid giving up privacy when we regenerate our filter with new keys
    private final long bloomFilterTweak = (long) (Math.random() * Long.MAX_VALUE);
    private double bloomFilterFPRate;
    private int lastBloomFilterElementCount;
    private BloomFilter lastFilter;

    public FilterMerger(double bloomFilterFPRate) {
        this.bloomFilterFPRate = bloomFilterFPRate;
    }

    public static class Result {
        public BloomFilter filter;
        public long earliestKeyTimeSecs;
        public boolean changed;
    }

    public Result calculate(ImmutableList<PeerFilterProvider> providers) {
        LinkedList<Lock> takenLocks = new LinkedList<Lock>();
        try {
            // Lock all the providers so they cannot be mutated out from underneath us whilst we're in the process
            // of calculating the Bloom filter. All providers must be in a consistent, unchanging state because the
            // filter is a merged one that's large enough for all providers elements: if a provider were to get more
            // elements in the middle of the calculation, we might assert or calculate the filter wrongly.
            for (PeerFilterProvider provider : providers) {
                Lock lock = provider.getLock();
                lock.lock();
                takenLocks.add(lock);
            }
            Result result = new Result();
            result.earliestKeyTimeSecs = Long.MAX_VALUE;
            int elements = 0;
            boolean requiresUpdateAll = false;
            for (PeerFilterProvider p : providers) {
                result.earliestKeyTimeSecs = Math.min(result.earliestKeyTimeSecs, p.getEarliestKeyCreationTime());
                elements += p.getBloomFilterElementCount();
                requiresUpdateAll = requiresUpdateAll || p.isRequiringUpdateAllBloomFilter();
            }

            if (elements > 0) {
                // We stair-step our element count so that we avoid creating a filter with different parameters
                // as much as possible as that results in a loss of privacy.
                // The constant 100 here is somewhat arbitrary, but makes sense for small to medium wallets -
                // it will likely mean we never need to create a filter with different parameters.
                lastBloomFilterElementCount = elements > lastBloomFilterElementCount ? elements + 100 : lastBloomFilterElementCount;
                BloomFilter.BloomUpdate bloomFlags =
                        requiresUpdateAll ? BloomFilter.BloomUpdate.UPDATE_ALL : BloomFilter.BloomUpdate.UPDATE_P2PUBKEY_ONLY;
                BloomFilter filter = new BloomFilter(lastBloomFilterElementCount, bloomFilterFPRate, bloomFilterTweak, bloomFlags);
                for (PeerFilterProvider p : providers)
                    filter.merge(p.getBloomFilter(lastBloomFilterElementCount, bloomFilterFPRate, bloomFilterTweak));

                result.changed = !filter.equals(lastFilter);
                result.filter = lastFilter = filter;
            }
            // Now adjust the earliest key time backwards by a week to handle the case of clock drift. This can occur
            // both in block header timestamps and if the users clock was out of sync when the key was first created
            // (to within a small amount of tolerance).
            result.earliestKeyTimeSecs -= 86400 * 7;
            return result;
        } finally {
            for (Lock takenLock : takenLocks) {
                takenLock.unlock();
            }
        }
    }

    public void setBloomFilterFPRate(double bloomFilterFPRate) {
        this.bloomFilterFPRate = bloomFilterFPRate;
    }

    public double getBloomFilterFPRate() {
        return bloomFilterFPRate;
    }

    public BloomFilter getLastFilter() {
        return lastFilter;
    }
}
