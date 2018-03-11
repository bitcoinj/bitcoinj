/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.net;

import com.google.common.collect.Lists;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.PeerFilterProvider;
import com.google.common.collect.ImmutableList;
import org.bitcoinj.core.PeerGroup;

import java.util.LinkedList;

// This code is unit tested by the PeerGroup tests.

/**
 * <p>A reusable object that will calculate, given a list of {@link PeerFilterProvider}s, a merged
 * {@link BloomFilter} and earliest key time for all of them.
 * Used by the {@link PeerGroup} class internally.</p>
 *
 * <p>Thread safety: threading here can be complicated. Each filter provider is given a begin event, which may acquire
 * a lock (and is guaranteed to receive an end event). This class is mostly thread unsafe and is meant to be used from a
 * single thread only, PeerGroup ensures this by only accessing it from the dedicated PeerGroup thread. PeerGroup does
 * not hold any locks whilst this object is used, relying on the single thread to prevent multiple filters being
 * calculated in parallel, thus a filter provider can do things like make blocking calls into PeerGroup from a separate
 * thread. However the bloomFilterFPRate property IS thread safe, for convenience.</p>
 */
public class FilterMerger {
    // We use a constant tweak to avoid giving up privacy when we regenerate our filter with new keys
    private final long bloomFilterTweak = (long) (Math.random() * Long.MAX_VALUE);

    private volatile double vBloomFilterFPRate;
    private int lastBloomFilterElementCount;
    private BloomFilter lastFilter;

    public FilterMerger(double bloomFilterFPRate) {
        this.vBloomFilterFPRate = bloomFilterFPRate;
    }

    public static class Result {
        public BloomFilter filter;
        public long earliestKeyTimeSecs;
        public boolean changed;
    }

    public Result calculate(ImmutableList<PeerFilterProvider> providers) {
        LinkedList<PeerFilterProvider> begunProviders = Lists.newLinkedList();
        try {
            // All providers must be in a consistent, unchanging state because the filter is a merged one that's
            // large enough for all providers elements: if a provider were to get more elements in the middle of the
            // calculation, we might assert or calculate the filter wrongly. Most providers use a lock here but
            // snapshotting required state is also a legitimate strategy.
            for (PeerFilterProvider provider : providers) {
                provider.beginBloomFilterCalculation();
                begunProviders.add(provider);
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
                double fpRate = vBloomFilterFPRate;
                BloomFilter filter = new BloomFilter(lastBloomFilterElementCount, fpRate, bloomFilterTweak, bloomFlags);
                for (PeerFilterProvider p : providers)
                    filter.merge(p.getBloomFilter(lastBloomFilterElementCount, fpRate, bloomFilterTweak));

                result.changed = !filter.equals(lastFilter);
                result.filter = lastFilter = filter;
            }
            // Now adjust the earliest key time backwards by a week to handle the case of clock drift. This can occur
            // both in block header timestamps and if the users clock was out of sync when the key was first created
            // (to within a small amount of tolerance).
            result.earliestKeyTimeSecs -= 86400 * 7;
            return result;
        } finally {
            for (PeerFilterProvider provider : begunProviders) {
                provider.endBloomFilterCalculation();
            }
        }
    }

    public void setBloomFilterFPRate(double bloomFilterFPRate) {
        this.vBloomFilterFPRate = bloomFilterFPRate;
    }

    public double getBloomFilterFPRate() {
        return vBloomFilterFPRate;
    }

    public BloomFilter getLastFilter() {
        return lastFilter;
    }
}
