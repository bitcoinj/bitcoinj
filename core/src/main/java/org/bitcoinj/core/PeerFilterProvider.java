/*
 * Copyright 2013 Google Inc.
 * Copyright 2019 Andreas Schildbach
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

package org.bitcoinj.core;

import java.time.Instant;

/**
 * An interface which provides the information required to properly filter data downloaded from Peers. Note that an
 * implementer is responsible for calling
 * {@link PeerGroup#recalculateFastCatchupAndFilter(PeerGroup.FilterRecalculateMode)} whenever a change occurs which
 * effects the data provided via this interface.
 */
public interface PeerFilterProvider {
    /**
     * Returns the earliest time for which full/bloom-filtered blocks must be downloaded.
     * Blocks with timestamps before this time will only have headers downloaded. {@link Instant#EPOCH} requires that all
     * blocks be downloaded, and thus this should default to {@link Instant#MAX}.
     */
    Instant earliestKeyCreationTime();

    /** @deprecated use {@link #earliestKeyCreationTime()} */
    @Deprecated
    default long getEarliestKeyCreationTime() {
        Instant earliestKeyCreationTime = earliestKeyCreationTime();
        return earliestKeyCreationTime.equals(Instant.MAX) ? Long.MAX_VALUE : earliestKeyCreationTime.getEpochSecond();
    }

    /**
     * Called on all registered filter providers before {@link #getBloomFilterElementCount()} and
     * {@link #getBloomFilter(int, double, int)} are called. Once called, the provider should ensure that the items
     * it will want to insert into the filter don't change. The reason is that all providers will have their element
     * counts queried, and then a filter big enough for all of them will be specified. So the provider must use
     * consistent state. There is guaranteed to be a matching call to {@link #endBloomFilterCalculation()} that can
     * be used to e.g. unlock a lock.
     */
    void beginBloomFilterCalculation();

    /**
     * Gets the number of elements that will be added to a bloom filter returned by
     * {@link PeerFilterProvider#getBloomFilter(int, double, int)}
     */
    int getBloomFilterElementCount();

    /**
     * Gets a bloom filter that contains all the necessary elements for the listener to receive relevant transactions.
     * Default value should be an empty bloom filter with the given size, falsePositiveRate, and nTweak.
     */
    BloomFilter getBloomFilter(int size, double falsePositiveRate, int nTweak);

    /**
     * See {@link #beginBloomFilterCalculation()}.
     */
    void endBloomFilterCalculation();
}
