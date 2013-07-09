/*
 * Copyright 2013 Google Inc.
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

package com.google.bitcoin.core;

/**
 * An interface which provides the information required to properly filter data downloaded from Peers.
 * Note that an implementer is responsible for calling {@link PeerGroup#recalculateFastCatchupAndFilter()} whenever a
 * change occurs which effects the data provided via this interface.
 */
public interface PeerFilterProvider {
    /**
     * Returns the earliest timestamp (seconds since epoch) for which full/bloom-filtered blocks must be downloaded.
     * Blocks with timestamps before this time will only have headers downloaded. 0 requires that all blocks be
     * downloaded, and thus this should default to {@link System#currentTimeMillis()}/1000.
     */
    public long getEarliestKeyCreationTime();

    /**
     * Gets the number of elements that will be added to a bloom filter returned by
     * {@link PeerFilterProvider#getBloomFilter(int, double, long)}
     */
    public int getBloomFilterElementCount();

    /**
     * Gets a bloom filter that contains all the necessary elements for the listener to receive relevant transactions.
     * Default value should be an empty bloom filter with the given size, falsePositiveRate, and nTweak.
     */
    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak);
}
