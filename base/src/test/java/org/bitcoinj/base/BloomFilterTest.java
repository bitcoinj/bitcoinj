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

package org.bitcoinj.base;

import org.bitcoinj.base.internal.ByteUtils;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BloomFilterTest {
    @Test
    public void bloomSizingIsBounded() {
        assertEquals(1, new BloomFilter(1, 0.999999, 0).getDataCopy().length);
        assertEquals(BloomFilter.MAX_FILTER_SIZE, new BloomFilter(500_000, 1e-12, 0).getDataCopy().length);
        BloomFilter maxHashFuncs = new BloomFilter(new byte[(int) BloomFilter.MAX_FILTER_SIZE],
                BloomFilter.MAX_HASH_FUNCS, 0, (byte) BloomFilter.BloomUpdate.UPDATE_ALL.ordinal());
        assertEquals(BloomFilter.MAX_HASH_FUNCS, maxHashFuncs.getHashFuncs());
    }

    @Test
    public void murmurHashMatchesKnownBitIndexes() {
        byte[] data = new byte[3];
        int tweak = 0;
        byte[] first = ByteUtils.parseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8");
        byte[] second = ByteUtils.parseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee");
        byte[] third = ByteUtils.parseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5");

        int[] firstExpected = {0, 23, 0, 19, 20};
        int[] secondExpected = {17, 14, 6, 10, 14};
        int[] thirdExpected = {11, 5, 20, 9, 16};

        for (int i = 0; i < 5; i++) {
            assertEquals(firstExpected[i], MurmurHash3.murmurHash3(data, tweak, i, first));
            assertEquals(secondExpected[i], MurmurHash3.murmurHash3(data, tweak, i, second));
            assertEquals(thirdExpected[i], MurmurHash3.murmurHash3(data, tweak, i, third));
        }
    }

    @Test
    public void insertAndContainsMatchKnownVector() {
        BloomFilter filter = new BloomFilter(3, 0.01, 0, BloomFilter.BloomUpdate.UPDATE_ALL);

        byte[] first = ByteUtils.parseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8");
        byte[] firstBitFlip = ByteUtils.parseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8");
        byte[] second = ByteUtils.parseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee");
        byte[] third = ByteUtils.parseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5");

        filter.insert(first);
        assertTrue(filter.contains(first));
        assertFalse(filter.contains(firstBitFlip));

        filter.insert(second);
        filter.insert(third);

        assertTrue(filter.contains(second));
        assertTrue(filter.contains(third));
        assertEquals("614e9b", ByteUtils.formatHex(filter.getDataCopy()));
    }
}
