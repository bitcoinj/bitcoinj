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
import org.jspecify.annotations.Nullable;

import java.util.Arrays;
import java.util.Objects;

import static java.lang.Math.E;
import static java.lang.Math.log;
import static java.lang.Math.max;
import static java.lang.Math.min;
import static java.lang.Math.pow;
import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * <p>A Bloom filter is a probabilistic data structure.</p>
 *
 * <p>Because a Bloom filter is probabilistic, it has a configurable false positive rate. So the filter will
 * sometimes match objects that weren't inserted into it, but it will never fail to match objects that were.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class BloomFilter {
    /** The BLOOM_UPDATE_* constants control when the bloom filter is auto-updated by the peer using
        it as a filter, either never, for all outputs or only for P2PK outputs (default) */
    public enum BloomUpdate {
        UPDATE_NONE, // 0
        UPDATE_ALL, // 1
        /** Only adds outpoints to the filter if the output is a P2PK/pay-to-multisig script. */
        UPDATE_P2PUBKEY_ONLY //2
    }

    private byte[] data;
    private final long hashFuncs;
    private final int nTweak;
    private final byte nFlags;

    // Same value as Bitcoin Core
    // A filter of 20,000 items and a false positive rate of 0.1% or one of 10,000 items and 0.0001% is just under 36,000 bytes
    public static final long MAX_FILTER_SIZE = 36000;
    // There is little reason to ever have more hash functions than 50 given a limit of 36,000 bytes
    public static final int MAX_HASH_FUNCS = 50;    

    /**
     * Constructs a filter with the given parameters which is updated on P2PK outputs only.
     */
    public BloomFilter(int elements, double falsePositiveRate, int randomNonce) {
        this(elements, falsePositiveRate, randomNonce, BloomUpdate.UPDATE_P2PUBKEY_ONLY);
    }

    /**
     * <p>Constructs a new Bloom Filter which will provide approximately the given false positive rate when the given
     * number of elements have been inserted. If the filter would otherwise be larger than the maximum allowed size,
     * it will be automatically downsized to the maximum size.</p>
     *
     * <p>To check the theoretical false positive rate of a given filter, use
     * {@link BloomFilter#getFalsePositiveRate(int)}.</p>
     *
     * <p>The anonymity of which coins are yours to any peer which you send a BloomFilter to is controlled by the
     * false positive rate. For reference, as of block 187,000, the total number of addresses used in the chain was
     * roughly 4.5 million. Thus, if you use a false positive rate of 0.001 (0.1%), there will be, on average, 4,500
     * distinct public keys/addresses which will be thought to be yours by nodes which have your bloom filter, but
     * which are not actually yours. Keep in mind that a remote node can do a pretty good job estimating the order of
     * magnitude of the false positive rate of a given filter you provide it when considering the anonymity of a given
     * filter.</p>
     *
     * <p>randomNonce is a tweak for the hash function used to prevent some theoretical DoS attacks.
     * It should be a random value, however secureness of the random value is of no great consequence.</p>
     *
     * <p>updateFlag is used to control filter behaviour on the server (remote node) side when it encounters a hit.
     * See {@link BloomFilter.BloomUpdate} for a brief description of each mode. The purpose
     * of this flag is to reduce network round-tripping and avoid over-dirtying the filter for the most common
     * wallet configurations.</p>
     */
    public BloomFilter(int elements, double falsePositiveRate, int randomNonce, BloomUpdate updateFlag) {
        // The following formulas were stolen from Wikipedia's page on Bloom Filters (with the addition of min(..., MAX_...))
        //                        Size required for a given number of elements and false-positive rate
        int size = (int)(-1  / (pow(log(2), 2)) * elements * log(falsePositiveRate));
        size = max(1, min(size, (int) MAX_FILTER_SIZE * 8) / 8);
        this.data = new byte[size];
        // Optimal number of hash functions for a given filter size and element count.
        long numHashFuncs = (int)(data.length * 8 / (double)elements * log(2));
        this.hashFuncs = max(1, min(numHashFuncs, MAX_HASH_FUNCS));
        this.nTweak = randomNonce;
        this.nFlags = (byte)(0xff & updateFlag.ordinal());
    }

    public BloomFilter(byte[] data, long hashFuncs, int nTweak, byte nFlags) {
        this.data = Arrays.copyOf(data, data.length);
        this.hashFuncs = hashFuncs;
        this.nTweak = nTweak;
        this.nFlags = nFlags;
    }

    /**
     * Returns the theoretical false positive rate of this filter if it were to contain the given number of elements.
     */
    public double getFalsePositiveRate(int elements) {
        return pow(1 - pow(E, -1.0 * (hashFuncs * elements) / (data.length * 8)), (double) hashFuncs);
    }

    /**
     * Returns true if the given object matches the filter either because it was inserted, or because of a false
     * positive.
     */
    public synchronized boolean contains(byte[] object) {
        for (int i = 0; i < hashFuncs; i++) {
            if (!ByteUtils.checkBitLE(data, MurmurHash3.murmurHash3(data, nTweak, i, object)))
                return false;
        }
        return true;
    }

    /** Insert the given arbitrary data into the filter. */
    public synchronized void insert(byte[] object) {
        for (int i = 0; i < hashFuncs; i++)
            ByteUtils.setBitLE(data, MurmurHash3.murmurHash3(data, nTweak, i, object));
    }

    /**
     * Sets this filter to match all objects.
     */
    public synchronized void setMatchAll() {
        data = new byte[] {(byte) 0xff};
    }

    /**
     * Copies filter into this. Filter must have the same size, hash function count and nTweak or an
     * IllegalArgumentException will be thrown.
     */
    public synchronized void merge(BloomFilter filter) {
        if (!this.matchesAll() && !filter.matchesAll()) {
            checkArgument(filter.data.length == this.data.length
                    && filter.hashFuncs == this.hashFuncs
                    && filter.nTweak == this.nTweak);
            for (int i = 0; i < data.length; i++)
                this.data[i] |= filter.data[i];
        } else {
            this.data = new byte[] {(byte) 0xff};
        }
    }

    /**
     * Returns true if this filter matches everything.
     */
    public synchronized boolean matchesAll() {
        for (byte b : data)
            if (b != (byte) 0xff)
                return false;
        return true;
    }

    /**
     * Returns the update mode encoded in this filter's flags.
     */
    public BloomUpdate getUpdateFlag() {
        if (nFlags == 0)
            return BloomUpdate.UPDATE_NONE;
        else if (nFlags == 1)
            return BloomUpdate.UPDATE_ALL;
        else if (nFlags == 2)
            return BloomUpdate.UPDATE_P2PUBKEY_ONLY;
        else
            throw new IllegalStateException("Unknown flag combination");
    }

    @Override
    public synchronized boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BloomFilter other = (BloomFilter) o;
        return hashFuncs == other.hashFuncs && nTweak == other.nTweak && Arrays.equals(data, other.data);
    }

    @Override
    public synchronized int hashCode() {
        return Objects.hash(hashFuncs, nTweak, Arrays.hashCode(data));
    }

    public synchronized byte[] getDataCopy() {
        return Arrays.copyOf(data, data.length);
    }

    public long getHashFuncs() {
        return hashFuncs;
    }

    public int getNTweak() {
        return nTweak;
    }

    public byte getNFlags() {
        return nFlags;
    }
}
