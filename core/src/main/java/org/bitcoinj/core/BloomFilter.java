/*
 * Copyright 2012 Matt Corallo
 * Copyright 2015 Andreas Schildbach
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

import com.google.common.base.MoreObjects;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>A Bloom filter is a probabilistic data structure which can be sent to another client so that it can avoid
 * sending us transactions that aren't relevant to our set of keys. This allows for significantly more efficient
 * use of available network bandwidth and CPU time.</p>
 * 
 * <p>Because a Bloom filter is probabilistic, it has a configurable false positive rate. So the filter will sometimes
 * match transactions that weren't inserted into it, but it will never fail to match transactions that were. This is
 * a useful privacy feature - if you have spare bandwidth the false positive rate can be increased so the remote peer
 * gets a noisy picture of what transactions are relevant to your wallet.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class BloomFilter extends Message {
    /** The BLOOM_UPDATE_* constants control when the bloom filter is auto-updated by the peer using
        it as a filter, either never, for all outputs or only for P2PK outputs (default) */
    public enum BloomUpdate {
        UPDATE_NONE, // 0
        UPDATE_ALL, // 1
        /** Only adds outpoints to the filter if the output is a P2PK/pay-to-multisig script */
        UPDATE_P2PUBKEY_ONLY //2
    }
    
    private byte[] data;
    private long hashFuncs;
    private long nTweak;
    private byte nFlags;

    // Same value as Bitcoin Core
    // A filter of 20,000 items and a false positive rate of 0.1% or one of 10,000 items and 0.0001% is just under 36,000 bytes
    private static final long MAX_FILTER_SIZE = 36000;
    // There is little reason to ever have more hash functions than 50 given a limit of 36,000 bytes
    private static final int MAX_HASH_FUNCS = 50;

    /**
     * Construct a BloomFilter by deserializing payloadBytes
     */
    public BloomFilter(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }

    @Override
    public String toString() {
        final MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this).omitNullValues();
        helper.add("data length", data.length);
        helper.add("hashFuncs", hashFuncs);
        helper.add("nFlags", getUpdateFlag());
        return helper.toString();
    }

    @Override
    protected void parse() throws ProtocolException {
        data = readByteArray();
        if (data.length > MAX_FILTER_SIZE)
            throw new ProtocolException ("Bloom filter out of size range.");
        hashFuncs = readUint32();
        if (hashFuncs > MAX_HASH_FUNCS)
            throw new ProtocolException("Bloom filter hash function count out of range");
        nTweak = readUint32();
        nFlags = readBytes(1)[0];
        length = cursor - offset;
    }
    
    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
     */
    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(new VarInt(data.length).encode());
        stream.write(data);
        Utils.uint32ToByteStreamLE(hashFuncs, stream);
        Utils.uint32ToByteStreamLE(nTweak, stream);
        stream.write(nFlags);
    }

    private static int rotateLeft32(int x, int r) {
        return (x << r) | (x >>> (32 - r));
    }

    /**
     * Applies the MurmurHash3 (x86_32) algorithm to the given data.
     * See this <a href="https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp">C++ code for the original.</a>
     */
    public static int murmurHash3(byte[] data, long nTweak, int hashNum, byte[] object) {
        int h1 = (int)(hashNum * 0xFBA4C795L + nTweak);
        final int c1 = 0xcc9e2d51;
        final int c2 = 0x1b873593;

        int numBlocks = (object.length / 4) * 4;
        // body
        for(int i = 0; i < numBlocks; i += 4) {
            int k1 = (object[i] & 0xFF) |
                  ((object[i+1] & 0xFF) << 8) |
                  ((object[i+2] & 0xFF) << 16) |
                  ((object[i+3] & 0xFF) << 24);
            
            k1 *= c1;
            k1 = rotateLeft32(k1, 15);
            k1 *= c2;

            h1 ^= k1;
            h1 = rotateLeft32(h1, 13);
            h1 = h1*5+0xe6546b64;
        }
        
        int k1 = 0;
        switch(object.length & 3)
        {
            case 3:
                k1 ^= (object[numBlocks + 2] & 0xff) << 16;
                // Fall through.
            case 2:
                k1 ^= (object[numBlocks + 1] & 0xff) << 8;
                // Fall through.
            case 1:
                k1 ^= (object[numBlocks] & 0xff);
                k1 *= c1; k1 = rotateLeft32(k1, 15); k1 *= c2; h1 ^= k1;
                // Fall through.
            default:
                // Do nothing.
                break;
        }

        // finalization
        h1 ^= object.length;
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;
        
        return (int)((h1&0xFFFFFFFFL) % (data.length * 8));
    }
    
    /**
     * Returns true if the given object matches the filter either because it was inserted, or because we have a
     * false-positive.
     */
    public synchronized boolean contains(byte[] object) {
        for (int i = 0; i < hashFuncs; i++) {
            if (!Utils.checkBitLE(data, murmurHash3(data, nTweak, i, object)))
                return false;
        }
        return true;
    }
    
    /** Insert the given arbitrary data into the filter */
    public synchronized void insert(byte[] object) {
        for (int i = 0; i < hashFuncs; i++)
            Utils.setBitLE(data, murmurHash3(data, nTweak, i, object));
    }

    /** Inserts the given key and equivalent hashed form (for the address). */
    public synchronized void insert(ECKey key) {
        insert(key.getPubKey());
        insert(key.getPubKeyHash());
    }

    /** Inserts the given transaction outpoint. */
    public synchronized void insert(TransactionOutPoint outpoint) {
        insert(outpoint.unsafeBitcoinSerialize());
    }

    /**
     * Copies filter into this. Filter must have the same size, hash function count and nTweak or an
     * IllegalArgumentException will be thrown.
     */
    public synchronized void merge(BloomFilter filter) {
        if (!this.matchesAll() && !filter.matchesAll()) {
            checkArgument(filter.data.length == this.data.length &&
                          filter.hashFuncs == this.hashFuncs &&
                          filter.nTweak == this.nTweak);
            for (int i = 0; i < data.length; i++)
                this.data[i] |= filter.data[i];
        } else {
            this.data = new byte[] {(byte) 0xff};
        }
    }

    /**
     * Returns true if this filter will match anything. See #$BloomFilter#setMatchAll()
     * for when this can be a useful thing to do.
     */
    public synchronized boolean matchesAll() {
        for (byte b : data)
            if (b != (byte) 0xff)
                return false;
        return true;
    }

    /**
     * The update flag controls how application of the filter to a block modifies the filter. See the enum javadocs
     * for information on what occurs and when.
     */
    public synchronized BloomUpdate getUpdateFlag() {
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
    public synchronized boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BloomFilter other = (BloomFilter) o;
        return hashFuncs == other.hashFuncs && nTweak == other.nTweak && Arrays.equals(data, other.data);
    }

    @Override
    public synchronized int hashCode() {
        return Objects.hash(hashFuncs, nTweak, Arrays.hashCode(data));
    }
}
