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

import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import com.google.common.base.Objects;
import com.google.common.collect.Lists;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static java.lang.Math.*;

/**
 * <p>A Bloom filter is a probabilistic data structure which can be sent to another client so that it can avoid
 * sending us transactions that aren't relevant to our set of keys. This allows for significantly more efficient
 * use of available network bandwidth and CPU time.</p>
 * 
 * <p>Because a Bloom filter is probabilistic, it has a configurable false positive rate. So the filter will sometimes
 * match transactions that weren't inserted into it, but it will never fail to match transactions that were. This is
 * a useful privacy feature - if you have spare bandwidth the false positive rate can be increased so the remote peer
 * gets a noisy picture of what transactions are relevant to your wallet.</p>
 */
public class BloomFilter extends Message {
    /** The BLOOM_UPDATE_* constants control when the bloom filter is auto-updated by the peer using
        it as a filter, either never, for all outputs or only for pay-2-pubkey outputs (default) */
    public enum BloomUpdate {
        UPDATE_NONE, // 0
        UPDATE_ALL, // 1
        /** Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script */
        UPDATE_P2PUBKEY_ONLY //2
    }
    
    private byte[] data;
    private long hashFuncs;
    private long nTweak;
    private byte nFlags;

    // Same value as the reference client
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
    
    /**
     * Constructs a filter with the given parameters which is updated on pay2pubkey outputs only.
     */
    public BloomFilter(int elements, double falsePositiveRate, long randomNonce) {
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
     * <p>In order for filtered block download to function efficiently, the number of matched transactions in any given
     * block should be less than (with some headroom) the maximum size of the MemoryPool used by the Peer
     * doing the downloading (default is {@link TxConfidenceTable#MAX_SIZE}). See the comment in processBlock(FilteredBlock)
     * for more information on this restriction.</p>
     * 
     * <p>randomNonce is a tweak for the hash function used to prevent some theoretical DoS attacks.
     * It should be a random value, however secureness of the random value is of no great consequence.</p>
     * 
     * <p>updateFlag is used to control filter behaviour on the server (remote node) side when it encounters a hit.
     * See {@link org.bitcoinj.core.BloomFilter.BloomUpdate} for a brief description of each mode. The purpose
     * of this flag is to reduce network round-tripping and avoid over-dirtying the filter for the most common
     * wallet configurations.</p>
     */
    public BloomFilter(int elements, double falsePositiveRate, long randomNonce, BloomUpdate updateFlag) {
        // The following formulas were stolen from Wikipedia's page on Bloom Filters (with the addition of min(..., MAX_...))
        //                        Size required for a given number of elements and false-positive rate
        int size = (int)(-1  / (pow(log(2), 2)) * elements * log(falsePositiveRate));
        size = max(1, min(size, (int) MAX_FILTER_SIZE * 8) / 8);
        data = new byte[size];
        // Optimal number of hash functions for a given filter size and element count.
        hashFuncs = (int)(data.length * 8 / (double)elements * log(2));
        hashFuncs = max(1, min(hashFuncs, MAX_HASH_FUNCS));
        this.nTweak = randomNonce;
        this.nFlags = (byte)(0xff & updateFlag.ordinal());
    }
    
    /**
     * Returns the theoretical false positive rate of this filter if were to contain the given number of elements.
     */
    public double getFalsePositiveRate(int elements) {
        return pow(1 - pow(E, -1.0 * (hashFuncs * elements) / (data.length * 8)), hashFuncs);
    }

    @Override
    public String toString() {
        return "Bloom Filter of size " + data.length + " with " + hashFuncs + " hash functions.";
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
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {
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
     * See this <a href="http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp">C++ code for the original.</a>
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

    /**
     * Sets this filter to match all objects. A Bloom filter which matches everything may seem pointless, however,
     * it is useful in order to reduce steady state bandwidth usage when you want full blocks. Instead of receiving
     * all transaction data twice, you will receive the vast majority of all transactions just once, at broadcast time.
     * Solved blocks will then be send just as Merkle trees of tx hashes, meaning a constant 32 bytes of data for each
     * transaction instead of 100-300 bytes as per usual.
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
     * Returns true if this filter will match anything. See {@link org.bitcoinj.core.BloomFilter#setMatchAll()}
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

    /**
     * Creates a new FilteredBlock from the given Block, using this filter to select transactions. Matches can cause the
     * filter to be updated with the matched element, this ensures that when a filter is applied to a block, spends of
     * matched transactions are also matched. However it means this filter can be mutated by the operation. The returned
     * filtered block already has the matched transactions associated with it.
     */
    public synchronized FilteredBlock applyAndUpdate(Block block) {
        List<Transaction> txns = block.getTransactions();
        List<Sha256Hash> txHashes = new ArrayList<Sha256Hash>(txns.size());
        List<Transaction> matched = Lists.newArrayList();
        byte[] bits = new byte[(int) Math.ceil(txns.size() / 8.0)];
        for (int i = 0; i < txns.size(); i++) {
            Transaction tx = txns.get(i);
            txHashes.add(tx.getHash());
            if (applyAndUpdate(tx)) {
                Utils.setBitLE(bits, i);
                matched.add(tx);
            }
        }
        PartialMerkleTree pmt = PartialMerkleTree.buildFromLeaves(block.getParams(), bits, txHashes);
        FilteredBlock filteredBlock = new FilteredBlock(block.getParams(), block.cloneAsHeader(), pmt);
        for (Transaction transaction : matched)
            filteredBlock.provideTransaction(transaction);
        return filteredBlock;
    }

    public synchronized boolean applyAndUpdate(Transaction tx) {
        if (contains(tx.getHash().getBytes()))
            return true;
        boolean found = false;
        BloomUpdate flag = getUpdateFlag();
        for (TransactionOutput output : tx.getOutputs()) {
            Script script = output.getScriptPubKey();
            for (ScriptChunk chunk : script.getChunks()) {
                if (!chunk.isPushData())
                    continue;
                if (contains(chunk.data)) {
                    boolean isSendingToPubKeys = script.isSentToRawPubKey() || script.isSentToMultiSig();
                    if (flag == BloomUpdate.UPDATE_ALL || (flag == BloomUpdate.UPDATE_P2PUBKEY_ONLY && isSendingToPubKeys))
                        insert(output.getOutPointFor().bitcoinSerialize());
                    found = true;
                }
            }
        }
        if (found) return true;
        for (TransactionInput input : tx.getInputs()) {
            if (contains(input.getOutpoint().bitcoinSerialize())) {
                return true;
            }
            for (ScriptChunk chunk : input.getScriptSig().getChunks()) {
                if (chunk.isPushData() && contains(chunk.data))
                    return true;
            }
        }
        return false;
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
        return Objects.hashCode(hashFuncs, nTweak, Arrays.hashCode(data));
    }
}
