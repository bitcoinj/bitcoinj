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

package org.bitcoinj.core;

import org.bitcoinj.base.BloomFilter;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptPattern;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>A {@code filterload} message carrying a {@link org.bitcoinj.base.BloomFilter} for peer-side
 * transaction filtering.</p>
 *
 * <p>It can be sent to a peer so that it can avoid sending transactions that are not relevant to the
 * local set of keys, allowing more efficient use of network bandwidth and CPU time.</p>
 *
 * <p>The false positive rate of the underlying bloom filter affects both efficiency and privacy:
 * higher rates increase the number of unrelated transactions that may be matched, making the filter
 * noisier from the remote peer's point of view.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class BloomFilterMessage implements Message {
    private final BloomFilter filter;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static BloomFilterMessage read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        byte[] data = Buffers.readLengthPrefixedBytes(payload);
        if (data.length > BloomFilter.MAX_FILTER_SIZE)
            throw new ProtocolException("Bloom filter out of size range.");
        long hashFuncs = ByteUtils.readUint32(payload);
        if (hashFuncs > BloomFilter.MAX_HASH_FUNCS)
            throw new ProtocolException("Bloom filter hash function count out of range");
        int nTweak = ByteUtils.readInt32(payload);
        byte nFlags = payload.get();
        return new BloomFilterMessage(new BloomFilter(data, hashFuncs, nTweak, nFlags));
    }

    public BloomFilterMessage(BloomFilter filter) {
        this.filter = filter;
    }

    public BloomFilter bloomFilter() {
        return filter;
    }

    @Override
    public int messageSize() {
        return Buffers.lengthPrefixedBytesSize(filter.getDataCopy()) +
                4 + // hashFuncs
                4 + // nTweak
                1; // nFlags
    }

    @Override
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        Buffers.writeLengthPrefixedBytes(buf, filter.getDataCopy());
        ByteUtils.writeInt32LE(filter.getHashFuncs(), buf);
        ByteUtils.writeInt32LE(filter.getNTweak(), buf);
        buf.put(filter.getNFlags());
        return buf;
    }

    /**
     * Creates a new FilteredBlock from the given Block, using this filter to select transactions. Matches can cause the
     * filter to be updated with the matched element, this ensures that when a filter is applied to a block, spends of
     * matched transactions are also matched. However it means this filter can be mutated by the operation. The returned
     * filtered block already has the matched transactions associated with it.
     */
    public synchronized FilteredBlock applyAndUpdate(Block block) {
        List<Transaction> txns = block.transactions();
        List<Sha256Hash> txHashes = new ArrayList<>(txns.size());
        List<Transaction> matched = new ArrayList<>();
        byte[] bits = new byte[(int) Math.ceil(txns.size() / 8.0)];
        for (int i = 0; i < txns.size(); i++) {
            Transaction tx = txns.get(i);
            txHashes.add(tx.getTxId());
            if (applyAndUpdate(tx)) {
                ByteUtils.setBitLE(bits, i);
                matched.add(tx);
            }
        }
        PartialMerkleTree pmt = PartialMerkleTree.buildFromLeaves(bits, txHashes);
        FilteredBlock filteredBlock = new FilteredBlock(block.asHeader(), pmt);
        for (Transaction transaction : matched)
            filteredBlock.provideTransaction(transaction);
        return filteredBlock;
    }

    public synchronized boolean applyAndUpdate(Transaction tx) {
        if (filter.contains(tx.getTxId().getBytes()))
            return true;
        boolean found = false;
        BloomFilter.BloomUpdate flag = filter.getUpdateFlag();
        for (TransactionOutput output : tx.getOutputs()) {
            Script script = output.getScriptPubKey();
            for (ScriptChunk chunk : script.chunks()) {
                if (!chunk.isPushData())
                    continue;
                if (filter.contains(chunk.pushData())) {
                    boolean isSendingToPubKeys = ScriptPattern.isP2PK(script) || ScriptPattern.isSentToMultisig(script);
                    if (flag == BloomFilter.BloomUpdate.UPDATE_ALL || (flag == BloomFilter.BloomUpdate.UPDATE_P2PUBKEY_ONLY && isSendingToPubKeys))
                        filter.insert(output.getOutPointFor().serialize());
                    found = true;
                }
            }
        }
        if (found) return true;
        for (TransactionInput input : tx.getInputs()) {
            if (filter.contains(input.getOutpoint().serialize())) {
                return true;
            }
            for (ScriptChunk chunk : input.getScriptSig().chunks()) {
                if (chunk.isPushData() && filter.contains(chunk.pushData()))
                    return true;
            }
        }
        return false;
    }
}
