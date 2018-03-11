/*
 * Copyright 2014 the bitcoinj authors
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

import com.google.common.base.Objects;
import org.bitcoinj.net.discovery.HttpDiscovery;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <p>Message representing a list of unspent transaction outputs ("utxos"), returned in response to sending a
 * {@link GetUTXOsMessage} ("getutxos"). Note that both this message and the query that generates it are not
 * supported by Bitcoin Core. An implementation is available in <a href="https://github.com/bitcoinxt/bitcoinxt">Bitcoin XT</a>,
 * a patch set on top of Core. Thus if you want to use it, you must find some XT peers to connect to. This can be done
 * using a {@link HttpDiscovery} class combined with an HTTP/Cartographer seed.</p>
 *
 * <p>The getutxos/utxos protocol is defined in <a href="https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki">BIP 65</a>.
 * In that document you can find a discussion of the security of this protocol (briefly, there is none). Because the
 * data found in this message is not authenticated it should be used carefully. Places where it can be useful are if
 * you're querying your own trusted node, if you're comparing answers from multiple nodes simultaneously and don't
 * believe there is a MITM on your connection, or if you're only using the returned data as a UI hint and it's OK
 * if the data is occasionally wrong. Bear in mind that the answer can be wrong even in the absence of malicious intent
 * just through the nature of querying an ever changing data source: the UTXO set may be updated by a new transaction
 * immediately after this message is returned.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class UTXOsMessage extends Message {
    private long height;
    private Sha256Hash chainHead;
    private byte[] hits;   // little-endian bitset indicating whether an output was found or not.

    private List<TransactionOutput> outputs;
    private long[] heights;

    /** This is a special sentinel value that can appear in the heights field if the given tx is in the mempool. */
    public static long MEMPOOL_HEIGHT = 0x7FFFFFFFL;

    public UTXOsMessage(NetworkParameters params, byte[] payloadBytes) {
        super(params, payloadBytes, 0);
    }

    /**
     * Provide an array of output objects, with nulls indicating that the output was missing. The bitset will
     * be calculated from this.
     */
    public UTXOsMessage(NetworkParameters params, List<TransactionOutput> outputs, long[] heights, Sha256Hash chainHead, long height) {
        super(params);
        hits = new byte[(int) Math.ceil(outputs.size() / 8.0)];
        for (int i = 0; i < outputs.size(); i++) {
            if (outputs.get(i) != null)
                Utils.setBitLE(hits, i);
        }
        this.outputs = new ArrayList<>(outputs.size());
        for (TransactionOutput output : outputs) {
            if (output != null) this.outputs.add(output);
        }
        this.chainHead = chainHead;
        this.height = height;
        this.heights = Arrays.copyOf(heights, heights.length);
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        Utils.uint32ToByteStreamLE(height, stream);
        stream.write(chainHead.getBytes());
        stream.write(new VarInt(hits.length).encode());
        stream.write(hits);
        stream.write(new VarInt(outputs.size()).encode());
        for (int i = 0; i < outputs.size(); i++) {
            TransactionOutput output = outputs.get(i);
            Transaction tx = output.getParentTransaction();
            Utils.uint32ToByteStreamLE(tx != null ? tx.getVersion() : 0L, stream);  // Version
            Utils.uint32ToByteStreamLE(heights[i], stream);  // Height
            output.bitcoinSerializeToStream(stream);
        }
    }

    @Override
    protected void parse() throws ProtocolException {
        // Format is:
        //   uint32 chainHeight
        //   uint256 chainHeadHash
        //   vector<unsigned char> hitsBitmap;
        //   vector<CCoin> outs;
        //
        // A CCoin is  { int nVersion, int nHeight, CTxOut output }
        // The bitmap indicates which of the requested TXOs were found in the UTXO set.
        height = readUint32();
        chainHead = readHash();
        int numBytes = (int) readVarInt();
        if (numBytes < 0 || numBytes > InventoryMessage.MAX_INVENTORY_ITEMS / 8)
            throw new ProtocolException("hitsBitmap out of range: " + numBytes);
        hits = readBytes(numBytes);
        int numOuts = (int) readVarInt();
        if (numOuts < 0 || numOuts > InventoryMessage.MAX_INVENTORY_ITEMS)
            throw new ProtocolException("numOuts out of range: " + numOuts);
        outputs = new ArrayList<>(numOuts);
        heights = new long[numOuts];
        for (int i = 0; i < numOuts; i++) {
            long version = readUint32();
            long height = readUint32();
            if (version > 1)
                throw new ProtocolException("Unknown tx version in getutxo output: " + version);
            TransactionOutput output = new TransactionOutput(params, null, payload, cursor);
            outputs.add(output);
            heights[i] = height;
            cursor += output.length;
        }
        length = cursor;
    }

    /**
     * Returns a bit map indicating which of the queried outputs were found in the UTXO set.
     */
    public byte[] getHitMap() {
        return Arrays.copyOf(hits, hits.length);
    }

    /** Returns the list of outputs that matched the query. */
    public List<TransactionOutput> getOutputs() {
        return new ArrayList<>(outputs);
    }

    /** Returns the block heights of each output returned in getOutputs(), or MEMPOOL_HEIGHT if not confirmed yet. */
    public long[] getHeights() { return Arrays.copyOf(heights, heights.length); }

    @Override
    public String toString() {
        return "UTXOsMessage{" +
                "height=" + height +
                ", chainHead=" + chainHead +
                ", hitMap=" + Arrays.toString(hits) +
                ", outputs=" + outputs +
                ", heights=" + Arrays.toString(heights) +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UTXOsMessage other = (UTXOsMessage) o;
        return height == other.height && chainHead.equals(other.chainHead)
            && Arrays.equals(heights, other.heights) && Arrays.equals(hits, other.hits)
            && outputs.equals(other.outputs);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(height, chainHead, Arrays.hashCode(heights), Arrays.hashCode(hits), outputs);
    }
}
