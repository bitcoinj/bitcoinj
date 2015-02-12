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

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Message representing a list of unspent transaction outputs, returned in response to sending a GetUTXOsMessage. */
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
        this.outputs = new ArrayList<TransactionOutput>(outputs.size());
        for (TransactionOutput output : outputs) {
            if (output != null) this.outputs.add(output);
        }
        this.chainHead = chainHead;
        this.height = height;
        this.heights = Arrays.copyOf(heights, heights.length);
    }

    @Override
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        Utils.uint32ToByteStreamLE(height, stream);
        stream.write(chainHead.getBytes());
        stream.write(new VarInt(hits.length).encode());
        stream.write(hits);
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput output : outputs) {
            // TODO: Allow these to be specified, if one day we care about sending this message ourselves
            // (currently it's just used for unit testing).
            Utils.uint32ToByteStreamLE(0L, stream);  // Version
            Utils.uint32ToByteStreamLE(0L, stream);  // Height
            output.bitcoinSerializeToStream(stream);
        }
    }

    @Override
    void parse() throws ProtocolException {
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
        outputs = new ArrayList<TransactionOutput>(numOuts);
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

    @Override
    protected void parseLite() throws ProtocolException {
        // Not used.
    }

    public byte[] getHitMap() {
        return Arrays.copyOf(hits, hits.length);
    }

    public List<TransactionOutput> getOutputs() {
        return new ArrayList<TransactionOutput>(outputs);
    }

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

        UTXOsMessage message = (UTXOsMessage) o;

        if (height != message.height) return false;
        if (!chainHead.equals(message.chainHead)) return false;
        if (!Arrays.equals(heights, message.heights)) return false;
        if (!Arrays.equals(hits, message.hits)) return false;
        if (!outputs.equals(message.outputs)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = (int) (height ^ (height >>> 32));
        result = 31 * result + chainHead.hashCode();
        result = 31 * result + Arrays.hashCode(hits);
        result = 31 * result + outputs.hashCode();
        result = 31 * result + Arrays.hashCode(heights);
        return result;
    }
}
