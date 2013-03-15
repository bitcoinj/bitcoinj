/**
 * Copyright 2011 Google Inc.
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

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents the "getblocks" P2P network message, which requests the hashes of the parts of the block chain we're
 * missing. Those blocks can then be downloaded with a {@link GetDataMessage}.
 */
public class GetBlocksMessage extends Message {
    private static final long serialVersionUID = 3479412877853645644L;
    protected long version;
    protected List<Sha256Hash> locator;
    protected Sha256Hash stopHash;

    public GetBlocksMessage(NetworkParameters params, List<Sha256Hash> locator, Sha256Hash stopHash) {
        super(params);
        this.version = protocolVersion;
        this.locator = locator;
        this.stopHash = stopHash;
    }

    protected void parseLite() throws ProtocolException {
        // NOP.  This is a root level message and should always be provided with a length.
    }

    public void parse() throws ProtocolException {
        cursor = offset;
        version = readUint32();
        int startCount = (int) readVarInt();
        if (startCount > 500)
            throw new ProtocolException("Number of locators cannot be > 500, received: " + startCount);
        locator = new ArrayList<Sha256Hash>(startCount);
        for (int i = 0; i < startCount; i++) {
            locator.add(readHash());
        }
        stopHash = readHash();
    }

    public List<Sha256Hash> getLocator() {
        return locator;
    }

    public Sha256Hash getStopHash() {
        return stopHash;
    }

    public String toString() {
        StringBuffer b = new StringBuffer();
        b.append("getblocks: ");
        for (Sha256Hash hash : locator) {
            b.append(hash.toString());
            b.append(" ");
        }
        return b.toString();
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        // Version, for some reason.
        Utils.uint32ToByteStreamLE(NetworkParameters.PROTOCOL_VERSION, stream);
        // Then a vector of block hashes. This is actually a "block locator", a set of block
        // identifiers that spans the entire chain with exponentially increasing gaps between
        // them, until we end up at the genesis block. See CBlockLocator::Set()
        stream.write(new VarInt(locator.size()).encode());
        for (Sha256Hash hash : locator) {
            // Have to reverse as wire format is little endian.
            stream.write(Utils.reverseBytes(hash.getBytes()));
        }
        // Next, a block ID to stop at.
        stream.write(Utils.reverseBytes(stopHash.getBytes()));
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || o.getClass() != getClass()) return false;
        GetBlocksMessage other = (GetBlocksMessage) o;
        return (other.version == version &&
                locator.size() == other.locator.size() && locator.containsAll(other.locator) &&
                stopHash.equals(other.stopHash));
    }

    @Override
    public int hashCode() {
        int hashCode = (int) version ^ "getblocks".hashCode();
        for (Sha256Hash aLocator : locator) hashCode ^= aLocator.hashCode();
        hashCode ^= stopHash.hashCode();
        return hashCode;
    }
}
