/*
 * Copyright 2011 Google Inc.
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

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * <p>Represents the "getblocks" P2P network message, which requests the hashes of the parts of the block chain we're
 * missing. Those blocks can then be downloaded with a {@link GetDataMessage}.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class GetBlocksMessage extends Message {

    protected long version;
    protected BlockLocator locator;
    protected Sha256Hash stopHash;

    public GetBlocksMessage(long protocolVersion, BlockLocator locator, Sha256Hash stopHash) {
        this.version = protocolVersion;
        this.locator = locator;
        this.stopHash = stopHash;
    }

    public GetBlocksMessage(ByteBuffer payload) throws ProtocolException {
        super(payload);
    }

    @Override
    protected void parse() throws BufferUnderflowException, ProtocolException {
        version = ByteUtils.readUint32(payload);
        int startCount = VarInt.read(payload).intValue();
        if (startCount > 500)
            throw new ProtocolException("Number of locators cannot be > 500, received: " + startCount);
        locator = new BlockLocator();
        for (int i = 0; i < startCount; i++) {
            locator = locator.add(Sha256Hash.read(payload));
        }
        stopHash = Sha256Hash.read(payload);
    }

    public BlockLocator getLocator() {
        return locator;
    }

    public Sha256Hash getStopHash() {
        return stopHash;
    }

    @Override
    public String toString() {
        return "getblocks: " + locator.toString();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        // Version, for some reason.
        ByteUtils.writeInt32LE(version, stream);
        // Then a vector of block hashes. This is actually a "block locator", a set of block
        // identifiers that spans the entire chain with exponentially increasing gaps between
        // them, until we end up at the genesis block. See CBlockLocator::Set()
        stream.write(VarInt.of(locator.size()).encode());
        for (Sha256Hash hash : locator.getHashes()) {
            // Have to reverse as wire format is little endian.
            stream.write(hash.getReversedBytes());
        }
        // Next, a block ID to stop at.
        stream.write(stopHash.getReversedBytes());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GetBlocksMessage other = (GetBlocksMessage) o;
        return version == other.version && stopHash.equals(other.stopHash) &&
            locator.size() == other.locator.size() && locator.equals(other.locator); // ignores locator ordering
    }

    @Override
    public int hashCode() {
        int hashCode = (int) version ^ "getblocks".hashCode() ^ stopHash.hashCode();
        return hashCode ^= locator.hashCode();
    }
}
