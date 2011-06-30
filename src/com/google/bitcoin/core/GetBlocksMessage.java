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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public class GetBlocksMessage extends Message {
    private static final long serialVersionUID = 3479412877853645644L;
    private final List<Sha256Hash> locator;
    private final Sha256Hash stopHash;

    public GetBlocksMessage(NetworkParameters params, List<Sha256Hash> locator, Sha256Hash stopHash) {
        super(params);
        this.locator = locator;
        this.stopHash = stopHash;
    }
    
    public void parse() {
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

    public byte[] bitcoinSerialize() {
        try {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            // Version, for some reason.
            Utils.uint32ToByteStreamLE(NetworkParameters.PROTOCOL_VERSION, buf);
            // Then a vector of block hashes. This is actually a "block locator", a set of block
            // identifiers that spans the entire chain with exponentially increasing gaps between
            // them, until we end up at the genesis block. See CBlockLocator::Set()
            buf.write(new VarInt(locator.size()).encode());
            for (Sha256Hash hash : locator) {
                // Have to reverse as wire format is little endian.
                buf.write(Utils.reverseBytes(hash.getBytes()));
            }
            // Next, a block ID to stop at.
            buf.write(stopHash.getBytes());
            return buf.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }
}
