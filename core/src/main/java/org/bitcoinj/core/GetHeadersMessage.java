/*
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

package org.bitcoinj.core;

import org.bitcoinj.base.Sha256Hash;

/**
 * <p>The "getheaders" command is structurally identical to "getblocks", but has different meaning. On receiving this
 * message a Bitcoin node returns matching blocks up to the limit, but without the bodies. It is useful as an
 * optimization: when your wallet does not contain any keys created before a particular time, you don't have to download
 * the bodies for those blocks because you know there are no relevant transactions.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class GetHeadersMessage extends GetBlocksMessage {
    public GetHeadersMessage(NetworkParameters params, BlockLocator locator, Sha256Hash stopHash) {
        super(params, locator, stopHash);
    }

    public GetHeadersMessage(NetworkParameters params, byte[] payload) throws ProtocolException {
        super(params, payload);
    }

    @Override
    public String toString() {
        return "getheaders: " + locator.toString();
    }

    /**
     * Compares two getheaders messages. Note that even though they are structurally identical a GetHeadersMessage
     * will not compare equal to a GetBlocksMessage containing the same data.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GetHeadersMessage other = (GetHeadersMessage) o;
        return version == other.version && stopHash.equals(other.stopHash) &&
            locator.size() == other.locator.size() && locator.equals(other.locator);  // ignores locator ordering
    }

    @Override
    public int hashCode() {
        int hashCode = (int) version ^ "getheaders".hashCode() ^ stopHash.hashCode();
        return hashCode ^= locator.hashCode();
    }
}
