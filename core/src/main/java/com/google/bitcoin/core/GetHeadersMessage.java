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

package com.google.bitcoin.core;

import java.util.List;

/**
 * The "getheaders" command is structurally identical to "getblocks", but has different meaning. On receiving this
 * message a Bitcoin node returns matching blocks up to the limit, but without the bodies. It is useful as an
 * optimization: when your wallet does not contain any keys created before a particular time, you don't have to download
 * the bodies for those blocks because you know there are no relevant transactions.
 */
public class GetHeadersMessage extends GetBlocksMessage {
    public GetHeadersMessage(NetworkParameters params, List<Sha256Hash> locator, Sha256Hash stopHash) {
        super(params, locator, stopHash);
    }

    @Override
    public String toString() {
        StringBuffer b = new StringBuffer();
        b.append("getheaders: ");
        for (Sha256Hash hash : locator) {
            b.append(hash.toString());
            b.append(" ");
        }
        return b.toString();
    }

    /**
     * Compares two getheaders messages. Note that even though they are structurally identical a GetHeadersMessage
     * will not compare equal to a GetBlocksMessage containing the same data.
     */
    @Override
    public boolean equals(Object o) {
        if (o == null || o.getClass() != getClass()) return false;
        GetHeadersMessage other = (GetHeadersMessage) o;
        return (other.version == version &&
                locator.size() == other.locator.size() && locator.containsAll(other.locator) &&
                stopHash.equals(other.stopHash));
    }

    @Override
    public int hashCode() {
        int hashCode = (int) version ^ "getheaders".hashCode();
        for (Sha256Hash aLocator : locator) hashCode ^= aLocator.hashCode();
        hashCode ^= stopHash.hashCode();
        return hashCode;
    }
}
