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

import java.math.BigInteger;

/**
 * Parses and generates private keys in the form used by the Bitcoin "dumpprivkey" command. This is the private key
 * bytes with a header byte and 4 checksum bytes at the end.
 */
public class DumpedPrivateKey extends VersionedChecksummedBytes {
    // Used by ECKey.getPrivateKeyEncoded()
    DumpedPrivateKey(NetworkParameters params, byte[] keyBytes) {
        super(params.dumpedPrivateKeyHeader, keyBytes);
        if (keyBytes.length != 32)  // 256 bit keys
            throw new RuntimeException("Keys are 256 bits, so you must provide 32 bytes, got " +
                    keyBytes.length + " bytes");
    }

    /**
     * Parses the given private key as created by the "dumpprivkey" Bitcoin C++ RPC.
     *
     * @param params  The expected network parameters of the key. If you don't care, provide null.
     * @param encoded The base58 encoded string.
     * @throws AddressFormatException If the string is invalid or the header byte doesn't match the network params.
     */
    public DumpedPrivateKey(NetworkParameters params, String encoded) throws AddressFormatException {
        super(encoded);
        if (params != null && version != params.dumpedPrivateKeyHeader)
            throw new AddressFormatException("Mismatched version number, trying to cross networks? " + version +
                    " vs " + params.dumpedPrivateKeyHeader);
    }

    /**
     * Returns an ECKey created from this encoded private key.
     */
    public ECKey getKey() {
        return new ECKey(new BigInteger(1, bytes));
    }
}
