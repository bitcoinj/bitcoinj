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

package org.bitcoinj.core;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;

import java.util.Arrays;

/**
 * Parses and generates private keys in the form used by the Bitcoin "dumpprivkey" command. This is the private key
 * bytes with a header byte and 4 checksum bytes at the end. If there are 33 private key bytes instead of 32, then
 * the last byte is a discriminator value for the compressed pubkey.
 */
public class DumpedPrivateKey extends VersionedChecksummedBytes {
    private boolean compressed;

    // Used by ECKey.getPrivateKeyEncoded()
    DumpedPrivateKey(NetworkParameters params, byte[] keyBytes, boolean compressed) {
        super(params.getDumpedPrivateKeyHeader(), encode(keyBytes, compressed));
        this.compressed = compressed;
    }

    private static byte[] encode(byte[] keyBytes, boolean compressed) {
        Preconditions.checkArgument(keyBytes.length == 32, "Private keys must be 32 bytes");
        if (!compressed) {
            return keyBytes;
        } else {
            // Keys that have compressed public components have an extra 1 byte on the end in dumped form.
            byte[] bytes = new byte[33];
            System.arraycopy(keyBytes, 0, bytes, 0, 32);
            bytes[32] = 1;
            return bytes;
        }
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
        if (params != null && version != params.getDumpedPrivateKeyHeader())
            throw new AddressFormatException("Mismatched version number, trying to cross networks? " + version +
                    " vs " + params.getDumpedPrivateKeyHeader());
        if (bytes.length == 33 && bytes[32] == 1) {
            compressed = true;
            bytes = Arrays.copyOf(bytes, 32);  // Chop off the additional marker byte.
        } else if (bytes.length == 32) {
            compressed = false;
        } else {
            throw new AddressFormatException("Wrong number of bytes for a private key, not 32 or 33");
        }
    }

    /**
     * Returns an ECKey created from this encoded private key.
     */
    public ECKey getKey() {
        final ECKey key = ECKey.fromPrivate(bytes);
        return compressed ? key : key.decompress();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DumpedPrivateKey other = (DumpedPrivateKey) o;
        return Arrays.equals(bytes, other.bytes) &&
               version == other.version &&
               compressed == other.compressed;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(bytes, version, compressed);
    }
}
