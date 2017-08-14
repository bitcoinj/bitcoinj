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

package org.bitcoincashj.core;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;

import java.util.Arrays;

import javax.annotation.Nullable;

/**
 * Parses and generates private keys in the form used by the Bitcoin "dumpprivkey" command. This is the private key
 * bytes with a header byte and 4 checksum bytes at the end. If there are 33 private key bytes instead of 32, then
 * the last byte is a discriminator value for the compressed pubkey.
 */
public class DumpedPrivateKey extends VersionedChecksummedBytes {
    private boolean compressed;

    /**
     * Construct a private key from its Base58 representation.
     * @param params
     *            The expected NetworkParameters or null if you don't want validation.
     * @param base58
     *            The textual form of the private key.
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     * @throws WrongNetworkException
     *             if the given private key is valid but for a different chain (eg testnet vs mainnet)
     */
    public static DumpedPrivateKey fromBase58(@Nullable NetworkParameters params,String base58) throws AddressFormatException {
        return new DumpedPrivateKey(params, base58);
    }

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

    /** @deprecated Use {@link #fromBase58(NetworkParameters, String)} */
    @Deprecated
    public DumpedPrivateKey(@Nullable NetworkParameters params, String encoded) throws AddressFormatException {
        super(encoded);
        if (params != null && version != params.getDumpedPrivateKeyHeader())
            throw new WrongNetworkException(version, new int[]{ params.getDumpedPrivateKeyHeader() });
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
        return version == other.version && compressed == other.compressed && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(version, compressed, Arrays.hashCode(bytes));
    }
}
