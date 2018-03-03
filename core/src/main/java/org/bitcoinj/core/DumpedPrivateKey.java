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

import com.google.common.base.Preconditions;

import java.util.Arrays;

import javax.annotation.Nullable;

import org.bitcoinj.params.Networks;

/**
 * Parses and generates private keys in the form used by the Bitcoin "dumpprivkey" command. This is the private key
 * bytes with a header byte and 4 checksum bytes at the end. If there are 33 private key bytes instead of 32, then
 * the last byte is a discriminator value for the compressed pubkey.
 */
public class DumpedPrivateKey extends PrefixedChecksummedBytes {

    /**
     * Construct a private key from its Base58 representation.
     * @param params
     *            The expected NetworkParameters or null if you don't want validation.
     * @param base58
     *            The textual form of the private key.
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork
     *             if the given private key is valid but for a different chain (eg testnet vs mainnet)
     */
    public static DumpedPrivateKey fromBase58(@Nullable NetworkParameters params, String base58)
            throws AddressFormatException, AddressFormatException.WrongNetwork {
        byte[] versionAndDataBytes = Base58.decodeChecked(base58);
        int version = versionAndDataBytes[0] & 0xFF;
        byte[] bytes = Arrays.copyOfRange(versionAndDataBytes, 1, versionAndDataBytes.length);
        if (params == null) {
            for (NetworkParameters p : Networks.get())
                if (version == p.getDumpedPrivateKeyHeader())
                    return new DumpedPrivateKey(p, bytes);
            throw new AddressFormatException.InvalidPrefix("No network found for version " + version);
        } else {
            if (version == params.getDumpedPrivateKeyHeader())
                return new DumpedPrivateKey(params, bytes);
            throw new AddressFormatException.WrongNetwork(version);
        }
    }

    private DumpedPrivateKey(NetworkParameters params, byte[] bytes) {
        super(params, bytes);
        if (bytes.length != 32 && bytes.length != 33)
            throw new AddressFormatException.InvalidDataLength(
                    "Wrong number of bytes for a private key (32 or 33): " + bytes.length);
    }

    // Used by ECKey.getPrivateKeyEncoded()
    DumpedPrivateKey(NetworkParameters params, byte[] keyBytes, boolean compressed) {
        this(params, encode(keyBytes, compressed));
    }

    /**
     * Returns the base58-encoded textual form, including version and checksum bytes.
     * 
     * @return textual form
     */
    public String toBase58() {
        return Base58.encodeChecked(params.getDumpedPrivateKeyHeader(), bytes);
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
     * Returns an ECKey created from this encoded private key.
     */
    public ECKey getKey() {
        return ECKey.fromPrivate(Arrays.copyOf(bytes, 32), isPubKeyCompressed());
    }

    /**
     * Returns true if the public key corresponding to this private key is compressed.
     */
    public boolean isPubKeyCompressed() {
        return bytes.length == 33 && bytes[32] == 1;
    }

    @Override
    public String toString() {
        return toBase58();
    }
}
