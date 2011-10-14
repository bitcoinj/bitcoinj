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

/**
 * A BitCoin address is fundamentally derived from an elliptic curve public key and a set of network parameters.
 * It has several possible representations:<p>
 *
 * <ol>
 * <li>The raw public key bytes themselves.
 * <li>RIPEMD160 hash of the public key bytes.
 * <li>A base58 encoded "human form" that includes a version and check code, to guard against typos.
 * </ol><p>
 *
 * One may question whether the base58 form is really an improvement over the hash160 form, given
 * they are both very unfriendly for typists. More useful representations might include qrcodes
 * and identicons.<p>
 *
 * Note that an address is specific to a network because the first byte is a discriminator value.
 */
public class Address extends VersionedChecksummedBytes {
    /**
     * Construct an address from parameters and the hash160 form. Example:<p>
     *
     * <pre>new Address(NetworkParameters.prodNet(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    public Address(NetworkParameters params, byte[] hash160) {
        super(params.addressHeader, hash160);
        if (hash160.length != 20)  // 160 = 8 * 20
            throw new RuntimeException("Addresses are 160-bit hashes, so you must provide 20 bytes");
    }

    /**
     * Construct an address from parameters and the standard "human readable" form. Example:<p>
     *
     * <pre>new Address(NetworkParameters.prodNet(), "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");</pre>
     */
    public Address(NetworkParameters params, String address) throws AddressFormatException {
        super(address);
        if (version != params.addressHeader)
            throw new AddressFormatException("Mismatched version number, trying to cross networks? " + version +
                                             " vs " + params.addressHeader);
    }

    /** The (big endian) 20 byte hash that is the core of a BitCoin address. */
    public byte[] getHash160() {
        return bytes;
    }
}
