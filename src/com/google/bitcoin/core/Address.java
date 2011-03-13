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

import java.util.Arrays;

/**
 * A BitCoin address is fundamentally derived from an elliptic curve public key and a set of network parameters.
 * It has several possible representations:<p>
 *
 * <ol>
 *     <li>The raw public key bytes themselves.
 *     <li>RIPEMD160 hash of the public key bytes.
 *     <li>A base58 encoded "human form" that includes a version and check code, to guard against typos.
 * </ol><p>
 *
 * One may question whether the base58 form is really an improvement over the hash160 form, given
 * they are both very unfriendly for typists. More useful representations might include qrcodes
 * and identicons.<p>
 *
 * Note that an address is specific to a network because the first byte is a discriminator value.
 */
public class Address {
    private byte[] hash160;
    private NetworkParameters params;

    /**
     * Construct an address from parameters and the hash160 form. Example:<p>
     *
     * <pre>new Address(NetworkParameters.prodNet(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    public Address(NetworkParameters params,  byte[] hash160) {
        assert hash160.length == 20;
        this.hash160 = hash160;
        this.params = params;
    }

    /**
     * Construct an address from parameters and the standard "human readable" form. Example:<p>
     *
     * <pre>new Address(NetworkParameters.prodNet(), "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");</pre>
     */
    public Address(NetworkParameters params, String address) throws AddressFormatException {
        this.params = params;
        this.hash160 = strToHash160(address);
    }

    /** The (big endian) 20 byte hash that is the core of a BitCoin address. */
    public byte[] getHash160() {
        assert hash160 != null;
        return hash160;
    }
    

    private byte[] strToHash160(String address) throws AddressFormatException {
        byte[] bytes = Base58.decode(address);
        if (bytes.length != 25) {
            // Zero pad the result.
            byte[] tmp = new byte[25];
            System.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);
            bytes = tmp;
        }
        if (bytes[0] != params.addressHeader)
            throw new AddressFormatException();
        byte[] check = Utils.doubleDigest(bytes, 0, 21);
        if (check[0] != bytes[21] || check[1] != bytes[22] || check[2] != bytes[23] || check[3] != bytes[24])
            throw new AddressFormatException();
        byte[] hash160 = new byte[20];
        System.arraycopy(bytes, 1, hash160, 0, 20);
        return hash160;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Address)) return false;
        Address a = (Address) o;
        return Arrays.equals(a.getHash160(), getHash160());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getHash160());
    }

    @Override
    public String toString() {
        byte[] input = hash160;
        // A stringified address is:
        //   1 byte version + 20 bytes hash + 4 bytes check code (itself a truncated hash)
        byte[] addressBytes = new byte[1 + 20 + 4];
        addressBytes[0] = params.addressHeader;
        System.arraycopy(input, 0, addressBytes, 1, 20);
        byte[] check = Utils.doubleDigest(addressBytes, 0, 21);
        System.arraycopy(check, 0, addressBytes, 21, 4);
        return Base58.encode(addressBytes);
    }
}
