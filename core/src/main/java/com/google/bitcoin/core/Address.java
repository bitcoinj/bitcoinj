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
 * A Bitcoin address is derived from an elliptic curve public key and a set of network parameters.
 * It has several possible representations:<p>
 *
 * <ol>
 * <li>The raw public key bytes themselves.
 * <li>RIPEMD160 hash of the public key bytes.
 * <li>A base58 encoded "human form" that includes a version and check code, to guard against typos.
 * </ol><p>
 *
 * The most common written form is the latter, and there may be several different types of address with the meaning
 * determined by the version code.<p>
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
     * <pre>new Address(NetworkParameters.prodNet(), "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");</pre><p>
     *
     * @param params The expected NetworkParameters or null if you don't want validation.
     * @param address The textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL"
     * @throws AddressFormatException if the given address doesn't parse or the checksum is invalid
     * @throws WrongNetworkException if the given address is valid but for a different chain (eg testnet vs prodnet)
     */
    public Address(NetworkParameters params, String address) throws AddressFormatException, WrongNetworkException {
        super(address);
        if (params != null) {
            boolean found = false;
            for (int v : params.acceptableAddressCodes) {
                if (version == v) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new WrongNetworkException(version, params.acceptableAddressCodes);
            }
        }
    }

    /** The (big endian) 20 byte hash that is the core of a BitCoin address. */
    public byte[] getHash160() {
        return bytes;
    }

    /**
     * Examines the version byte of the address and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet. You should be able to handle a null response from this method. Note that the
     * parameters returned is not necessarily the same as the one the Address was created with.
     *
     * @return a NetworkParameters representing the network the address is intended for, or null if unknown.
     */
    public NetworkParameters getParameters() {
        // TODO: There should be a more generic way to get all supported networks.
        NetworkParameters[] networks =
                new NetworkParameters[] { NetworkParameters.testNet(), NetworkParameters.prodNet() };

        for (NetworkParameters params : networks) {
            if (params.acceptableAddressCodes == null) {
                // Old Java-serialized wallet. This code can eventually be deleted.
                if (params.getId().equals(NetworkParameters.ID_PRODNET))
                    params = NetworkParameters.prodNet();
                else if (params.getId().equals(NetworkParameters.ID_TESTNET))
                    params = NetworkParameters.testNet();
            }
            for (int code : params.acceptableAddressCodes) {
                if (code == version) {
                    return params;
                }
            }
        }
        return null;
    }

    /**
     * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet. You should be able to handle a null response from this method.
     *
     * @param address
     * @return a NetworkParameters representing the network the address is intended for, or null if unknown.
     */
    public static NetworkParameters getParametersFromAddress(String address) throws AddressFormatException {
        try {
            return new Address(null, address).getParameters();
        } catch (WrongNetworkException e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
    }
}
