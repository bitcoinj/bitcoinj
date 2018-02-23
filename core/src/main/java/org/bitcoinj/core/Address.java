/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Giannis Dzegoutanis
 * Copyright 2015 Andreas Schildbach
 * Copyright 2018 John Jegutanis
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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;

import com.google.common.base.Objects;
import com.google.common.primitives.Ints;
import com.google.common.primitives.UnsignedBytes;
import org.bitcoinj.params.Networks;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.core.AddressScript.AddressFormat.BASE58;
import static org.bitcoinj.script.Script.ScriptType.P2PKH;
import static org.bitcoinj.script.Script.ScriptType.P2SH;

/**
 * <p>A Bitcoin address looks like 1MsScoe2fTJoq4ZPdQgqyhgWeoNamYPevy and is derived from an elliptic curve public key
 * plus a set of network parameters. Not to be confused with a {@link PeerAddress} or {@link AddressMessage}
 * which are about network (TCP) addresses.</p>
 *
 * <p>A standard address is built by taking the RIPE-MD160 hash of the public key bytes, with a version prefix and a
 * checksum suffix, then encoding it textually as base58. The version prefix is used to both denote the network for
 * which the address is valid (see {@link NetworkParameters}, and also to indicate how the bytes inside the address
 * should be interpreted. Whilst almost all addresses today are hashes of public keys, another (currently unsupported
 * type) can contain a hash of a script instead.</p>
 */
public class Address implements AddressScript, Serializable, Cloneable, Comparable<Address>{

    protected final AddressScript addressScript;

    Address(AddressScript address) {
        checkNotNull(address);
        checkState(!(address instanceof Address), "Cannot pass Address here");
        addressScript = address;
    }

    /**
     * Construct an address from parameters, the address script type, and the hash160 form. Example:<p>
     *
     * <pre>new Address(MainNetParams.get(), ScriptType.P2PKH, Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    Address(NetworkParameters params, ScriptType scriptType, byte[] hash160) {
        switch (scriptType) {
            case P2PKH:
            case P2SH:
                addressScript = new Base58Address(params, scriptType, hash160);
                break;
            // TODO Implement SegWit script types
//            case P2WPKH:
//            case P2WSH:
//                addressScript = new SegWitAddress(params, scriptType, hash160);
//                break;
            default:
                throw new IllegalArgumentException("Unsupported script type: " + scriptType);
        }
    }

    public static Address fromString(@Nullable NetworkParameters params, String str) throws AddressFormatException {
        AddressScript address;
        try {
            address = Base58Address.fromBase58(params, str);
        } catch (WrongNetworkException x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                // TODO Implement SegWit addresses
                throw x;
//                address = SegwitAddress.fromBech32(params, str);
            } catch (WrongNetworkException x2) {
                throw x;
            } catch (AddressFormatException x2) {
                throw new AddressFormatException(str);
            }
        }
        return fromAddressScript(address);
    }

    public static Address fromAddressScript(AddressScript address) {
        if (address instanceof Address) {
            return (Address) address;
        } else {
            return new Address(address);
        }
    }

    /**
     * Examines the version byte of the address and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet. You should be able to handle a null response from this method. Note that the
     * parameters returned is not necessarily the same as the one the Address was created with.
     *
     * @return a NetworkParameters representing the network the address is intended for.
     */
    public NetworkParameters getParameters() {
        return addressScript.getParameters();
    }


    @Override
    public AddressFormat getAddressFormat() {
        return addressScript.getAddressFormat();
    }

    @Override
    public ScriptType getScriptType() {
        return addressScript.getScriptType();
    }

    @Override
    public byte[] getValue() {
        return addressScript.getValue();
    }

    @Override
    public String toString() {
        return addressScript.toString();
    }

    @Override
    public int hashCode() {
        return addressScript.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Address other = (Address) o;
        return addressScript.equals(other.addressScript);
    }

    /**
     * This implementation narrows the return type to <code>Address</code>.
     */
    @Override
    public Address clone() throws CloneNotSupportedException {
        return (Address) super.clone();
    }

    /**
     * {@inheritDoc}
     *
     * This implementation uses an optimized Google Guava method to compare <code>bytes</code>.
     */
    @Override
    public int compareTo(Address o) {
        int result = Ints.compare(addressScript.getScriptType().ordinal(), o.getScriptType().ordinal());
        return result != 0 ? result :
                UnsignedBytes.lexicographicalComparator().compare(addressScript.getValue(), o.getValue());
    }


    /* ************************************************************************
     * ************************************************************************
     * Deprecated stuff bellow
     * ************************************************************************
     * ************************************************************************
     */


    /**
     * Construct an address from parameters, the address version, and the hash160 form. Example:<p>
     *
     * <pre>new Address(MainNetParams.get(), NetworkParameters.getAddressHeader(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    @Deprecated
    public Address(NetworkParameters params, int version, byte[] hash160) throws WrongNetworkException {
        addressScript = new Base58Address(params, version, hash160);
    }

    /** Returns an Address that represents the given P2SH script hash. */
    @Deprecated
    public static Address fromP2SHHash(NetworkParameters params, byte[] hash160) {
        try {
            return new Address(params, params.getP2SHHeader(), hash160);
        } catch (WrongNetworkException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Returns an Address that represents the script hash extracted from the given scriptPubKey */
    @Deprecated
    public static Address fromP2SHScript(NetworkParameters params, Script scriptPubKey) {
        checkArgument(scriptPubKey.isPayToScriptHash(), "Not a P2SH script");
        return fromP2SHHash(params, scriptPubKey.getPubKeyHash());
    }

    /**
     * Construct an address from its Base58 representation.
     * @param params
     *            The expected NetworkParameters or null if you don't want validation.
     * @param base58
     *            The textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL".
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     * @throws WrongNetworkException
     *             if the given address is valid but for a different chain (eg testnet vs mainnet)
     */
    @Deprecated
    public static Address fromBase58(@Nullable NetworkParameters params, String base58) throws AddressFormatException {
        return new Address(params, base58);
    }

    /**
     * Construct an address from parameters and the hash160 form. Example:<p>
     *
     * <pre>new Address(MainNetParams.get(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    @Deprecated
    public Address(NetworkParameters params, byte[] hash160) {
        checkArgument(hash160.length == 20, "Addresses are 160-bit hashes, so you must provide 20 bytes");
        addressScript = new Base58Address(params, hash160);
    }

    /** @deprecated Use {@link #fromBase58(NetworkParameters, String)} */
    @Deprecated
    public Address(@Nullable NetworkParameters params, String address) throws AddressFormatException {
        addressScript = new Base58Address(params, address);
        //
    }

    /** The (big endian) 20 byte hash that is the core of a Bitcoin address. */
    @Deprecated
    public byte[] getHash160() {
        return addressScript.getValue();
    }

    /**
     * Returns true if this address is a Pay-To-Script-Hash (P2SH) address.
     * See also https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki: Address Format for pay-to-script-hash
     */
    @Deprecated
    public boolean isP2SHAddress() {
        return addressScript.getScriptType() == P2SH;
    }

    /**
     * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet.
     * @return a NetworkParameters of the address
     * @throws AddressFormatException if the string wasn't of a known version
     */
    public static NetworkParameters getParametersFromAddress(String address) throws AddressFormatException {
        try {
            return Address.fromString(null, address).getParameters();
        } catch (WrongNetworkException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Check if a given address version is valid given the NetworkParameters.
     */
    @Deprecated
    private static boolean isAcceptableVersion(NetworkParameters params, int version) {
        for (int v : params.getAcceptableAddressCodes()) {
            if (version == v) {
                return true;
            }
        }
        return false;
    }

}
