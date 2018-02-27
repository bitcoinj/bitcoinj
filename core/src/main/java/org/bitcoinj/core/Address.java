/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Giannis Dzegoutanis
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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bitcoinj.params.Networks;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptPattern;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

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
public class Address extends VersionedChecksummedBytes {
    /**
     * An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
     */
    public static final int LENGTH = 20;

    private transient NetworkParameters params;

    /**
     * Private constructor. Use {@link #fromBase58(NetworkParameters, String)},
     * {@link #fromPubKeyHash(NetworkParameters, byte[])}, {@link #fromP2SHHash(NetworkParameters, byte[])} or
     * {@link #fromKey(NetworkParameters, ECKey)}.
     * 
     * @param params
     *            network this address is valid for
     * @param version
     *            version header of the address
     * @param hash160
     *            20-byte hash of pubkey or script
     */
    private Address(NetworkParameters params, int version, byte[] hash160) throws WrongNetworkException {
        super(version, hash160);
        checkNotNull(params);
        checkArgument(hash160.length == 20, "Addresses are 160-bit hashes, so you must provide 20 bytes");
        if (!isAcceptableVersion(params, version))
            throw new WrongNetworkException(version);
        this.params = params;
    }

    /**
     * Construct an {@link Address} that represents the given pubkey hash. The resulting address will be a P2PKH type of
     * address.
     * 
     * @param params
     *            the network this address is valid for
     * @param hash160
     *            20-byte pubkey hash
     * @return constructed address
     */
    public static Address fromPubKeyHash(NetworkParameters params, byte[] hash160) {
        return new Address(params, params.getAddressHeader(), hash160);
    }

    /**
     * Returns an {@link Address} that represents the public part of the given {@link ECKey}. Note that an address is
     * derived from a hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    public static Address fromKey(NetworkParameters params, ECKey key) {
        return fromPubKeyHash(params, key.getPubKeyHash());
    }

    /** Returns an Address that represents the given P2SH script hash. */
    public static Address fromP2SHHash(NetworkParameters params, byte[] hash160) {
        try {
            return new Address(params, params.getP2SHHeader(), hash160);
        } catch (WrongNetworkException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Returns an Address that represents the script hash extracted from the given scriptPubKey */
    public static Address fromP2SHScript(NetworkParameters params, Script scriptPubKey) {
        checkArgument(ScriptPattern.isPayToScriptHash(scriptPubKey), "Not a P2SH script");
        return fromP2SHHash(params, ScriptPattern.extractHashFromPayToScriptHash(scriptPubKey));
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
    public static Address fromBase58(@Nullable NetworkParameters params, String base58) throws AddressFormatException {
        return new Address(params, base58);
    }

    /** @deprecated use {@link #fromPubKeyHash(NetworkParameters, byte[])} */
    @Deprecated
    public Address(NetworkParameters params, byte[] hash160) {
        this(params, params.getAddressHeader(), hash160);
    }

    /** @deprecated Use {@link #fromBase58(NetworkParameters, String)} */
    @Deprecated
    public Address(@Nullable NetworkParameters params, String address) throws AddressFormatException {
        super(address);
        if (params != null) {
            if (!isAcceptableVersion(params, version)) {
                throw new WrongNetworkException(version);
            }
            this.params = params;
        } else {
            NetworkParameters paramsFound = null;
            for (NetworkParameters p : Networks.get()) {
                if (isAcceptableVersion(p, version)) {
                    paramsFound = p;
                    break;
                }
            }
            if (paramsFound == null)
                throw new AddressFormatException("No network found for " + address);

            this.params = paramsFound;
        }
    }

    /** The (big endian) 20 byte hash that is the core of a Bitcoin address. */
    public byte[] getHash160() {
        return bytes;
    }

    /**
     * Returns true if this address is a Pay-To-Script-Hash (P2SH) address.
     * See also https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki: Address Format for pay-to-script-hash
     */
    public boolean isP2SHAddress() {
        final NetworkParameters parameters = getParameters();
        return parameters != null && this.version == parameters.p2shHeader;
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
        return params;
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
            return Address.fromBase58(null, address).getParameters();
        } catch (WrongNetworkException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Check if a given address version is valid given the NetworkParameters.
     */
    private static boolean isAcceptableVersion(NetworkParameters params, int version) {
        if (version == params.getAddressHeader())
            return true;
        if (version == params.getP2SHHeader())
            return true;
        return false;
    }

    /**
     * This implementation narrows the return type to <code>Address</code>.
     */
    @Override
    public Address clone() throws CloneNotSupportedException {
        return (Address) super.clone();
    }

    // Java serialization

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeUTF(params.id);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        params = NetworkParameters.fromID(in.readUTF());
    }
}
