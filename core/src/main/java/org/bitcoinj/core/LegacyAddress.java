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

import com.google.common.primitives.UnsignedBytes;
import org.bitcoinj.base.Base58;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.params.Networks;
import org.bitcoinj.base.ScriptType;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;

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
public class LegacyAddress extends Address {
    /**
     * An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
     */
    public static final int LENGTH = 20;

    /** True if P2SH, false if P2PKH. */
    public final boolean p2sh;

    /**
     * Private constructor. Use {@link #fromBase58(Network, String)},
     * {@link #fromPubKeyHash(Network, byte[])}, {@link #fromScriptHash(Network, byte[])} or
     * {@link ECKey#toAddress(ScriptType, Network)}.
     *
     * @param network
     *            network this address is valid for
     * @param p2sh
     *            true if hash160 is hash of a script, false if it is hash of a pubkey
     * @param hash160
     *            20-byte hash of pubkey or script
     */
    private LegacyAddress(Network network, boolean p2sh, byte[] hash160) throws AddressFormatException {
        super(normalizeNetwork(network), hash160);
        if (hash160.length != 20)
            throw new AddressFormatException.InvalidDataLength(
                    "Legacy addresses are 20 byte (160 bit) hashes, but got: " + hash160.length);
        this.p2sh = p2sh;
    }

    private static Network normalizeNetwork(Network network) {
        // LegacyAddress does not distinguish between the different testnet types, normalize to TESTNET
        if (network instanceof BitcoinNetwork) {
            BitcoinNetwork bitcoinNetwork = (BitcoinNetwork) network;
            if (bitcoinNetwork == BitcoinNetwork.SIGNET || bitcoinNetwork == BitcoinNetwork.REGTEST) {
                return BitcoinNetwork.TESTNET;
            }
        }
        return network;
    }

    /**
     * Construct a {@link LegacyAddress} that represents the given pubkey hash. The resulting address will be a P2PKH type of
     * address.
     * 
     * @param params
     *            network this address is valid for
     * @param hash160
     *            20-byte pubkey hash
     * @return constructed address
     * @deprecated Use {@link #fromPubKeyHash(Network, byte[])}
     */
    @Deprecated
    public static LegacyAddress fromPubKeyHash(NetworkParameters params, byte[] hash160) throws AddressFormatException {
        return fromPubKeyHash(params.network(), hash160);
    }

    /**
     * Construct a {@link LegacyAddress} that represents the given pubkey hash. The resulting address will be a P2PKH type of
     * address.
     *
     * @param network network this address is valid for
     * @param hash160 20-byte pubkey hash
     * @return constructed address
     */
    public static LegacyAddress fromPubKeyHash(Network network, byte[] hash160) throws AddressFormatException {
        return new LegacyAddress(network, false, hash160);
    }

    /**
     * Construct a {@link LegacyAddress} that represents the public part of the given {@link ECKey}. Note that an address is
     * derived from a hash of the public key and is not the public key itself.
     * 
     * @param params
     *            network this address is valid for
     * @param key
     *            only the public part is used
     * @return constructed address
     * @deprecated Use {@link ECKey#toAddress(ScriptType, Network)}
     */
    @Deprecated
    public static LegacyAddress fromKey(NetworkParameters params, ECKey key) {
        return (LegacyAddress) key.toAddress(ScriptType.P2PKH, params.network());
    }

    /**
     * Construct a {@link LegacyAddress} that represents the given P2SH script hash.
     * 
     * @param params
     *            network this address is valid for
     * @param hash160
     *            P2SH script hash
     * @return constructed address
     * @deprecated Use {@link #fromScriptHash(Network, byte[])}
     */
    @Deprecated
    public static LegacyAddress fromScriptHash(NetworkParameters params, byte[] hash160) throws AddressFormatException {
        return fromScriptHash(params.network(), hash160);
    }

    /**
     * Construct a {@link LegacyAddress} that represents the given P2SH script hash.
     *
     * @param network network this address is valid for
     * @param hash160 P2SH script hash
     * @return constructed address
     */
    public static LegacyAddress fromScriptHash(Network network, byte[] hash160) throws AddressFormatException {
        return new LegacyAddress(network, true, hash160);
    }

    /**
     * Construct a {@link LegacyAddress} from its base58 form.
     * 
     * @param params
     *            expected network this address is valid for, or null if if the network should be derived from the
     *            base58
     * @param base58
     *            base58-encoded textual form of the address
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork
     *             if the given address is valid but for a different chain (eg testnet vs mainnet)
     * @deprecated Use {@link #fromBase58(Network, String)}
     */
    @Deprecated
    public static LegacyAddress fromBase58(@Nullable NetworkParameters params, String base58)
            throws AddressFormatException, AddressFormatException.WrongNetwork {
        return fromBase58( (params != null) ? params.network() : null, base58);
    }

    /**
     * Construct a {@link LegacyAddress} from its base58 form.
     *
     * @param network expected network this address is valid for, or null if the network should be derived from the base58
     * @param base58 base58-encoded textual form of the address
     * @throws AddressFormatException if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork if the given address is valid but for a different chain (eg testnet vs mainnet)
     */
    public static LegacyAddress fromBase58(@Nullable Network network, String base58)
            throws AddressFormatException, AddressFormatException.WrongNetwork {
        NetworkParameters params = (network != null) ? NetworkParameters.of(network) : null;
        byte[] versionAndDataBytes = Base58.decodeChecked(base58);
        int version = versionAndDataBytes[0] & 0xFF;
        byte[] bytes = Arrays.copyOfRange(versionAndDataBytes, 1, versionAndDataBytes.length);
        if (network == null) {
            for (NetworkParameters p : Networks.get()) {
                if (version == p.getAddressHeader())
                    return new LegacyAddress(p.network(), false, bytes);
                else if (version == p.getP2SHHeader())
                    return new LegacyAddress(p.network(), true, bytes);
            }
            throw new AddressFormatException.InvalidPrefix("No network found for " + base58);
        } else {
            if (version == params.getAddressHeader())
                return new LegacyAddress(network, false, bytes);
            else if (version == params.getP2SHHeader())
                return new LegacyAddress(network, true, bytes);
            throw new AddressFormatException.WrongNetwork(version);
        }
    }

    /**
     * Get the version header of an address. This is the first byte of a base58 encoded address.
     * 
     * @return version header as one byte
     */
    public int getVersion() {
        NetworkParameters params = NetworkParameters.of(network);
        return p2sh ? params.getP2SHHeader() : params.getAddressHeader();
    }

    /**
     * Returns the base58-encoded textual form, including version and checksum bytes.
     * 
     * @return textual form
     */
    public String toBase58() {
        return Base58.encodeChecked(getVersion(), bytes);
    }

    /** The (big endian) 20 byte hash that is the core of a Bitcoin address. */
    @Override
    public byte[] getHash() {
        return bytes;
    }

    /**
     * Get the type of output script that will be used for sending to the address. This is either
     * {@link ScriptType#P2PKH} or {@link ScriptType#P2SH}.
     * 
     * @return type of output script
     */
    @Override
    public ScriptType getOutputScriptType() {
        return p2sh ? ScriptType.P2SH : ScriptType.P2PKH;
    }

    /**
     * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet.
     * 
     * @return network the address is valid for
     * @throws AddressFormatException if the given base58 doesn't parse or the checksum is invalid
     */
    @Deprecated
    public static NetworkParameters getParametersFromAddress(String address) throws AddressFormatException {
        return NetworkParameters.fromAddress(Address.addressParser.parseAddressAnyNetwork(address));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        LegacyAddress other = (LegacyAddress) o;
        return super.equals(other) && this.p2sh == other.p2sh;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), p2sh);
    }

    @Override
    public String toString() {
        return toBase58();
    }

    @Override
    public LegacyAddress clone() throws CloneNotSupportedException {
        return (LegacyAddress) super.clone();
    }

    // Comparator for LegacyAddress, left argument must be LegacyAddress, right argument can be any Address
    private static final Comparator<Address> LEGACY_ADDRESS_COMPARATOR = Address.PARTIAL_ADDRESS_COMPARATOR
            .thenComparingInt(a -> ((LegacyAddress) a).getVersion())                    // Then compare Legacy address version byte
            .thenComparing(a -> a.bytes, UnsignedBytes.lexicographicalComparator());    // Then compare Legacy bytes

    /**
     * {@inheritDoc}
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    @Override
    public int compareTo(Address o) {
       return LEGACY_ADDRESS_COMPARATOR.compare(this, o);
    }
}
