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

import static com.google.common.base.Preconditions.checkArgument;

import javax.annotation.Nullable;

import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;
import org.bitcoinj.script.ScriptPattern;


/**
 * A legacy (base58) Bitcoin address looks like 1MsScoe2fTJoq4ZPdQgqyhgWeoNamYPevy and is divided into two
 * concrete types: {@link LegacyP2PKHAddress}, which is derived from the RIPE-MD160 hash of public key bytes,
 * and {@link LegacyP2SHAddress}, which is derived from the hash of a {@link Script}.
 */
public abstract class LegacyAddress extends Address {
    /**
     * An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
     */
    public static final int LENGTH = 20;

    /**
     * Private constructor. Use {@link #fromBase58(NetworkParameters, String)},
     * {@link #fromPubKeyHash(NetworkParameters, byte[])}, {@link #fromScriptHash(NetworkParameters, byte[])} or
     * {@link #fromKey(NetworkParameters, ECKey)}.
     * 
     * @param params
     *            network this address is valid for
     * @param hash160
     *            20-byte hash of pubkey or script
     */
     protected LegacyAddress(NetworkParameters params, byte[] hash160) throws AddressFormatException {
        super(params, hash160);
        if (hash160.length != 20)
            throw new AddressFormatException.InvalidDataLength(
                    "Legacy addresses are 20 byte (160 bit) hashes, but got: " + hash160.length);
    }

    /**
     * Construct a {@link LegacyP2PKHAddress} that represents the given pubkey hash. The resulting address will be a P2PKH type of
     * address.
     * 
     * @param params
     *            network this address is valid for
     * @param hash160
     *            20-byte pubkey hash
     * @return constructed address
     */
    public static LegacyP2PKHAddress fromPubKeyHash(NetworkParameters params, byte[] hash160) throws AddressFormatException {
        return LegacyP2PKHAddress.fromPubKeyHash(params, hash160);
    }

    /**
     * Construct a {@link LegacyP2PKHAddress} that represents the public part of the given {@link ECKey}. Note that an address is
     * derived from a hash of the public key and is not the public key itself.
     * 
     * @param params
     *            network this address is valid for
     * @param key
     *            only the public part is used
     * @return constructed address
     */
    public static LegacyP2PKHAddress fromKey(NetworkParameters params, ECKey key) {
        return fromPubKeyHash(params, key.getPubKeyHash());
    }

    /**
     * Construct a {@link LegacyP2SHAddress} that represents the given P2SH script hash.
     * 
     * @param params
     *            network this address is valid for
     * @param hash160
     *            P2SH script hash
     * @return constructed address
     */
    public static LegacyP2SHAddress fromScriptHash(NetworkParameters params, byte[] hash160) throws AddressFormatException {
        return LegacyP2SHAddress.fromScriptHash(params, hash160);
    }

    /** @deprecated use {@link #fromScriptHash(NetworkParameters, byte[])} */
    @Deprecated
    public static LegacyP2SHAddress fromP2SHHash(NetworkParameters params, byte[] hash160) {
        return fromScriptHash(params, hash160);
    }

    /**
     * @deprecated use {@link #fromScriptHash(NetworkParameters, byte[])} in combination with
     *             {@link ScriptPattern#extractHashFromP2SH(Script)}
     */
    @Deprecated
    public static LegacyP2SHAddress fromP2SHScript(NetworkParameters params, Script scriptPubKey) {
        checkArgument(ScriptPattern.isP2SH(scriptPubKey), "Not a P2SH script");
        return fromScriptHash(params, ScriptPattern.extractHashFromP2SH(scriptPubKey));
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
     */
    public static LegacyAddress fromBase58(@Nullable NetworkParameters params, String base58)
            throws AddressFormatException, AddressFormatException.WrongNetwork {
        try {
            return LegacyP2PKHAddress.fromBase58(params, base58);
        } catch (AddressFormatException.WrongAddressType ignore) {
            try {
                return LegacyP2SHAddress.fromBase58(params, base58);
            } catch (AddressFormatException.WrongAddressType e) {
                throw new IllegalStateException("Address type is somehow neither P2SH or P2PKH", e);
            }
        }
    }

    /**
     * Get the version header of an address. This is the first byte of a base58 encoded address.
     * 
     * @return version header as one byte
     */
    public abstract int getVersion();

    /** @deprecated Use isInstanceOf with concrete subclasses */
    @Deprecated
    public boolean isP2SHAddress() {
        return getOutputScriptType() == ScriptType.P2SH;
    }

    /**
     * Returns the base58-encoded textual form, including version and checksum bytes.
     * 
     * @return textual form
     */
    public String toBase58() {
        return Base58.encodeChecked(getVersion(), bytes);
    }

    /** @deprecated use {@link #getHash()} */
    @Deprecated
    public byte[] getHash160() {
        return getHash();
    }

    /** The (big endian) 20 byte hash that is the core of a Bitcoin address. */
    @Override
    public byte[] getHash() {
        return bytes;
    }

    /**
     * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet.
     * 
     * @return network the address is valid for
     * @throws AddressFormatException if the given base58 doesn't parse or the checksum is invalid
     */
    public static NetworkParameters getParametersFromAddress(String address) throws AddressFormatException {
        return LegacyAddress.fromBase58(null, address).getParameters();
    }

    @Override
    public String toString() {
        return toBase58();
    }

    @Override
    public LegacyAddress clone() throws CloneNotSupportedException {
        return (LegacyAddress) super.clone();
    }
}
