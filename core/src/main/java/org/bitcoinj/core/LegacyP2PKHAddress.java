/*
 * Copyright by the original author or authors.
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

import org.bitcoinj.params.Networks;
import org.bitcoinj.script.Script;

import javax.annotation.Nullable;
import java.util.Arrays;

/**
 * A legacy P2PKH (Pay 2 Public Key Hash) address is built by taking the RIPE-MD160 hash of the public key bytes,
 * with a version prefix and a checksum suffix, then encoding it textually as base58. The version prefix is used to
 * both denote the network for which the address is valid (see {@link NetworkParameters}, and also to indicate how the
 * bytes inside the address * should be interpreted (in this case, as P2PKH rather than P2SH).
 */
public class LegacyP2PKHAddress extends LegacyAddress {

    public static final Script.ScriptType OUTPUT_SCRIPT_TYPE = Script.ScriptType.P2PKH;

    private LegacyP2PKHAddress(NetworkParameters params, byte[] hash160) throws AddressFormatException {
        super(params, hash160);
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
        return new LegacyP2PKHAddress(params, hash160);
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
     * Construct a {@link LegacyP2PKHAddress} from its base58 form.
     *
     * @param params
     *            expected network this address is valid for, or null if if the network should be derived from the
     *            base58
     * @param base58
     *            base58-encoded textual form of the address
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongAddressType
     *             if the given base58 corresponds to a P2SH address
     * @throws AddressFormatException.WrongNetwork
     *             if the given address is valid but for a different chain (eg testnet vs mainnet)
     */
    public static LegacyP2PKHAddress fromBase58(@Nullable NetworkParameters params, String base58)
            throws AddressFormatException, AddressFormatException.WrongAddressType, AddressFormatException.WrongNetwork {
        byte[] versionAndDataBytes = Base58.decodeChecked(base58);
        int version = versionAndDataBytes[0] & 0xFF;
        byte[] bytes = Arrays.copyOfRange(versionAndDataBytes, 1, versionAndDataBytes.length);
        if (params == null) {
            for (NetworkParameters p : Networks.get()) {
                if (version == p.getAddressHeader())
                    return fromPubKeyHash(p, bytes);
                if (version == p.getP2SHHeader())
                    throw new AddressFormatException.WrongAddressType("P2PKH");
            }
            throw new AddressFormatException.InvalidPrefix("No network found for " + base58);
        } else {
            if (version == params.getAddressHeader())
                return fromPubKeyHash(params, bytes);
            if (version == params.getP2SHHeader())
                throw new AddressFormatException.WrongAddressType("P2PKH");
            throw new AddressFormatException.WrongNetwork(version);
        }
    }

    @Override
    public int getVersion() {
        return params.getAddressHeader();
    }

    @Override
    public Script.ScriptType getOutputScriptType() {
        return OUTPUT_SCRIPT_TYPE;
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
        return fromBase58(null, address).getParameters();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        LegacyP2PKHAddress other = (LegacyP2PKHAddress) o;
        return super.equals(other);
    }

    @Override
    public LegacyP2PKHAddress clone() throws CloneNotSupportedException {
        return (LegacyP2PKHAddress) super.clone();
    }
}
