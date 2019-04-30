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
 * A legacy P2SH (Pay 2 Script Hash) address is built by taking the RIPE-MD160 hash of the redemption {@link Script}
 * bytes, with a version prefix and a checksum suffix, then encoding it textually as base58. The version prefix is used
 * to both denote the network for which the address is valid (see {@link NetworkParameters}, and also to indicate how
 * the bytes inside the address * should be interpreted (in this case, as P2SH rather than P2PKH).
 *
 * <p>For further details on this address type, see its definition in
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki">BIP 13</a>.</p>
 */
public class P2SHAddress extends LegacyAddress {

    public static final Script.ScriptType OUTPUT_SCRIPT_TYPE = Script.ScriptType.P2SH;

    private P2SHAddress(NetworkParameters params, byte[] hash160) throws AddressFormatException {
        super(params, hash160);
    }

    /**
     * Construct a {@link P2SHAddress} that represents the given P2SH script hash.
     *
     * @param params
     *            network this address is valid for
     * @param hash160
     *            P2SH script hash
     * @return constructed address
     */
    public static P2SHAddress fromScriptHash(NetworkParameters params, byte[] hash160) {
        return new P2SHAddress(params, hash160);
    }

    /**
     * Construct a {@link P2SHAddress} from its base58 form.
     *
     * @param params
     *            expected network this address is valid for, or null if if the network should be derived from the
     *            base58
     * @param base58
     *            base58-encoded textual form of the address
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongAddressType
     *             if the given base58 corresponds to a P2PKH address
     * @throws AddressFormatException.WrongNetwork
     *             if the given address is valid but for a different chain (eg testnet vs mainnet)
     */
    public static P2SHAddress fromBase58(@Nullable NetworkParameters params, String base58)
            throws AddressFormatException, AddressFormatException.WrongNetwork {
        byte[] versionAndDataBytes = Base58.decodeChecked(base58);
        int version = versionAndDataBytes[0] & 0xFF;
        byte[] bytes = Arrays.copyOfRange(versionAndDataBytes, 1, versionAndDataBytes.length);
        if (params == null) {
            for (NetworkParameters p : Networks.get()) {
                if (version == p.getP2SHHeader())
                    return fromScriptHash(p, bytes);
                if (version == p.getAddressHeader())
                    throw wrongAddressTypeException();
            }
            throw new AddressFormatException.InvalidPrefix("No network found for " + base58);
        } else {
            if (version == params.getP2SHHeader())
                return fromScriptHash(params, bytes);
            if (version == params.getAddressHeader())
                throw wrongAddressTypeException();
            throw new AddressFormatException.WrongNetwork(version);
        }
    }

    private static AddressFormatException.WrongAddressType wrongAddressTypeException() {
        return new AddressFormatException.WrongAddressType(P2SHAddress.class, Script.ScriptType.P2PKH);
    }

    @Override
    public int getVersion() {
        return params.getP2SHHeader();
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
        P2SHAddress other = (P2SHAddress) o;
        return super.equals(other);
    }

    @Override
    public P2SHAddress clone() throws CloneNotSupportedException {
        return (P2SHAddress) super.clone();
    }
}
