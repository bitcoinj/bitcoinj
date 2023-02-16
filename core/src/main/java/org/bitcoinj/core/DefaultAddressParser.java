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

import org.bitcoinj.base.Address;
import org.bitcoinj.base.AddressParser;
import org.bitcoinj.base.Base58;
import org.bitcoinj.base.Bech32;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.base.utils.StreamUtils;
import org.bitcoinj.params.Networks;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Address parser that knows about the address types supported by bitcoinj core and is configurable
 * with additional network types.
 */
public class DefaultAddressParser implements AddressParser {

    // Networks to try when parsing segwit addresses
    public static final List<Network> DEFAULT_NETWORKS_SEGWIT = unmodifiableList(
                                                                    BitcoinNetwork.MAINNET,
                                                                    BitcoinNetwork.TESTNET,
                                                                    BitcoinNetwork.REGTEST);

    // Networks to try when parsing legacy (base58) addresses
    public static final List<Network> DEFAULT_NETWORKS_LEGACY = unmodifiableList(
                                                                    BitcoinNetwork.MAINNET,
                                                                    BitcoinNetwork.TESTNET);

    // Networks to search when parsing segwit addresses
    private final List<Network> segwitNetworks;
    // Networks to search when parsing base58 addresses
    private final List<Network> base58Networks;

    /**
     * DefaultAddressParser with default network lists
     */
    public DefaultAddressParser() {
        this(DEFAULT_NETWORKS_SEGWIT, DEFAULT_NETWORKS_LEGACY);
    }

    /**
     * Use this constructor if you have a custom list of networks to use when parsing addresses
     * @param segwitNetworks Networks to search when parsing segwit addresses
     * @param base58Networks Networks to search when parsing base58 addresses
     */
    public DefaultAddressParser(List<Network> segwitNetworks, List<Network> base58Networks) {
        this.segwitNetworks = segwitNetworks;
        this.base58Networks = base58Networks;
    }

    /**
     * Dynamically create a new AddressParser using a snapshot of currently configured networks
     * from Networks.get().
     * @return A backward-compatible parser
     */
    @Deprecated
    public static DefaultAddressParser fromNetworks() {
        List<Network> nets = Networks.get().stream()
                .map(NetworkParameters::network)
                .collect(StreamUtils.toUnmodifiableList());
        return new DefaultAddressParser(nets, nets);
    }

    @Override
    public Address parseAddressAnyNetwork(String addressString) throws AddressFormatException {
        try {
            return parseBase58AnyNetwork(addressString);
        } catch (AddressFormatException.WrongNetwork x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                return parseBech32AnyNetwork(addressString);
            } catch (AddressFormatException.WrongNetwork x2) {
                throw x;
            } catch (AddressFormatException x2) {
                //throw new AddressFormatException(addressString);
                throw x2;
            }
        }
    }

    @Override
    public Address parseAddress(String addressString, Network network) throws AddressFormatException {
        try {
            return LegacyAddress.fromBase58(network, addressString);
        } catch (AddressFormatException.WrongNetwork x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                return SegwitAddress.fromBech32(network, addressString);
            } catch (AddressFormatException.WrongNetwork x2) {
                throw x;
            } catch (AddressFormatException x2) {
                throw new AddressFormatException(addressString);
            }
        }
    }

    /**
     * Construct a {@link SegwitAddress} from its textual form.
     *
     * @param bech32 bech32-encoded textual form of the address
     * @return constructed address
     * @throws AddressFormatException if something about the given bech32 address isn't right
     */
    private SegwitAddress parseBech32AnyNetwork(String bech32)
            throws AddressFormatException {
        String hrp = Bech32.decode(bech32).hrp;
        return segwitNetworks.stream()
                .map(NetworkParameters::of)
                .filter(p -> hrp.equals(p.getSegwitAddressHrp()))
                .findFirst()
                .map(p -> SegwitAddress.fromBech32(p.network(), bech32))
                .orElseThrow(() -> new AddressFormatException.InvalidPrefix("No network found for " + bech32));
    }

    /**
     * Construct a {@link LegacyAddress} from its base58 form.
     *
     * @param base58 base58-encoded textual form of the address
     * @throws AddressFormatException if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork if the given address is valid but for a different chain (eg testnet vs mainnet)
     */
    private LegacyAddress parseBase58AnyNetwork(String base58)
            throws AddressFormatException, AddressFormatException.WrongNetwork {
        int version = Base58.decodeChecked(base58)[0] & 0xFF;
        return base58Networks.stream()
                .map(NetworkParameters::of)
                .filter(p ->  (version == p.getAddressHeader()) || (version == p.getP2SHHeader()))
                .findFirst()
                .map(p -> LegacyAddress.fromBase58(p.network(), base58))
                .orElseThrow(() -> new AddressFormatException.InvalidPrefix("No network found for " + base58));
    }

    // Create an unmodifiable set of NetworkParameters from an array/varargs
    private static List<Network> unmodifiableList(Network... ts) {
        return Collections.unmodifiableList(new ArrayList<>(Arrays.asList(ts)));
    }
}
