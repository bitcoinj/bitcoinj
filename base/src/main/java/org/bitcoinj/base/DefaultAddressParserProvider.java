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

package org.bitcoinj.base;

import org.bitcoinj.base.exceptions.AddressFormatException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * An {@code AddressParserProvider} that supports both Base58 and Bech32 encodings and knows about a fixed collection of networks.
 * The networks are specified as two lists: one list for Base58/{@link LegacyAddress} and one for Bech32/{@link SegwitAddress}.
 * Two lists are used because address <i>normalization</i> (see {@link Address#network()}) is different for {@code LegacyAddress}
 * and {@code SegwitAddress}.
 * <p>
 * The no-args constructor is used by {@link AddressParser#getDefault()} and {@link AddressParser#getDefault(Network)}
 * to provide parsers for the networks in the {@link BitcoinNetwork} {@code enum}. {@link DefaultAddressParserProvider#DefaultAddressParserProvider(List, List)} is available for implementing subclasses that
 * add additional Bitcoin or Bitcoin-like networks/sidechains (for example: a new Testnet incarnation or the Liquid sidechain.)
 */
public class DefaultAddressParserProvider implements AddressParser.AddressParserProvider {

    /** Valid, normalized, {@link BitcoinNetwork} types for {@link SegwitAddress}/Bech32. */
    static final List<Network> DEFAULT_NETWORKS_SEGWIT = unmodifiableList(
                                                                    BitcoinNetwork.MAINNET,
                                                                    BitcoinNetwork.TESTNET,
                                                                    BitcoinNetwork.REGTEST);

    /** Valid, normalized, {@link BitcoinNetwork} types for {@link LegacyAddress}/Base58. */
    static final List<Network> DEFAULT_NETWORKS_LEGACY = unmodifiableList(
                                                                    BitcoinNetwork.MAINNET,
                                                                    BitcoinNetwork.TESTNET);

    // Networks to search when parsing segwit addresses
    private final List<Network> segwitNetworks;
    // Networks to search when parsing base58 addresses
    private final List<Network> base58Networks;

    /**
     * Construct an {@link AddressParser.AddressParserProvider} that provides parsers that handle addresses for
     * <b>bitcoinj</b>'s built-in networks.
     */
    DefaultAddressParserProvider() {
        this(DEFAULT_NETWORKS_SEGWIT, DEFAULT_NETWORKS_LEGACY);
    }

    /**
     * Construct an {@link AddressParser.AddressParserProvider} that provides parsers that handle addresses for a
     * fixed collection of networks based upon the two lists passed to the constructor.
     * Use this constructor if you have a custom list of networks to use when parsing addresses
     * @param segwitNetworks Networks to search when parsing segwit addresses
     * @param base58Networks Networks to search when parsing base58 addresses
     */
    protected DefaultAddressParserProvider(List<Network> segwitNetworks, List<Network> base58Networks) {
        this.segwitNetworks = segwitNetworks;
        this.base58Networks = base58Networks;
    }

    @Override
    public AddressParser forKnownNetworks() {
        return this::parseAddress;
    }

    @Override
    public AddressParser forNetwork(Network network) {
        return address -> this.parseAddress(address, network);
    }

    private Address parseAddress(String addressString) throws AddressFormatException {
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

    private Address parseAddress(String addressString, Network network) throws AddressFormatException {
        try {
            return LegacyAddress.fromBase58(addressString, network);
        } catch (AddressFormatException.WrongNetwork x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                return SegwitAddress.fromBech32(addressString, network);
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
        Bech32.Bech32Data bechData = Bech32.decode(bech32);
        String hrp = bechData.hrp;
        Network network = segwitNetworks.stream()
                .filter(n -> hrp.equals(n.segwitAddressHrp()))
                .findFirst()
                .orElseThrow(() -> new AddressFormatException.InvalidPrefix("No network found for " + bech32));
        return SegwitAddress.fromBechData(network, bechData);
    }

    /**
     * Construct a {@link LegacyAddress} from its base58 form.
     *
     * @param base58 base58-encoded textual form of the address
     * @throws AddressFormatException if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork if the given address is valid but for a different chain (e.g. testnet vs mainnet)
     */
    private LegacyAddress parseBase58AnyNetwork(String base58)
            throws AddressFormatException, AddressFormatException.WrongNetwork {
        int version = Base58.decodeChecked(base58)[0] & 0xFF;
        return base58Networks.stream()
                .filter(n -> version == n.legacyAddressHeader() || version == n.legacyP2SHHeader())
                .findFirst()
                .map(n -> LegacyAddress.fromBase58(base58, n))
                .orElseThrow(() -> new AddressFormatException.InvalidPrefix("No network found for " + base58));
    }

    // Create an unmodifiable set of NetworkParameters from an array/varargs
    private static List<Network> unmodifiableList(Network... ts) {
        return Collections.unmodifiableList(new ArrayList<>(Arrays.asList(ts)));
    }
}
