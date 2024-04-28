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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.bitcoinj.base.Coin.COIN;

/**
 * A convenient {@code enum} representation of a Bitcoin network.
 * <p>
 * Note that the name of each {@code enum} constant is defined in <i>uppercase</i> as is the convention in Java.
 * However, the <q>canonical</q> representation in <b>bitcoinj</b> for user-facing display and input
 * of Bitcoin network names is <i>lowercase</i> (e.g. as a command-line parameter.)
 * Implementations should use the {@link #toString()} method for output and the {@link #fromString(String)}
 * method for input of network values.
 */
public enum BitcoinNetwork implements Network {
    /** The main Bitcoin network, known as {@code "mainnet"}, with {@code id} string {@code "org.bitcoin.production"}  */
    MAINNET("org.bitcoin.production", "main", "prod"),
    /** The Bitcoin test network, known as {@code "testnet"}, with {@code id} string {@code "org.bitcoin.test"}  */
    TESTNET("org.bitcoin.test", "test"),
    /** The Bitcoin signature-based test network, known as {@code "signet"}, with {@code id} string {@code "org.bitcoin.signet"}  */
    SIGNET("org.bitcoin.signet", "sig"),
    /** A local Bitcoin regression test network, known as {@code "regtest"}, with {@code id} string {@code "org.bitcoin.regtest"}  */
    REGTEST("org.bitcoin.regtest");

    /**
     * Scheme part for Bitcoin URIs.
     */
    public static final String BITCOIN_SCHEME = "bitcoin";

    /**
     * The maximum number of coins to be generated
     */
    private static final long MAX_COINS = 21_000_000;

    /**
     * The maximum money to be generated
     */
    public static final Coin MAX_MONEY = COIN.multiply(MAX_COINS);

    /** The ID string for the main, production network where people trade things. */
    public static final String ID_MAINNET = MAINNET.id();
    /** The ID string for the testnet. */
    public static final String ID_TESTNET = TESTNET.id();
    /** The ID string for the signet. */
    public static final String ID_SIGNET = SIGNET.id();
    /** The ID string for regtest mode. */
    public static final String ID_REGTEST = REGTEST.id();

    private final String id;

    // All supported names for this BitcoinNetwork
    private final List<String> allNames;

    // Maps from names and alternateNames to BitcoinNetwork
    private static final Map<String, BitcoinNetwork> stringToEnum = mergedNameMap();

    BitcoinNetwork(String networkId, String... alternateNames) {
        this.id = networkId;
        this.allNames = combine(this.toString(), alternateNames);
    }

    /**
     * Return the canonical, lowercase, user-facing {@code String} for an {@code enum}.
     * It is the lowercase value of {@link #name()} and can be displayed to the user, used
     * as a command-line parameter, etc.
     * <dl>
     *     <dt>{@link #MAINNET}</dt>
     *     <dd>{@code mainnet}</dd>
     *     <dt>{@link #TESTNET}</dt>
     *     <dd>{@code testnet}</dd>
     *     <dt>{@link #SIGNET}</dt>
     *     <dd>{@code signet}</dd>
     *     <dt>{@link #REGTEST}</dt>
     *     <dd>{@code regtest}</dd>
     * </dl>
     * @return canonical lowercase name for this Bitcoin network
     */
    @Override
    public String toString() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * Return the network ID string as defined by (these were previously defined in {@code NetworkParameters})
     * <dl>
     *     <dt>{@link #MAINNET}</dt>
     *     <dd>{@code org.bitcoin.production}</dd>
     *     <dt>{@link #TESTNET}</dt>
     *     <dd>{@code org.bitcoin.test}</dd>
     *     <dt>{@link #SIGNET}</dt>
     *     <dd>{@code org.bitcoin.signet}</dd>
     *     <dt>{@link #REGTEST}</dt>
     *     <dd>{@code org.bitcoin.regtest}</dd>
     * </dl>
     *
     * @return The network ID string
     */
    @Override
    public String id() {
        return id;
    }

    /**
     * Header byte of base58 encoded legacy P2PKH addresses for this network.
     * @return header byte as an {@code int}.
     * @see LegacyAddress.AddressHeader
     */
    public int legacyAddressHeader() {
        return LegacyAddress.AddressHeader.ofNetwork(this).headerByte();
    }

    /**
     * Header byte of base58 encoded legacy P2SH addresses for this network.
     * @return header byte as an {@code int}.
     * @see LegacyAddress.P2SHHeader
     */
    public int legacyP2SHHeader() {
        return LegacyAddress.P2SHHeader.ofNetwork(this).headerByte();
    }

    /**
     * Return the standard Bech32 {@link org.bitcoinj.base.SegwitAddress.SegwitHrp} (as a {@code String}) for
     * this network.
     * @return The HRP as a (lowercase) string.
     */
    public String segwitAddressHrp() {
        return SegwitAddress.SegwitHrp.ofNetwork(this).toString();
    }

    /**
     * The URI scheme for Bitcoin.
     * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki">BIP 0021</a>
     * @return string containing the URI scheme
     */
    @Override
    public String uriScheme() {
        return BITCOIN_SCHEME;
    }

    @Override
    public boolean hasMaxMoney() {
        return true;
    }

    @Override
    public Coin maxMoney() {
        return MAX_MONEY;
    }

    @Override
    public boolean exceedsMaxMoney(Monetary amount) {
        if (amount instanceof Coin) {
            return ((Coin) amount).compareTo(MAX_MONEY) > 0;
        } else {
            throw new IllegalArgumentException("amount must be a Coin type");
        }
    }

    /**
     * Check if an address is valid on this network.
     * This is meant to be used as a precondition for a method or function that expects a valid address. If
     * you are validating addresses provided externally, you probably want to use
     * {@link #isValidAddress(Address)} to handle errors more gracefully. This method uses {@link #isValidAddress(Address)}
     * internally which properly accounts for address normalization.
     * @param address Address to validate
     * @return The unmodified address if valid on this network
     * @throws IllegalArgumentException if address not valid on this network
     */
    public Address checkAddress(Address address) throws IllegalArgumentException {
        if (!isValidAddress(address)) {
            throw new IllegalArgumentException(String.format("Address %s not valid on network %s", address, this));
        }
        return address;
    }

    /**
     * Is address valid for this network. Because we normalize the {@code network()} value in the {@link Address}
     * type (see the JavaDoc for {@link Address#network()}) this method should be used in preference to simply
     * verifying that {@code address.network()} returns the desired network type.
     * @param address Address to validate
     * @return {@code true} if valid on this network, {@code false} otherwise
     */
    public boolean isValidAddress(Address address) {
        boolean valid;
        switch (this) {
            case MAINNET:
                valid = address.network() == MAINNET;
                break;
            case TESTNET:
            case SIGNET:
                // SIGNET uses the same addresses as TESTNET
                valid = address.network() == TESTNET;
                break;
            case REGTEST:
                if (address instanceof LegacyAddress) {
                    // For Legacy addresses, REGTEST uses TESTNET addresses
                    valid = ((LegacyAddress) address).network == TESTNET;
                } else {
                    // On segwit, REGTEST has its own address type
                    valid = address.network() == REGTEST;
                }
                break;
            default:
                valid = false;
                break;
        }
        return valid;
    }

    /**
     * Find the {@code BitcoinNetwork} from a name string, e.g. "mainnet", "testnet" or "signet".
     * A number of common alternate names are allowed too, e.g. "main" or "prod".
     * @param nameString A name string
     * @return An {@code Optional} containing the matching enum or empty
     */
    public static Optional<BitcoinNetwork> fromString(String nameString) {
        return Optional.ofNullable(stringToEnum.get(nameString));
    }

    /**
     * Find the {@code BitcoinNetwork} from an ID String
     * @param idString specifies the network
     * @return An {@code Optional} containing the matching enum or empty
     */
    public static Optional<BitcoinNetwork> fromIdString(String idString) {
        return stream()
                .filter(n -> n.id.equals(idString))
                .findFirst();
    }

    /**
     * @return list of the names of all instances of this enum
     */
    public static List<String> strings() {
        return stream()
                .map(BitcoinNetwork::toString)
                .collect(Collectors.toList());
    }

    /**
     * @return stream of all instances of this enum
     */
    private static Stream<BitcoinNetwork> stream() {
        return Arrays.stream(values());
    }

    // Create a Map that maps name Strings to networks for all instances
    private static Map<String, BitcoinNetwork> mergedNameMap() {
        return stream()
                .collect(HashMap::new,                  // Supply HashMaps as mutable containers
                    BitcoinNetwork::accumulateNames,    // Accumulate one network into hashmap
                    Map::putAll);                       // Combine two containers
    }

    // Add allNames for this Network as keys to a map that can be used to find it
    private static void accumulateNames(Map<String, BitcoinNetwork> map, BitcoinNetwork net) {
        net.allNames.forEach(name -> map.put(name, net));
    }

    // Combine a String and an array of String and return as an unmodifiable list
    private static List<String> combine(String canonical, String[] alternateNames) {
        List<String> temp = new ArrayList<>();
        temp.add(canonical);
        temp.addAll(Arrays.asList(alternateNames));
        return Collections.unmodifiableList(temp);
    }
}
