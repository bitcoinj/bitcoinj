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
    MAINNET("org.bitcoin.production", "main", "prod"),
    TESTNET("org.bitcoin.test", "test"),
    SIGNET("org.bitcoin.signet", "sig"),
    REGTEST("org.bitcoin.regtest");

    /**
     * Scheme part for Bitcoin URIs.
     */
    public static final String BITCOIN_SCHEME = "bitcoin";

    /**
     * The maximum number of coins to be generated
     */
    private static final long MAX_COINS = 21000000;

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
    /** The ID string for the Unit test network -- there is no corresponding {@code enum}. */
    public static final String ID_UNITTESTNET = "org.bitcoinj.unittest";

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
     * Return the canonical, lowercase, user-facing {@code String} for an {@code enum}
     * @return canonical lowercase value
     */
    @Override
    public String toString() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * Return the network ID string (previously specified in {@code NetworkParameters})
     *
     * @return The network ID string
     */
    @Override
    public String id() {
        return id;
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
     * <p>
     * Note: {@link #ID_UNITTESTNET} is not supported as an enum
     * @param idString specifies the network
     * @return An {@code Optional} containing the matching enum or empty
     */
    public static Optional<BitcoinNetwork> fromIdString(String idString) {
        return Arrays.stream(values())
                .filter(n -> n.id.equals(idString))
                .findFirst();
    }

    // Create a Map that maps name Strings to networks for all instances
    private static Map<String, BitcoinNetwork> mergedNameMap() {
        return Stream.of(values())
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
