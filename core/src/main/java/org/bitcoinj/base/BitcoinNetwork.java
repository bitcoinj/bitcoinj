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

import java.util.Arrays;
import java.util.Optional;

import static org.bitcoinj.base.Coin.COIN;

/**
 * A convenient {@code enum} representation of a network.
 */
public enum BitcoinNetwork implements Network {
    MAIN("org.bitcoin.production"),
    TEST("org.bitcoin.test"),
    SIGNET("org.bitcoin.signet"),
    REGTEST("org.bitcoin.regtest");

    /**
     * The maximum number of coins to be generated
     */
    private static final long MAX_COINS = 21000000;

    /**
     * The maximum money to be generated
     */
    public static final Coin MAX_MONEY = COIN.multiply(MAX_COINS);

    /** The ID string for the main, production network where people trade things. */
    public static final String ID_MAINNET = MAIN.id();
    /** The ID string for the testnet. */
    public static final String ID_TESTNET = TEST.id();
    /** The ID string for the signet. */
    public static final String ID_SIGNET = SIGNET.id();
    /** The ID string for regtest mode. */
    public static final String ID_REGTEST = REGTEST.id();
    /** The ID string for the Unit test network -- there is no corresponding {@code enum}. */
    public static final String ID_UNITTESTNET = "org.bitcoinj.unittest";

    private final String id;

    BitcoinNetwork(String networkId) {
        id = networkId;
    }

    /**
     * Get the network id string (previously specified in {@code NetworkParameters})
     *
     * @return The network id string
     */
    @Override
    public String id() {
        return id;
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
     * Get the {@code BitcoinNetwork} from a <i>validated</i> name String
     * @param nameString A name string (e.g. "MAIN", "TEST", "SIGNET")
     * @return The matching enum
     * @throws IllegalArgumentException if there is no matching enum
     */
    public static BitcoinNetwork of(String nameString) {
        return find(nameString)
                .orElseThrow(() -> new IllegalArgumentException("Unrecognized network name : " + nameString));
    }

    /**
     * Find the {@code BitcoinNetwork} from a name String
     * @param nameString A name string (e.g. "MAIN", "TEST", "SIGNET")
     * @return An {@code Optional} containing the matching enum or empty
     */
    public static Optional<BitcoinNetwork> find(String nameString) {
        return Arrays.stream(values())
                .filter(n -> n.toString().equals(nameString.toUpperCase()))
                .findFirst();
    }

    /**
     * Get the correct enum for a network id string
     * <p>
     * Note: UNITTEST is not supported as an enum
     * @param idString specifies the network
     * @return the enum
     * @throws IllegalArgumentException if there is no matching enum
     */
    public static BitcoinNetwork ofId(String idString) {
        return findById(idString)
                .orElseThrow(() -> new IllegalArgumentException("Illegal network ID: " + idString));
    }

    /**
     * Find the {@code BitcoinNetwork} from an ID String
     * @param idString specifies the network
     * @return An {@code Optional} containing the matching enum or empty
     */
    public static Optional<BitcoinNetwork> findById(String idString) {
        return Arrays.stream(values())
                .filter(n -> n.id.equals(idString))
                .findFirst();
    }
}
