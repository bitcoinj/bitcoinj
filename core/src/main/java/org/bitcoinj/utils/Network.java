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

package org.bitcoinj.utils;

import java.util.Arrays;

/**
 * A convenient {@code enum} representation of a network.
 */
public enum Network {
    MAIN("org.bitcoin.production"),
    TEST("org.bitcoin.test"),
    SIGNET("org.bitcoin.signet"),
    REGTEST("org.bitcoin.regtest");
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

    Network(String networkId) {
        id = networkId;
    }

    /**
     * Get the network id string (previously specified in {@code NetworkParameters})
     *
     * @return The network id string
     */
    public String id() {
        return id;
    }

    /**
     * Get the correct enum for a network id string
     * <p>
     * Note: UNITTEST is not supported as an enum
     * @param idString specifies the network
     * @return the enum
     */
    public static Network of(String idString) {
        return Arrays.stream(values())
                .filter(n -> n.id.equals(idString))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Illegal network ID: " + idString));
    }
}
