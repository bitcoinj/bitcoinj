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

import org.bitcoinj.core.NetworkParameters;

/**
 * A convenient {@code enum} representation of a network.
 */
public enum Network {
    MAIN(NetworkParameters.ID_MAINNET),
    TEST(NetworkParameters.ID_TESTNET),
    SIGNET(NetworkParameters.ID_SIGNET),
    REGTEST(NetworkParameters.ID_REGTEST);

    private final String id;

    Network(String networkId) {
        id = networkId;
    }

    /**
     * Get the network id string as specified in {@link NetworkParameters}
     *
     * @return The network id string
     */
    public String id() {
        return id;
    }

    /**
     * Get the associated {@link NetworkParameters}
     *
     * @return The network parameters
     */
    public NetworkParameters networkParameters() {
        return NetworkParameters.fromID(id);
    }

    /**
     * Get the correct enum for a NetworkParameters
     * Note: UNITTEST is not supported as an enum
     * @param networkParameters specifies the network
     * @return the enum
     */
    public static Network of(NetworkParameters networkParameters) {
        return of(networkParameters.getId());
    }

    /**
     * Get the correct enum for a network id string
     * Note: UNITTEST is not supported as an enum
     * @param idString specifies the network
     * @return the enum
     */
    public static Network of(String idString) {
        switch (idString) {
            case NetworkParameters.ID_MAINNET:
                return MAIN;
            case NetworkParameters.ID_TESTNET:
                return TEST;
            case NetworkParameters.ID_SIGNET:
                return SIGNET;
            case NetworkParameters.ID_REGTEST:
                return REGTEST;
            case NetworkParameters.ID_UNITTESTNET:
                return REGTEST;
            default:
                throw new IllegalArgumentException("Illegal NetworkParameters: " + idString);
        }
    }
}
