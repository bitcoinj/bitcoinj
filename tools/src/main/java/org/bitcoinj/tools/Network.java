/*
 * Copyright 2014 Mike Hearn
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

package org.bitcoinj.tools;

import org.bitcoinj.core.NetworkParameters;

/**
 * A convenient {@code enum} representation of a network.
 */
public enum Network {
    MAIN(NetworkParameters.ID_MAINNET),
    PROD(NetworkParameters.ID_MAINNET), // alias for MAIN
    TEST(NetworkParameters.ID_TESTNET),
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
}
