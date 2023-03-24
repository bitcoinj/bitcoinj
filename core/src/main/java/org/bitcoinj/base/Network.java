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

/**
 * Interface for a generic Bitcoin-like cryptocurrency network. See {@link BitcoinNetwork} for the Bitcoin implementation.
 */
public interface Network {
    /**
     * The dot-seperated string id for this network. For example {@code "org.bitcoin.production"}
     * @return String ID for network
     */
    String id();

    /**
     * Header byte of base58 encoded legacy P2PKH addresses for this network.
     * @return header byte as an {@code int}.
     * @see LegacyAddress.AddressHeader
     */
    int legacyAddressHeader();

    /**
     * Header byte of base58 encoded legacy P2SH addresses for this network.
     * @return header byte as an {@code int}.
     * @see LegacyAddress.P2SHHeader
     */
    int legacyP2SHHeader();

    /**
     * Human-readable part (HRP) of bech32 encoded segwit addresses for this network.
     * @return HRP (lowercase)
     */
    String segwitAddressHrp();

    /**
     * The URI scheme for this network. See {@link BitcoinNetwork#uriScheme()}.
     * @return The URI scheme for this network
     */
    String uriScheme();

    /**
     * Does this network have a fixed maximum number of coins
     * @return {@code true} if this network has a fixed maximum number of coins
     */
    boolean hasMaxMoney();

    /**
     * Maximum number of coins for this network as a {@link Monetary} value.
     * Where not applicable, a very large number of coins is returned instead (e.g. the main coin issue for Dogecoin).
     * @return Maximum number of coins for this network
     */
    Monetary maxMoney();

    /**
     * Check if an amount exceeds the maximum allowed for a network (if the network has one)
     * @param monetary A monetary amount
     * @return true if too big, false if an allowed amount
     */
    boolean exceedsMaxMoney(Monetary monetary);
}
