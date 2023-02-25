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

import java.util.Comparator;

/**
 * Interface for addresses, e.g. native segwit addresses ({@link SegwitAddress}) or legacy addresses ({@link LegacyAddress}).
 * <p>
 * Use {@link AddressParser} to construct any kind of address from its textual form.
 */
public interface Address extends Comparable<Address> {
    /**
     * Get either the public key hash or script hash that is encoded in the address.
     * 
     * @return hash that is encoded in the address
     */
    byte[] getHash();

    /**
     * Get the type of output script that will be used for sending to the address.
     * 
     * @return type of output script
     */
    ScriptType getOutputScriptType();

    /**
     * Comparison field order for addresses is:
     * <ol>
     *     <li>{@link Network#id()}</li>
     *     <li>Legacy vs. Segwit</li>
     *     <li>(Legacy only) Version byte</li>
     *     <li>remaining {@code bytes}</li>
     * </ol>
     * <p>
     * Implementations use {@link Address#PARTIAL_ADDRESS_COMPARATOR} for tests 1 and 2.
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    @Override
    int compareTo(Address o);

    /**
     * Get the network this address is used on. Returns the <i>normalized</i> network (see below.)
     * <p>
     * <b>Note:</b> The network value returned is <i>normalized</i>. For example the address {@code "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"}
     * may be used on either {@link BitcoinNetwork#TESTNET} or {@link BitcoinNetwork#SIGNET}, but the value returned by
     * this method will always be {@link BitcoinNetwork#TESTNET}. Similarly, the address {@code "mnHUcqUVvrfi5kAaXJDQzBb9HsWs78b42R"}
     * may be used on {@link BitcoinNetwork#TESTNET}, {@link BitcoinNetwork#REGTEST}, or {@link BitcoinNetwork#REGTEST}, but
     * the value returned by this method will always be {@link BitcoinNetwork#TESTNET}.
     * @return the Network.
     */
    Network network();

    /**
     * Comparator for the first two comparison fields in {@code Address} comparisons, see {@link Address#compareTo(Address)}.
     * Used by {@link LegacyAddress#compareTo(Address)} and {@link SegwitAddress#compareTo(Address)}.
     * For use by implementing classes only.
     */
    Comparator<Address> PARTIAL_ADDRESS_COMPARATOR = Comparator
        .comparing((Address a) -> a.network().id()) // First compare network
        .thenComparing(Address::compareTypes);      // Then compare address type (subclass)

    /* private */
    static int compareTypes(Address a, Address b) {
        if (a instanceof LegacyAddress && b instanceof SegwitAddress) {
            return -1;  // Legacy addresses (starting with 1 or 3) come before Segwit addresses.
        } else if (a instanceof SegwitAddress && b instanceof LegacyAddress) {
            return 1;
        } else {
            return 0;   // Both are the same type: additional `thenComparing()` lambda(s) for that type must finish the comparison
        }
    }
}
