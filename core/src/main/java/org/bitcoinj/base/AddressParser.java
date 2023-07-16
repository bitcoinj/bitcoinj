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

/**
 * Interface for parsing and validating address strings.
 */
public interface AddressParser {
    /**
     * Parse an address for any known/configured network
     * @param addressString string representation of address
     * @return A validated address object
     * @throws AddressFormatException invalid address string
     */
    Address parseAddress(String addressString) throws AddressFormatException;

    /**
     * Parse an address and validate for specified network
     * @param addressString string representation of address
     * @param network the network the address string must represent
     * @return A validated address object
     * @throws AddressFormatException invalid address string or not valid for specified network
     */
    Address parseAddress(String addressString, Network network) throws AddressFormatException;

    /**
     * Parse an address for any known/configured network
     * @param addressString string representation of address
     * @return A validated address object
     * @throws AddressFormatException invalid address string
     * @deprecated Use {@link #parseAddress(String)}
     */
    @Deprecated /* Added in 0.17-alpha1, Deprecated after 0.17-alpha1, to be removed before 0.17 final */
    default Address parseAddressAnyNetwork(String addressString) throws AddressFormatException {
        return parseAddress(addressString);
    }

    /**
     * Functional interface for address parsing. It takes a single parameter, like {@link AddressParser#parseAddress(String)}
     * but its behavior is context-specific. This interface may be
     * implemented by creating a partial application of ({@link AddressParser#parseAddress(String, Network)} providing
     * a fixed value for {@link Network}. Or it may behave more like {@link #parseAddress(String)} with a context-specific
     * list of networks.
     */
    @FunctionalInterface
    interface Simple {
        /**
         * Parse an address in a context-specific way (i.e. with a configured list of valid networks)
         * @param addressString string representation of address
         * @return A validated address object
         * @throws AddressFormatException invalid address string or not valid for network (provided by context)
         */
        Address parseAddress(String addressString) throws AddressFormatException;
    }

    /**
     * Functional interface for strict parsing. It takes a single parameter, like {@link AddressParser#parseAddressAnyNetwork(String)}
     * but is used in a context where a specific {@link Network} has been specified. This interface may be
     * implemented by creating a partial application of ({@link AddressParser#parseAddress(String, Network)} providing
     * a fixed value for {@link Network}.
     * @deprecated You probably want to use {@link AddressParser.Simple}, though the semantics of <q>strict</q> no longer apply.
     */
    @Deprecated  /* Added in 0.17-alpha1, Deprecated after 0.17-alpha1, to be removed before 0.17 final */
    @FunctionalInterface
    interface Strict {
        /**
         * Parse an address in a strict context (e.g. the network must be valid)
         * @param addressString string representation of address
         * @return A validated address object
         * @throws AddressFormatException invalid address string or not valid for network (provided by context)
         */
        Address parseAddress(String addressString) throws AddressFormatException;
    }
}
