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
     * Parse an address that could be for any network
     * @param addressString string representation of address
     * @return A validated address object
     * @throws AddressFormatException invalid address string
     */
    Address parseAddressAnyNetwork(String addressString) throws AddressFormatException;

    /**
     * Parse an address and validate for specified network
     * @param addressString string representation of address
     * @param network the network the address string must represent
     * @return A validated address object
     * @throws AddressFormatException invalid address string or not valid for specified network
     */
    Address parseAddress(String addressString, Network network) throws AddressFormatException;

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
