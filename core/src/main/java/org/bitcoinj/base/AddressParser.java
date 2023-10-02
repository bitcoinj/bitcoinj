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
import org.bitcoinj.core.NetworkParameters;

import javax.annotation.Nullable;

/**
 * Functional interface for parsing an {@link Address}. It takes a {@link String} parameter and will parse address
 * strings for a configured set of {@link Network}s. For example, if the parser was created with ({@link AddressParser#getDefault(Network)}
 * it will only parse addresses for the provided value of {@link Network}. If created with {@link AddressParser#getDefault()} it will parse
 * addresses matching any known network. The default set of known networks is defined by {@link BitcoinNetwork}.
 * <p>
 * Note: Be aware that the value returned by {@link Address#network()} will be normalized. See {@link Address#network()} for details.
 */
@FunctionalInterface
public interface AddressParser {
    /**
     * Parse an address for a configured set of {@link Network}s.
     * @param addressString string representation of an address
     * @return A validated address object
     * @throws AddressFormatException invalid address string
     */
    Address parseAddress(String addressString) throws AddressFormatException;

    /**
     * @return The default parser for address and networks types built-in to bitcoinj.
     */
    static AddressParser getDefault() {
        return new DefaultAddressParserProvider().forKnownNetworks();
    }

    /**
     * @param network the network to parse for
     * @return The default (built-in) parser for network
     */
    static AddressParser getDefault(Network network) {
        return new DefaultAddressParserProvider().forNetwork(network);
    }

    /**
     * Interface implemented by custom address parser providers.
     */
    interface AddressParserProvider {
        /**
         * Return a parser that will parse valid addresses for all networks ({@link Network}) known by this provider.
         * @return a parser for all networks known by this provider
         */
        AddressParser forKnownNetworks();

        /**
         * Return a parser that will parse valid addresses for a given {@link Network}.
         * @param network network to parse and validate addresses for
         * @return a parser for the specified network
         */
        AddressParser forNetwork(Network network);
    }

    /**
     * Get a <i>legacy</i> address parser that knows about networks that have been
     * dynamically added to the list maintained by {@link org.bitcoinj.params.Networks}.
     * @return A parser for all known networks
     */
    @Deprecated
    static AddressParser getLegacy() {
        return DefaultAddressParserProvider.fromNetworks().forKnownNetworks();
    }

    /**
     * Get a <i>legacy</i> address parser that knows about networks that have been
     * dynamically added to the list maintained by {@link org.bitcoinj.params.Networks}.
     * @param network the network to parse for
     * @return A parser that will throw for strings that are not valid for network.
     */
    @Deprecated
    static AddressParser getLegacy(Network network) {
        return DefaultAddressParserProvider.fromNetworks().forNetwork(network);
    }

    /**
     * Get a <i>legacy</i> address parser that knows about networks that have been
     * dynamically added to the list maintained by {@link org.bitcoinj.params.Networks}.
     * @param params the network to parser for, or {@code null} for all networks.
     * @return A parser that will throw for strings that are not valid for network.
     */
    @Deprecated
    static AddressParser getLegacy(@Nullable NetworkParameters params) {
        AddressParser.AddressParserProvider provider = DefaultAddressParserProvider.fromNetworks();
        return (params == null)
                ? provider.forKnownNetworks()
                : provider.forNetwork(params.network());
    }

}
