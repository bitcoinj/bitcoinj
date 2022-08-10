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

package org.bitcoinj.core;

import org.bitcoinj.base.Network;
import org.bitcoinj.base.exceptions.AddressFormatException;

/**
 * Address Parser that knows about the address types supported by bitcoinj core.
 */
public class DefaultAddressParser implements AddressParser {
    @Override
    public Address parseAddressAnyNetwork(String addressString) throws AddressFormatException {
        return parseAddress(addressString, null);
    }

    @Override
    public Address parseAddress(String addressString, Network network) throws AddressFormatException {
        try {
            return LegacyAddress.fromBase58(network, addressString);
        } catch (AddressFormatException.WrongNetwork x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                return SegwitAddress.fromBech32(network, addressString);
            } catch (AddressFormatException.WrongNetwork x2) {
                throw x;
            } catch (AddressFormatException x2) {
                throw new AddressFormatException(addressString);
            }
        }
    }
}
