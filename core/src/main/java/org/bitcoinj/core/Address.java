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

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.exceptions.AddressFormatException;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Base class for addresses, e.g. native segwit addresses ({@link SegwitAddress}) or legacy addresses ({@link LegacyAddress}).
 * <p>
 * Use an implementation of {@link AddressParser#parseAddress(String, Network)} to conveniently construct any kind of address from its textual
 * form.
 */
public abstract class Address implements Comparable<Address> {
    protected static final AddressParser addressParser = new DefaultAddressParser();
    protected final Network network;
    protected final byte[] bytes;

    /**
     * Construct an address from its binary form.
     *
     * @param params the network this address is valid for
     * @param bytes the binary address data
     * @deprecated Use {@link Address#Address(Network, byte[])}
     */
    @Deprecated
    protected Address(NetworkParameters params, byte[] bytes) {
        this.network = checkNotNull(params).network();
        this.bytes = checkNotNull(bytes);
    }

    /**
     * Construct an address from its binary form.
     *
     * @param network the network this address is valid for
     * @param bytes the binary address data
     */
    protected Address(Network network, byte[] bytes) {
        this.network = checkNotNull(network);
        this.bytes = checkNotNull(bytes);
    }

    /**
     * Construct an address from its textual form.
     * 
     * @param params the expected network this address is valid for, or null if the network should be derived from the
     *               textual form
     * @param str the textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL" or
     *            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
     * @return constructed address
     * @throws AddressFormatException
     *             if the given string doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork
     *             if the given string is valid but not for the expected network (eg testnet vs mainnet)
     * @deprecated Use {@link org.bitcoinj.wallet.Wallet#parseAddress(String)} or {@link AddressParser#parseAddress(String, Network)}
     */
    @Deprecated
    public static Address fromString(@Nullable NetworkParameters params, String str)
            throws AddressFormatException {
        return (params != null)
                    ? addressParser.parseAddress(str, params.network())
                    : addressParser.parseAddressAnyNetwork(str);
    }

    /**
     * Construct an {@link Address} that represents the public part of the given {@link ECKey}.
     * 
     * @param params
     *            network this address is valid for
     * @param key
     *            only the public part is used
     * @param outputScriptType
     *            script type the address should use
     * @return constructed address
     * @deprecated Use {@link ECKey#toAddress(ScriptType, Network)}
     */
    @Deprecated
    public static Address fromKey(final NetworkParameters params, final ECKey key, final ScriptType outputScriptType) {
        return key.toAddress(outputScriptType, params.network());
    }

    /**
     * @return network this data is valid for
     * @deprecated Use {@link #network()}
     */
    @Deprecated
    public final NetworkParameters getParameters() {
        return NetworkParameters.of(network);
    }

    @Override
    public int hashCode() {
        return Objects.hash(network, Arrays.hashCode(bytes));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Address other = (Address) o;
        return this.network == other.network && Arrays.equals(this.bytes, other.bytes);
    }

    /**
     * Get either the public key hash or script hash that is encoded in the address.
     * 
     * @return hash that is encoded in the address
     */
    public abstract byte[] getHash();

    /**
     * Get the type of output script that will be used for sending to the address.
     * 
     * @return type of output script
     */
    public abstract ScriptType getOutputScriptType();

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
    abstract public int compareTo(Address o);

    /**
     * Get the network this address works on. Use of {@link BitcoinNetwork} is preferred to use of {@link NetworkParameters}
     * when you need to know what network an address is for.
     * @return the Network.
     */
    public Network network() {
        return network;
    }

    /**
     * Comparator for the first two comparison fields in {@code Address} comparisons, see {@link Address#compareTo(Address)}.
     * Used by {@link LegacyAddress#compareTo(Address)} and {@link SegwitAddress#compareTo(Address)}.
     */
    protected static final Comparator<Address> PARTIAL_ADDRESS_COMPARATOR = Comparator
        .comparing((Address a) -> a.network.id())   // First compare network
        .thenComparing(Address::compareTypes);      // Then compare address type (subclass)

    private static int compareTypes(Address a, Address b) {
        if (a instanceof LegacyAddress && b instanceof SegwitAddress) {
            return -1;  // Legacy addresses (starting with 1 or 3) come before Segwit addresses.
        } else if (a instanceof SegwitAddress && b instanceof LegacyAddress) {
            return 1;
        } else {
            return 0;   // Both are the same type: additional `thenComparing()` lambda(s) for that type must finish the comparison
        }
    }
}
