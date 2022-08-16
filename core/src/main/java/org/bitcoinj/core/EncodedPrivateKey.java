/*
 * Copyright 2011 Google Inc.
 * Copyright 2018 Andreas Schildbach
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

import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.crypto.BIP38PrivateKey;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Some form of string-encoded private key. This form is useful for noting them down, e.g. on paper wallets.
 */
public abstract class EncodedPrivateKey {
    protected final NetworkParameters params;
    protected final byte[] bytes;

    protected EncodedPrivateKey(NetworkParameters params, byte[] bytes) {
        this.params = checkNotNull(params);
        this.bytes = checkNotNull(bytes);
    }

    /**
     * Tries to construct a {@link EncodedPrivateKey} subclass from the textual form. Use the
     * <code>instanceof</code> operator to determine what type of data was detected.
     *
     * @param params expected network this data is valid for, or null if the network should be derived from the
     *               textual form
     * @param str    the textual form of the data
     * @return subclass of {@link EncodedPrivateKey}, containing the data
     * @throws AddressFormatException              if the given string doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork if the given string is valid but not for the expected network (eg
     *                                             testnet vs mainnet)
     */
    public static EncodedPrivateKey fromString(@Nullable NetworkParameters params, String str)
            throws AddressFormatException {
        try {
            return DumpedPrivateKey.fromBase58(params, str);
        } catch (AddressFormatException x) {
            return BIP38PrivateKey.fromBase58(params, str);
        }
    }

    /**
     * @return network this data is valid for
     */
    public final NetworkParameters getParameters() {
        return params;
    }

    @Override
    public int hashCode() {
        return Objects.hash(params, Arrays.hashCode(bytes));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncodedPrivateKey other = (EncodedPrivateKey) o;
        return this.params.equals(other.params) && Arrays.equals(this.bytes, other.bytes);
    }
}
