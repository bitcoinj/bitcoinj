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

import org.bitcoinj.base.Network;

import java.util.Arrays;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Some form of string-encoded private key. This form is useful for noting them down, e.g. on paper wallets.
 */
public abstract class EncodedPrivateKey {
    protected final transient Network network;
    protected final int version;
    protected final byte[] bytes;

    protected EncodedPrivateKey(Network network, int version, byte[] bytes) {
        this.network = checkNotNull(network);
        this.version = version;
        this.bytes = checkNotNull(bytes);
    }

    /**
     * @return network this data is valid for
     */
    @Deprecated
    public final NetworkParameters getParameters() {
        return NetworkParameters.of(network);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, Arrays.hashCode(bytes));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncodedPrivateKey other = (EncodedPrivateKey) o;
        return this.version == other.version && Arrays.equals(this.bytes, other.bytes);
    }
}
