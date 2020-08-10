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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>
 * The following format is often used to represent some type of data (e.g. key or hash of key):
 * </p>
 * 
 * <pre>
 * [prefix] [data bytes] [checksum]
 * </pre>
 * <p>
 * and the result is then encoded with some variant of base. This format is most commonly used for addresses and private
 * keys exported using Bitcoin Core's dumpprivkey command.
 * </p>
 */
public abstract class PrefixedChecksummedBytes implements Serializable, Cloneable {
    protected final transient NetworkParameters params;
    protected final byte[] bytes;

    protected PrefixedChecksummedBytes(NetworkParameters params, byte[] bytes) {
        this.params = checkNotNull(params);
        this.bytes = checkNotNull(bytes);
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
        PrefixedChecksummedBytes other = (PrefixedChecksummedBytes) o;
        return this.params.equals(other.params) && Arrays.equals(this.bytes, other.bytes);
    }

    /**
     * This implementation narrows the return type to {@link PrefixedChecksummedBytes}
     * and allows subclasses to throw {@link CloneNotSupportedException} even though it
     * is never thrown by this implementation.
     */
    @Override
    public PrefixedChecksummedBytes clone() throws CloneNotSupportedException {
        return (PrefixedChecksummedBytes) super.clone();
    }

    // Java serialization

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeUTF(params.getId());
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            Field paramsField = PrefixedChecksummedBytes.class.getDeclaredField("params");
            paramsField.setAccessible(true);
            paramsField.set(this, checkNotNull(NetworkParameters.fromID(in.readUTF())));
            paramsField.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException x) {
            throw new RuntimeException(x);
        }
    }
}
