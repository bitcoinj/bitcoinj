/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2019 John L. Jegutanis
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

import java.io.Serializable;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A RawBytes just wraps a byte[] so that equals and hashcode work correctly, allowing it to be used as keys in a
 * map.
 */
public class RawBytes implements Serializable, Comparable<RawBytes> {
    private final byte[] bytes;
    private long hash = -1L;

    private RawBytes(byte[] rawBytes) {
        this.bytes = checkNotNull(rawBytes);
    }

    /**
     * Creates a new instance that wraps the given bytes.
     *
     * @param rawBytes the raw bytes to wrap
     * @return a new instance
     */
    public static RawBytes wrap(byte[] rawBytes) {
        return new RawBytes(rawBytes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(bytes, ((RawBytes)o).bytes);
    }

    @Override
    public int hashCode() {
        if (hash == -1L) hash = Arrays.hashCode(bytes) & 0xFFFFFFFFL;
        return (int) hash;
    }

    @Override
    public String toString() {
        return Utils.HEX.encode(bytes);
    }

    /**
     * Returns the internal byte array, without defensively copying. Therefore do NOT modify the returned array.
     */
    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Creates a deep copy of this object
     * @return the copied raw bytes
     */
    public RawBytes copy() {
        RawBytes newRb = new RawBytes(Arrays.copyOf(bytes, bytes.length));
        newRb.hash = hash;
        return newRb;
    }

    @Override
    public int compareTo(final RawBytes other) {
        for (int i = bytes.length - 1; i >= 0; i--) {
            final int thisByte = this.bytes[i] & 0xff;
            final int otherByte = other.bytes[i] & 0xff;
            if (thisByte > otherByte)
                return 1;
            if (thisByte < otherByte)
                return -1;
        }
        return 0;
    }
}
