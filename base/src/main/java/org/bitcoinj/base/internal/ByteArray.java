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

package org.bitcoinj.base.internal;

import java.util.Arrays;

/**
 * An effectively-immutable byte array.
 */
public class ByteArray implements Comparable<ByteArray> {
    protected final byte[] bytes;

    /**
     * Wrapper for a {@code byte[]}
     * @param bytes byte data to wrap
     */
    public ByteArray(byte[] bytes) {
        // Make defensive copy, so we are effectively immutable
        this.bytes = new byte[bytes.length];
        System.arraycopy(bytes, 0, this.bytes, 0, bytes.length);
    }

    /**
     * @return the key bytes
     */
    public byte[] bytes() {
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }

    /**
     * @return the bytes as a hex-formatted string
     */
    public String formatHex() {
        return ByteUtils.formatHex(bytes);
    }

    /**
     * {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /**
     * {@inheritDoc}
     * @param o {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ByteArray other = (ByteArray) o;
        return Arrays.equals(this.bytes, other.bytes);
    }

    /**
     * {@inheritDoc}
     * <p>For {@link ByteArray} this is a byte-by-byte, unsigned comparison.
     * @param o {@inheritDoc}
     * @return {@inheritDoc}
     */
    @Override
    public int compareTo(ByteArray o) {
        return ByteUtils.arrayUnsignedComparator().compare(bytes, o.bytes);
    }
}
