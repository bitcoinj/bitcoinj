/*
 * Copyright 2011 Google Inc.
 * Copyright 2021 Andreas Schildbach
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

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * A variable-length encoded unsigned integer using Satoshi's encoding (a.k.a. "CompactSize").
 */
public class VarInt {
    private final long value;
    private final int originallyEncodedSize;

    private static final int SIZE_BYTE = Byte.BYTES; // 1 data byte
    private static final int SIZE_SHORT = Byte.BYTES + Short.BYTES; // 1 marker + 2 data bytes
    private static final int SIZE_INT = Byte.BYTES + Integer.BYTES; // 1 marker + 4 data bytes
    private static final int SIZE_LONG = Byte.BYTES + Long.BYTES; // 1 marker + 8 data bytes

    /**
     * Constructs a new VarInt with the given unsigned long value.
     *
     * @param value the unsigned long value (beware widening conversion of negatives!)
     */
    public static VarInt of(long value) {
        return new VarInt(value, sizeOf(value));
    }

    /**
     * Constructs a new VarInt with the value parsed from the specified offset of the given buffer.
     *
     * @param buf the buffer containing the value
     * @param offset the offset of the value
     * @throws ArrayIndexOutOfBoundsException if offset points outside of the buffer, or
     *                                        if the value doesn't fit the remaining buffer
     */
    public static VarInt ofBytes(byte[] buf, int offset) throws ArrayIndexOutOfBoundsException {
        check(offset >= 0 && offset < buf.length, () ->
                new ArrayIndexOutOfBoundsException(offset));
        return read(ByteBuffer.wrap(buf, offset, buf.length - offset));
    }

    /**
     * Constructs a new VarInt by reading from the given buffer.
     *
     * @param buf buffer to read from
     * @throws BufferUnderflowException if the read value extends beyond the remaining bytes of the buffer
     */
    public static VarInt read(ByteBuffer buf) throws BufferUnderflowException {
        buf.order(ByteOrder.LITTLE_ENDIAN);
        int first = Byte.toUnsignedInt(buf.get());
        long value;
        int originallyEncodedSize;
        if (first < 253) {
            value = first;
            originallyEncodedSize = SIZE_BYTE;
        } else if (first == 253) {
            value = Short.toUnsignedInt(buf.getShort());
            originallyEncodedSize = SIZE_SHORT;
        } else if (first == 254) {
            value = Integer.toUnsignedLong(buf.getInt());
            originallyEncodedSize = SIZE_INT;
        } else {
            value = buf.getLong();
            originallyEncodedSize = SIZE_LONG;
        }
        return new VarInt(value, originallyEncodedSize);
    }

    private VarInt(long value, int originallyEncodedSize) {
        this.value = value;
        this.originallyEncodedSize = originallyEncodedSize;
    }

    /** @deprecated use {@link #of(long)} */
    @Deprecated
    public VarInt(long value) {
        this.value = value;
        originallyEncodedSize = getSizeInBytes();
    }

    /** @deprecated use {@link #ofBytes(byte[], int)} */
    @Deprecated
    public VarInt(byte[] buf, int offset) {
        VarInt copy = read(ByteBuffer.wrap(buf, offset, buf.length));
        value = copy.value;
        originallyEncodedSize = copy.originallyEncodedSize;
    }

    /**
     * Gets the value as a long. For values greater than {@link Long#MAX_VALUE} the returned long
     * will be negative. It is still to be interpreted as an unsigned value.
     *
     * @return value as a long
     */
    public long longValue() {
        return value;
    }

    /**
     * Determine if the value would fit an int, i.e. it is in the range of {@code 0} to {@link Integer#MAX_VALUE}.
     * If this is true, it's safe to call {@link #intValue()}.
     *
     * @return true if the value fits an int, false otherwise
     */
    public boolean fitsInt() {
        return value >= 0 && value <= Integer.MAX_VALUE;
    }

    /**
     * Gets the value as an unsigned int in the range of {@code 0} to {@link Integer#MAX_VALUE}.
     *
     * @return value as an unsigned int
     * @throws ArithmeticException if the value doesn't fit an int
     */
    public int intValue() throws ArithmeticException {
        check(fitsInt(), () ->
                new ArithmeticException("value too large for an int: " + Long.toUnsignedString(value)));
        return (int) value;
    }

    /**
     * Returns the original number of bytes used to encode the value if it was
     * deserialized from a byte array, or the minimum encoded size if it was not.
     */
    public int getOriginalSizeInBytes() {
        return originallyEncodedSize;
    }

    /**
     * Returns the minimum encoded size of the value.
     */
    public final int getSizeInBytes() {
        return sizeOf(value);
    }

    /**
     * Returns the minimum encoded size of the given unsigned long value.
     *
     * @param value the unsigned long value (beware widening conversion of negatives!)
     */
    public static int sizeOf(long value) {
        // if negative, it's actually a very large unsigned long value
        if (value < 0) return SIZE_LONG;
        if (value < 253) return SIZE_BYTE;
        if (value <= 0xFFFFL) return SIZE_SHORT;
        if (value <= 0xFFFFFFFFL) return SIZE_INT;
        return SIZE_LONG;
    }

    /**
     * Allocates a byte array and serializes the value into its minimal representation.
     *
     * @return the minimal encoded bytes of the value
     */
    public byte[] serialize() {
        ByteBuffer buf = ByteBuffer.allocate(sizeOf(value));
        return write(buf).array();
    }

    /**
     * Write encoded value into the given buffer.
     *
     * @param buf buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the value doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        buf.order(ByteOrder.LITTLE_ENDIAN);
        switch (sizeOf(value)) {
            case 1:
                buf.put((byte) value);
                break;
            case 3:
                buf.put((byte) 253);
                buf.putShort((short) value);
                break;
            case 5:
                buf.put((byte) 254);
                buf.putInt((int) value);
                break;
            default:
                buf.put((byte) 255);
                buf.putLong(value);
                break;
        }
        return buf;
    }

    @Override
    public String toString() {
        return Long.toUnsignedString(value);
    }

    @Override
    public boolean equals(Object o) {
        // originallyEncodedSize is not considered on purpose
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return value == ((VarInt) o).value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
