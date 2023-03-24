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

import org.bitcoinj.base.internal.ByteUtils;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * A variable-length encoded unsigned integer using Satoshi's encoding (a.k.a. "CompactSize").
 */
public class VarInt {
    private final long value;
    private final int originallyEncodedSize;

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
        int first = Byte.toUnsignedInt(buf.get());
        long value;
        int originallyEncodedSize;
        if (first < 253) {
            value = first;
            originallyEncodedSize = 1; // 1 data byte (8 bits)
        } else if (first == 253) {
            value = ByteUtils.readUint16(buf);
            originallyEncodedSize = 3; // 1 marker + 2 data bytes (16 bits)
        } else if (first == 254) {
            value = ByteUtils.readUint32(buf);
            originallyEncodedSize = 5; // 1 marker + 4 data bytes (32 bits)
        } else {
            value = ByteUtils.readInt64(buf);
            originallyEncodedSize = 9; // 1 marker + 8 data bytes (64 bits)
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
        int first = 0xFF & buf[offset];
        if (first < 253) {
            value = first;
            originallyEncodedSize = 1; // 1 data byte (8 bits)
        } else if (first == 253) {
            value = ByteUtils.readUint16(buf, offset + 1);
            originallyEncodedSize = 3; // 1 marker + 2 data bytes (16 bits)
        } else if (first == 254) {
            value = ByteUtils.readUint32(buf, offset + 1);
            originallyEncodedSize = 5; // 1 marker + 4 data bytes (32 bits)
        } else {
            value = ByteUtils.readInt64(buf, offset + 1);
            originallyEncodedSize = 9; // 1 marker + 8 data bytes (64 bits)
        }
    }

    public long longValue() {
        return value;
    }

    public int intValue() {
        return Math.toIntExact(value);
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
        if (value < 0) return 9; // 1 marker + 8 data bytes
        if (value < 253) return 1; // 1 data byte
        if (value <= 0xFFFFL) return 3; // 1 marker + 2 data bytes
        if (value <= 0xFFFFFFFFL) return 5; // 1 marker + 4 data bytes
        return 9; // 1 marker + 8 data bytes
    }

    /**
     * Encodes the value into its minimal representation.
     *
     * @return the minimal encoded bytes of the value
     */
    public byte[] encode() {
        byte[] bytes = new byte[sizeOf(value)];
        write(ByteBuffer.wrap(bytes));
        return bytes;
    }

    /**
     * Write encoded value into the given buffer.
     *
     * @param buf buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the value doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        switch (sizeOf(value)) {
            case 1:
                buf.put((byte) value);
                break;
            case 3:
                buf.put((byte) 253);
                ByteUtils.writeInt16LE((int) value, buf);
                break;
            case 5:
                buf.put((byte) 254);
                ByteUtils.writeInt32LE(value, buf);
                break;
            default:
                buf.put((byte) 255);
                ByteUtils.writeInt64LE(value, buf);
                break;
        }
        return buf;
    }
}
