/**
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;

import static com.google.bitcoin.core.Utils.isLessThanUnsigned;

public class VarInt {
    public final long value;

    public VarInt(long value) {
        this.value = value;
    }

    // BitCoin has its own varint format, known in the C++ source as "compact size".
    public VarInt(byte[] buf, int offset) {
        int first = 0xFF & buf[offset];
        long val;
        if (first < 253) {
            // 8 bits.
            val = first;
        } else if (first == 253) {
            // 16 bits.
            val = (0xFF & buf[offset + 1]) | ((0xFF & buf[offset + 2]) << 8);
        } else if (first == 254) {
            // 32 bits.
            val = Utils.readUint32(buf, offset + 1);
        } else {
            // 64 bits.
            val = Utils.readUint32(buf, offset + 1) | (Utils.readUint32(buf, offset + 5) << 32);
        }
        this.value = val;
    }

    public int getSizeInBytes() {
        return sizeOf(value);
    }

    public static int sizeOf(int value) {
        // Java doesn't have the actual value of MAX_INT, as all types in Java are signed.
        if (value < 253)
            return 1;
        else if (value < 65536)
            return 3;  // 1 marker + 2 data bytes
        return 5;  // 1 marker + 4 data bytes
    }

    public static int sizeOf(long value) {
        // Java doesn't have the actual value of MAX_INT, as all types in Java are signed.
        if (isLessThanUnsigned(value, 253))
            return 1;
        else if (isLessThanUnsigned(value, 65536))
            return 3;  // 1 marker + 2 data bytes
        else if (isLessThanUnsigned(value, 4294967296L))
            return 5;  // 1 marker + 4 data bytes
        else
            return 9;  // 1 marker + 8 data bytes
    }

    public byte[] encode() {
        return encodeBE();
    }


    public byte[] encodeBE() {
        if (isLessThanUnsigned(value, 253)) {
            return new byte[]{(byte) value};
        } else if (isLessThanUnsigned(value, 65536)) {
            return new byte[]{(byte) 253, (byte) (value), (byte) (value >> 8)};
        } else if (isLessThanUnsigned(value, 4294967295L)) {
            byte[] bytes = new byte[5];
            bytes[0] = (byte) 254;
            Utils.uint32ToByteArrayLE(value, bytes, 1);
            return bytes;
        } else {
            byte[] bytes = new byte[9];
            bytes[0] = (byte) 255;
            Utils.uint32ToByteArrayLE(value, bytes, 1);
            Utils.uint32ToByteArrayLE(value >>> 32, bytes, 5);
            return bytes;
        }
    }
}
