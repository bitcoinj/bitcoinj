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

package org.bitcoinj.base.utils;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class ByteUtilsTest {

    @Test
    public void testReverseBytes() {
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, ByteUtils.reverseBytes(new byte[]{5, 4, 3, 2, 1}));
        assertArrayEquals(new byte[]{0}, ByteUtils.reverseBytes(new byte[]{0}));
        assertArrayEquals(new byte[]{}, ByteUtils.reverseBytes(new byte[]{}));
    }

    @Test
    public void compactEncoding() {
        assertEquals(new BigInteger("1234560000", 16), ByteUtils.decodeCompactBits(0x05123456L));
        assertEquals(new BigInteger("c0de000000", 16), ByteUtils.decodeCompactBits(0x0600c0de));
        assertEquals(0x05123456L, ByteUtils.encodeCompactBits(new BigInteger("1234560000", 16)));
        assertEquals(0x0600c0deL, ByteUtils.encodeCompactBits(new BigInteger("c0de000000", 16)));
        // UnitTest difficulty
        assertEquals(new BigInteger("7fffff0000000000000000000000000000000000000000000000000000000000", 16), ByteUtils.decodeCompactBits(0x207fFFFFL));
        assertEquals(0x207fFFFFL, ByteUtils.encodeCompactBits(new BigInteger("7fffff0000000000000000000000000000000000000000000000000000000000", 16)));
        // MainNet starting difficulty
        assertEquals(new BigInteger("00000000FFFF0000000000000000000000000000000000000000000000000000", 16), ByteUtils.decodeCompactBits(0x1d00ffffL));
        assertEquals(0x1d00ffffL, ByteUtils.encodeCompactBits(new BigInteger("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)));
    }

    @Test
    public void bigIntegerToBytes_roundTrip() {
        int ITERATIONS = 100;
        int LENGTH = 32;
        Random rnd = new Random();
        byte[] bytes = new byte[LENGTH];

        for (int i = 0; i < ITERATIONS; i++) {
            rnd.nextBytes(bytes);
            BigInteger bi = ByteUtils.bytesToBigInteger(bytes);
            assertArrayEquals(ByteUtils.HEX.encode(bytes), bytes, ByteUtils.bigIntegerToBytes(bi, LENGTH));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_convertNegativeNumber() {
        BigInteger b = BigInteger.valueOf(-1);
        ByteUtils.bigIntegerToBytes(b, 32);
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_convertWithNegativeLength() {
        BigInteger b = BigInteger.valueOf(10);
        ByteUtils.bigIntegerToBytes(b, -1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_convertWithZeroLength() {
        BigInteger b = BigInteger.valueOf(10);
        ByteUtils.bigIntegerToBytes(b, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_insufficientLength() {
        BigInteger b = BigInteger.valueOf(0b1000__0000_0000);   // base 2
        ByteUtils.bigIntegerToBytes(b, 1);
    }

    @Test
    public void bigIntegerToBytes_convertZero() {
        BigInteger b = BigInteger.valueOf(0);
        byte[] expected = new byte[]{0b0000_0000};
        byte[] actual = ByteUtils.bigIntegerToBytes(b, 1);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void bigIntegerToBytes_singleByteSignFit() {
        BigInteger b = BigInteger.valueOf(0b0000_1111);
        byte[] expected = new byte[]{0b0000_1111};
        byte[] actual = ByteUtils.bigIntegerToBytes(b, 1);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void bigIntegerToBytes_paddedSingleByte() {
        BigInteger b = BigInteger.valueOf(0b0000_1111);
        byte[] expected = new byte[]{0, 0b0000_1111};
        byte[] actual = ByteUtils.bigIntegerToBytes(b, 2);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void bigIntegerToBytes_singleByteSignDoesNotFit() {
        BigInteger b = BigInteger.valueOf(0b1000_0000);     // 128 (2-compl does not fit in one byte)
        byte[] expected = new byte[]{-128};                 // -128 == 1000_0000 (compl-2)
        byte[] actual = ByteUtils.bigIntegerToBytes(b, 1);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testReadUint16() {
        assertEquals(258L, ByteUtils.readUint16(new byte[]{2, 1}, 0));
        assertEquals(258L, ByteUtils.readUint16(new byte[]{2, 1, 3, 4}, 0));
        assertEquals(772L, ByteUtils.readUint16(new byte[]{1, 2, 4, 3}, 2));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint16ThrowsException1() {
        ByteUtils.readUint16(new byte[]{1}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint16ThrowsException2() {
        ByteUtils.readUint16(new byte[]{1, 2, 3}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint16ThrowsException3() {
        ByteUtils.readUint16(new byte[]{1, 2, 3}, -1);
    }

    @Test
    public void testReadUint32() {
        assertEquals(258L, ByteUtils.readUint32(new byte[]{2, 1, 0, 0}, 0));
        assertEquals(258L, ByteUtils.readUint32(new byte[]{2, 1, 0, 0, 3, 4}, 0));
        assertEquals(772L, ByteUtils.readUint32(new byte[]{1, 2, 4, 3, 0, 0}, 2));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint32ThrowsException1() {
        ByteUtils.readUint32(new byte[]{1, 2, 3}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint32ThrowsException2() {
        ByteUtils.readUint32(new byte[]{1, 2, 3, 4, 5}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint32ThrowsException3() {
        ByteUtils.readUint32(new byte[]{1, 2, 3, 4, 5}, -1);
    }

    @Test
    public void testReadInt64() {
        assertEquals(258L, ByteUtils.readInt64(new byte[]{2, 1, 0, 0, 0, 0, 0, 0}, 0));
        assertEquals(258L, ByteUtils.readInt64(new byte[]{2, 1, 0, 0, 0, 0, 0, 0, 3, 4}, 0));
        assertEquals(772L, ByteUtils.readInt64(new byte[]{1, 2, 4, 3, 0, 0, 0, 0, 0, 0}, 2));
        assertEquals(-1L, ByteUtils.readInt64(new byte[]{-1, -1, -1, -1, -1, -1, -1, -1}, 0));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadInt64ThrowsException1() {
        ByteUtils.readInt64(new byte[]{1, 2, 3, 4, 5, 6, 7}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadInt64ThrowsException2() {
        ByteUtils.readInt64(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadInt64ThrowsException3() {
        ByteUtils.readInt64(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9}, -1);
    }

    @Test
    public void testReadUInt32BE() {
        assertEquals(258L, ByteUtils.readUint32BE(new byte[]{0, 0, 1, 2}, 0));
        assertEquals(258L, ByteUtils.readUint32BE(new byte[]{0, 0, 1, 2, 3, 4}, 0));
        assertEquals(772L, ByteUtils.readUint32BE(new byte[]{1, 2, 0, 0, 3, 4}, 2));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint32BEThrowsException1() {
        ByteUtils.readUint32BE(new byte[]{1, 2, 3}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint32BEThrowsException2() {
        ByteUtils.readUint32BE(new byte[]{1, 2, 3, 4, 5}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint32BEThrowsException3() {
        ByteUtils.readUint32BE(new byte[]{1, 2, 3, 4, 5}, -1);
    }

    @Test
    public void testReadUint16BE() {
        assertEquals(258L, ByteUtils.readUint16BE(new byte[]{1, 2}, 0));
        assertEquals(258L, ByteUtils.readUint16BE(new byte[]{1, 2, 3, 4}, 0));
        assertEquals(772L, ByteUtils.readUint16BE(new byte[]{0, 0, 3, 4}, 2));
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint16BEThrowsException1() {
        ByteUtils.readUint16BE(new byte[]{1}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint16BEThrowsException2() {
        ByteUtils.readUint16BE(new byte[]{1, 2, 3}, 2);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testReadUint16BEThrowsException3() {
        ByteUtils.readUint16BE(new byte[]{1, 2, 3}, -1);
    }

    @Test
    public void testDecodeMPI() {
        assertEquals(BigInteger.ZERO, ByteUtils.decodeMPI(new byte[]{}, false));
    }
}
