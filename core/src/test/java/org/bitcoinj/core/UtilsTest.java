/*
 * Copyright 2011 Thilo Planz
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Nicola Atzei
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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

import org.junit.Test;

import static org.junit.Assert.*;

public class UtilsTest {

    @Test
    public void testReverseBytes() {
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, Utils.reverseBytes(new byte[]{5, 4, 3, 2, 1}));
    }

    @Test
    public void compactEncoding() throws Exception {
        assertEquals(new BigInteger("1234560000", 16), Utils.decodeCompactBits(0x05123456L));
        assertEquals(new BigInteger("c0de000000", 16), Utils.decodeCompactBits(0x0600c0de));
        assertEquals(0x05123456L, Utils.encodeCompactBits(new BigInteger("1234560000", 16)));
        assertEquals(0x0600c0deL, Utils.encodeCompactBits(new BigInteger("c0de000000", 16)));
    }

    @Test
    public void dateTimeFormat() {
        assertEquals("2014-11-16T10:54:33Z", Utils.dateTimeFormat(1416135273781L));
        assertEquals("2014-11-16T10:54:33Z", Utils.dateTimeFormat(new Date(1416135273781L)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_convertNegativeNumber() {
        BigInteger b = BigInteger.valueOf(-1);
        Utils.bigIntegerToBytes(b, 32);
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_convertWithNegativeLength() {
        BigInteger b = BigInteger.valueOf(10);
        Utils.bigIntegerToBytes(b, -1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_convertWithZeroLength() {
        BigInteger b = BigInteger.valueOf(10);
        Utils.bigIntegerToBytes(b, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void bigIntegerToBytes_insufficientLength() {
        BigInteger b = BigInteger.valueOf(0b1000__0000_0000);   // base 2
        Utils.bigIntegerToBytes(b, 1);
    }

    @Test
    public void bigIntegerToBytes_convertZero() {
        BigInteger b = BigInteger.valueOf(0);
        byte[] expected = new byte[]{0b0000_0000};
        byte[] actual = Utils.bigIntegerToBytes(b, 1);
        assertTrue(Arrays.equals(expected, actual));
    }

    @Test
    public void bigIntegerToBytes_singleByteSignFit() {
        BigInteger b = BigInteger.valueOf(0b0000_1111);
        byte[] expected = new byte[]{0b0000_1111};
        byte[] actual = Utils.bigIntegerToBytes(b, 1);
        assertTrue(Arrays.equals(expected, actual));
    }

    @Test
    public void bigIntegerToBytes_paddedSingleByte() {
        BigInteger b = BigInteger.valueOf(0b0000_1111);
        byte[] expected = new byte[]{0, 0b0000_1111};
        byte[] actual = Utils.bigIntegerToBytes(b, 2);
        assertTrue(Arrays.equals(expected, actual));
    }

    @Test
    public void bigIntegerToBytes_singleByteSignDoesNotFit() {
        BigInteger b = BigInteger.valueOf(0b1000_0000);     // 128 (2-compl does not fit in one byte)
        byte[] expected = new byte[]{-128};                 // -128 == 1000_0000 (compl-2)
        byte[] actual = Utils.bigIntegerToBytes(b, 1);
        assertTrue(Arrays.equals(expected, actual));
    }

    @Test
    public void runtime() {
        // This test assumes it is run within a Java runtime for desktop computers.
        assertTrue(Utils.isOpenJDKRuntime() || Utils.isOracleJavaRuntime());
        assertFalse(Utils.isAndroidRuntime());
    }
}
