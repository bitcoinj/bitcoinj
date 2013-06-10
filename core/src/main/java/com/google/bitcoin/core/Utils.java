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

import com.google.common.primitives.UnsignedLongs;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * A collection of various utility methods that are helpful for working with the Bitcoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
public class Utils {
    private static final MessageDigest digest;
    static {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    /** The string that prefixes all text messages signed using Bitcoin keys. */
    public static final String BITCOIN_SIGNED_MESSAGE_HEADER = "Bitcoin Signed Message:\n";

    // TODO: Replace this nanocoins business with something better.

    /**
     * How many "nanocoins" there are in a Bitcoin.
     * <p/>
     * A nanocoin is the smallest unit that can be transferred using Bitcoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion.
     */
    public static final BigInteger COIN = new BigInteger("100000000", 10);

    /**
     * How many "nanocoins" there are in 0.01 BitCoins.
     * <p/>
     * A nanocoin is the smallest unit that can be transferred using Bitcoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion).
     */
    public static final BigInteger CENT = new BigInteger("1000000", 10);

    /**
     * Convert an amount expressed in the way humans are used to into nanocoins.
     */
    public static BigInteger toNanoCoins(int coins, int cents) {
        checkArgument(cents < 100);
        BigInteger bi = BigInteger.valueOf(coins).multiply(COIN);
        bi = bi.add(BigInteger.valueOf(cents).multiply(CENT));
        return bi;
    }

    /**
     * The regular {@link java.math.BigInteger#toByteArray()} method isn't quite what we often need: it appends a
     * leading zero to indicate that the number is positive and may need padding.
     *
     * @param b the integer to format into a byte array
     * @param numBytes the desired size of the resulting byte array
     * @return numBytes byte long array.
     */
    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        if (b == null) {
            return null;
        }
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;        
    }

    /**
     * Convert an amount expressed in the way humans are used to into nanocoins.<p>
     * <p/>
     * This takes string in a format understood by {@link BigDecimal#BigDecimal(String)},
     * for example "0", "1", "0.10", "1.23E3", "1234.5E-5".
     *
     * @throws ArithmeticException if you try to specify fractional nanocoins
     */
    public static BigInteger toNanoCoins(String coins) {
        return new BigDecimal(coins).movePointRight(8).toBigIntegerExact();
    }

    public static void uint32ToByteArrayBE(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xFF & (val >> 24));
        out[offset + 1] = (byte) (0xFF & (val >> 16));
        out[offset + 2] = (byte) (0xFF & (val >> 8));
        out[offset + 3] = (byte) (0xFF & (val >> 0));
    }

    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xFF & (val >> 0));
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
    }

    public static void uint64ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xFF & (val >> 0));
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
        out[offset + 4] = (byte) (0xFF & (val >> 32));
        out[offset + 5] = (byte) (0xFF & (val >> 40));
        out[offset + 6] = (byte) (0xFF & (val >> 48));
        out[offset + 7] = (byte) (0xFF & (val >> 56));
    }

    public static void uint32ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 0)));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
    }
    
    public static void int64ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 0)));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
        stream.write((int) (0xFF & (val >> 32)));
        stream.write((int) (0xFF & (val >> 40)));
        stream.write((int) (0xFF & (val >> 48)));
        stream.write((int) (0xFF & (val >> 56)));
    }

    public static void uint64ToByteStreamLE(BigInteger val, OutputStream stream) throws IOException {
        byte[] bytes = val.toByteArray();
        if (bytes.length > 8) {
            throw new RuntimeException("Input too large to encode into a uint64");
        }
        bytes = reverseBytes(bytes);
        stream.write(bytes);
        if (bytes.length < 8) {
            for (int i = 0; i < 8 - bytes.length; i++)
                stream.write(0);
        }
    }

    /**
     * See {@link Utils#doubleDigest(byte[], int, int)}.
     */
    public static byte[] doubleDigest(byte[] input) {
        return doubleDigest(input, 0, input.length);
    }

    /**
     * Calculates the SHA-256 hash of the given byte range, and then hashes the resulting hash again. This is
     * standard procedure in Bitcoin. The resulting hash is in big endian form.
     */
    public static byte[] doubleDigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    public static byte[] singleDigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            return digest.digest();
        }
    }

    /**
     * Calculates SHA256(SHA256(byte range 1 + byte range 2)).
     */
    public static byte[] doubleDigestTwoBuffers(byte[] input1, int offset1, int length1,
                                                byte[] input2, int offset2, int length2) {
        synchronized (digest) {
            digest.reset();
            digest.update(input1, offset1, length1);
            digest.update(input2, offset2, length2);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    /**
     * Work around lack of unsigned types in Java.
     */
    public static boolean isLessThanUnsigned(long n1, long n2) {
        return UnsignedLongs.compare(n1, n2) < 0;
    }

    /**
     * Returns the given byte array hex encoded.
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuffer buf = new StringBuffer(bytes.length * 2);
        for (byte b : bytes) {
            String s = Integer.toString(0xFF & b, 16);
            if (s.length() < 2)
                buf.append('0');
            buf.append(s);
        }
        return buf.toString();
    }


    /**
     * Returns a copy of the given byte array in reverse order.
     */
    public static byte[] reverseBytes(byte[] bytes) {
        // We could use the XOR trick here but it's easier to understand if we don't. If we find this is really a
        // performance issue the matter can be revisited.
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }
    
    /**
     * Returns a copy of the given byte array with the bytes of each double-word (4 bytes) reversed.
     * 
     * @param bytes length must be divisible by 4.
     * @param trimLength trim output to this length.  If positive, must be divisible by 4.
     */
    public static byte[] reverseDwordBytes(byte[] bytes, int trimLength) {
        checkArgument(bytes.length % 4 == 0);
        checkArgument(trimLength < 0 || trimLength % 4 == 0);
        
        byte[] rev = new byte[trimLength >= 0 && bytes.length > trimLength ? trimLength : bytes.length];
        
        for (int i = 0; i < rev.length; i += 4) {
            System.arraycopy(bytes, i, rev, i , 4);
            for (int j = 0; j < 4; j++) {
                rev[i + j] = bytes[i + 3 - j];
            }
        }
        return rev;
}

    public static long readUint32(byte[] bytes, int offset) {
        return ((bytes[offset++] & 0xFFL) << 0) |
                ((bytes[offset++] & 0xFFL) << 8) |
                ((bytes[offset++] & 0xFFL) << 16) |
                ((bytes[offset] & 0xFFL) << 24);
    }
    
    public static long readInt64(byte[] bytes, int offset) {
        return ((bytes[offset++] & 0xFFL) << 0) |
               ((bytes[offset++] & 0xFFL) << 8) |
               ((bytes[offset++] & 0xFFL) << 16) |
               ((bytes[offset++] & 0xFFL) << 24) |
               ((bytes[offset++] & 0xFFL) << 32) |
               ((bytes[offset++] & 0xFFL) << 40) |
               ((bytes[offset++] & 0xFFL) << 48) |
               ((bytes[offset] & 0xFFL) << 56);
    }

    public static long readUint32BE(byte[] bytes, int offset) {
        return ((bytes[offset + 0] & 0xFFL) << 24) |
                ((bytes[offset + 1] & 0xFFL) << 16) |
                ((bytes[offset + 2] & 0xFFL) << 8) |
                ((bytes[offset + 3] & 0xFFL) << 0);
    }

    public static int readUint16BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | bytes[offset + 1] & 0xff;
    }

    /**
     * Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
     */
    public static byte[] sha256hash160(byte[] input) {
        try {
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(input);
            RIPEMD160Digest digest = new RIPEMD160Digest();
            digest.update(sha256, 0, sha256.length);
            byte[] out = new byte[20];
            digest.doFinal(out, 0);
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Returns the given value in nanocoins as a 0.12 type string. More digits after the decimal place will be used
     * if necessary, but two will always be present.
     */
    public static String bitcoinValueToFriendlyString(BigInteger value) {
        // TODO: This API is crap. This method should go away when we encapsulate money values.
        boolean negative = value.compareTo(BigInteger.ZERO) < 0;
        if (negative)
            value = value.negate();
        BigDecimal bd = new BigDecimal(value, 8);
        String formatted = bd.toPlainString();   // Don't use scientific notation.
        int decimalPoint = formatted.indexOf(".");
        // Drop unnecessary zeros from the end.
        int toDelete = 0;
        for (int i = formatted.length() - 1; i > decimalPoint + 2; i--) {
            if (formatted.charAt(i) == '0')
                toDelete++;
            else
                break;
        }
        return (negative ? "-" : "") + formatted.substring(0, formatted.length() - toDelete);
    }
    
    /**
     * <p>
     * Returns the given value as a plain string denominated in BTC.   
     * The result is unformatted with no trailing zeroes.
     * For instance, an input value of BigInteger.valueOf(150000) nanocoin gives an output string of "0.0015" BTC
     * </p>
     * 
     * @param value The value in nanocoins to convert to a string (denominated in BTC)
     * @throws IllegalArgumentException
     *            If the input value is null
     */
    public static String bitcoinValueToPlainString(BigInteger value) {
        if (value == null) {
            throw new IllegalArgumentException("Value cannot be null");
        }
                
        BigDecimal valueInBTC = new BigDecimal(value).divide(new BigDecimal(Utils.COIN));
        return valueInBTC.toPlainString();
    }

    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     * @param hasLength can be set to false if the given array is missing the 4 byte length field
     */
    public static BigInteger decodeMPI(byte[] mpi, boolean hasLength) {
        byte[] buf;
        if (hasLength) {
            int length = (int) readUint32BE(mpi, 0);
            buf = new byte[length];
            System.arraycopy(mpi, 4, buf, 0, length);
        } else
            buf = mpi;
        if (buf.length == 0)
            return BigInteger.ZERO;
        boolean isNegative = (buf[0] & 0x80) == 0x80;
        if (isNegative)
            buf[0] &= 0x7f;
        BigInteger result = new BigInteger(buf);
        return isNegative ? result.negate() : result;
    }
    
    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     * @param includeLength indicates whether the 4 byte length field should be included
     */
    public static byte[] encodeMPI(BigInteger value, boolean includeLength) {
        if (value.equals(BigInteger.ZERO)) {
            if (!includeLength)
                return new byte[] {};
            else
                return new byte[] {0x00, 0x00, 0x00, 0x00};
        }
        boolean isNegative = value.compareTo(BigInteger.ZERO) < 0;
        if (isNegative)
            value = value.negate();
        byte[] array = value.toByteArray();
        int length = array.length;
        if ((array[0] & 0x80) == 0x80)
            length++;
        if (includeLength) {
            byte[] result = new byte[length + 4];
            System.arraycopy(array, 0, result, length - array.length + 3, array.length);
            uint32ToByteArrayBE(length, result, 0);
            if (isNegative)
                result[4] |= 0x80;
            return result;
        } else {
            byte[] result;
            if (length != array.length) {
                result = new byte[length];
                System.arraycopy(array, 0, result, 1, array.length);
            }else
                result = array;
            if (isNegative)
                result[0] |= 0x80;
            return result;
        }
    }

    // The representation of nBits uses another home-brew encoding, as a way to represent a large
    // hash value in only 32 bits.
    public static BigInteger decodeCompactBits(long compact) {
        int size = ((int) (compact >> 24)) & 0xFF;
        byte[] bytes = new byte[4 + size];
        bytes[3] = (byte) size;
        if (size >= 1) bytes[4] = (byte) ((compact >> 16) & 0xFF);
        if (size >= 2) bytes[5] = (byte) ((compact >> 8) & 0xFF);
        if (size >= 3) bytes[6] = (byte) ((compact >> 0) & 0xFF);
        return decodeMPI(bytes, true);
    }

    /**
     * If non-null, overrides the return value of now().
     */
    public static volatile Date mockTime;

    /**
     * Advances (or rewinds) the mock clock by the given number of seconds.
     */
    public static Date rollMockClock(int seconds) {
        if (mockTime == null)
            mockTime = new Date();
        mockTime = new Date(mockTime.getTime() + (seconds * 1000));
        return mockTime;
    }

    /**
     * Sets the mock clock to the given time (in seconds)
     * @param mockClock
     */
    public static void setMockClock(long mockClock) {
        mockTime = new Date(mockClock * 1000);
    }

    /**
     * Returns the current time, or a mocked out equivalent.
     */
    public static Date now() {
        if (mockTime != null)
            return mockTime;
        else
            return new Date();
    }
    
    public static byte[] copyOf(byte[] in, int length) {
        byte[] out = new byte[length];
        System.arraycopy(in, 0, out, 0, Math.min(length, in.length));
        return out;
    }

    /**
     * Creates a copy of bytes and appends b to the end of it
     */
    public static byte[] appendByte(byte[] bytes, byte b) {
        byte[] result = Arrays.copyOf(bytes, bytes.length + 1);
        result[result.length - 1] = b;
        return result;
    }

    /**
     * Attempts to parse the given string as arbitrary-length hex or base58 and then return the results, or null if
     * neither parse was successful.
     */
    public static byte[] parseAsHexOrBase58(String data) {
        try {
            return Hex.decode(data);
        } catch (Exception e) {
            // Didn't decode as hex, try base58.
            try {
                return Base58.decodeChecked(data);
            } catch (AddressFormatException e1) {
                return null;
            }
        }
    }

    public static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    /**
     * <p>Given a textual message, returns a byte buffer formatted as follows:</p>
     *
     * <tt><p>[24] "Bitcoin Signed Message:\n" [message.length as a varint] message</p></tt>
     */
    public static byte[] formatMessageForSigning(String message) {
        VarInt size = new VarInt(message.length());
        int totalSize = 1 + BITCOIN_SIGNED_MESSAGE_HEADER.length() + size.getSizeInBytes() + message.length();
        byte[] result = new byte[totalSize];
        int cursor = 0;
        result[cursor++] = (byte) BITCOIN_SIGNED_MESSAGE_HEADER.length();
        byte[] bytes = BITCOIN_SIGNED_MESSAGE_HEADER.getBytes(Charset.forName("UTF-8"));
        System.arraycopy(bytes, 0, result, cursor, bytes.length);
        cursor += bytes.length;
        bytes = size.encode();
        System.arraycopy(bytes, 0, result, cursor, bytes.length);
        cursor += bytes.length;
        bytes = message.getBytes(Charset.forName("UTF-8"));
        System.arraycopy(bytes, 0, result, cursor, bytes.length);
        return result;
    }
    
    // 00000001, 00000010, 00000100, 00001000, ...
    private static final int bitMask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    
    // Checks if the given bit is set in data
    public static boolean checkBitLE(byte[] data, int index) {
        return (data[index >>> 3] & bitMask[7 & index]) != 0;
    }
    
    // Sets the given bit in data to one
    public static void setBitLE(byte[] data, int index) {
        data[index >>> 3] |= bitMask[7 & index];
    }
}
