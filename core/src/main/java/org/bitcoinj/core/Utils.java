/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.spongycastle.crypto.digests.RIPEMD160Digest;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.common.collect.Ordering;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Ints;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly;

/**
 * A collection of various utility methods that are helpful for working with the Bitcoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
public class Utils {

    /** Joiner for concatenating words with a space inbetween. */
    public static final Joiner SPACE_JOINER = Joiner.on(" ");
    /** Splitter for splitting words on whitespaces. */
    public static final Splitter WHITESPACE_SPLITTER = Splitter.on(Pattern.compile("\\s+"));
    /** Hex encoding used throughout the framework. Use with HEX.encode(byte[]) or HEX.decode(CharSequence). */
    public static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

    /**
     * Max initial size of variable length arrays and ArrayLists that could be attacked.
     * Avoids this attack: Attacker sends a msg indicating it will contain a huge number (eg 2 billion) elements (eg transaction inputs) and
     * forces bitcoinj to try to allocate a huge piece of the memory resulting in OutOfMemoryError.
    */
    public static final int MAX_INITIAL_ARRAY_LENGTH = 20;

    private static BlockingQueue<Boolean> mockSleepQueue;

    /**
     * <p>
     * The regular {@link BigInteger#toByteArray()} includes the sign bit of the number and
     * might result in an extra byte addition. This method removes this extra byte.
     * </p>
     * <p>
     * Assuming only positive numbers, it's possible to discriminate if an extra byte
     * is added by checking if the first element of the array is 0 (0000_0000).
     * Due to the minimal representation provided by BigInteger, it means that the bit sign
     * is the least significant bit 0000_000<b>0</b> .
     * Otherwise the representation is not minimal.
     * For example, if the sign bit is 0000_00<b>0</b>0, then the representation is not minimal due to the rightmost zero.
     * </p>
     * @param b the integer to format into a byte array
     * @param numBytes the desired size of the resulting byte array
     * @return numBytes byte long array.
     */
    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        checkArgument(b.signum() >= 0, "b must be positive or zero");
        checkArgument(numBytes > 0, "numBytes must be positive");
        byte[] src = b.toByteArray();
        byte[] dest = new byte[numBytes];
        boolean isFirstByteOnlyForSign = src[0] == 0;
        int length = isFirstByteOnlyForSign ? src.length - 1 : src.length;
        checkArgument(length <= numBytes, "The given number does not fit in " + numBytes);
        int srcPos = isFirstByteOnlyForSign ? 1 : 0;
        int destPos = numBytes - length;
        System.arraycopy(src, srcPos, dest, destPos, length);
        return dest;
    }

    /** Write 2 bytes to the byte array (starting at the offset) as unsigned 16-bit integer in little endian format. */
    public static void uint16ToByteArrayLE(int val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
    }

    /** Write 4 bytes to the byte array (starting at the offset) as unsigned 32-bit integer in little endian format. */
    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
    }

    /** Write 4 bytes to the byte array (starting at the offset) as unsigned 32-bit integer in big endian format. */
    public static void uint32ToByteArrayBE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & (val >> 24));
        out[offset + 1] = (byte) (0xFF & (val >> 16));
        out[offset + 2] = (byte) (0xFF & (val >> 8));
        out[offset + 3] = (byte) (0xFF & val);
    }

    /** Write 8 bytes to the byte array (starting at the offset) as signed 64-bit integer in little endian format. */
    public static void int64ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
        out[offset + 4] = (byte) (0xFF & (val >> 32));
        out[offset + 5] = (byte) (0xFF & (val >> 40));
        out[offset + 6] = (byte) (0xFF & (val >> 48));
        out[offset + 7] = (byte) (0xFF & (val >> 56));
    }

    /** Write 2 bytes to the output stream as unsigned 16-bit integer in little endian format. */
    public static void uint16ToByteStreamLE(int val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
    }

    /** Write 2 bytes to the output stream as unsigned 16-bit integer in big endian format. */
    public static void uint16ToByteStreamBE(int val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & val));
    }

    /** Write 4 bytes to the output stream as unsigned 32-bit integer in little endian format. */
    public static void uint32ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
    }

    /** Write 4 bytes to the output stream as unsigned 32-bit integer in big endian format. */
    public static void uint32ToByteStreamBE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 24)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & val));
    }

    /** Write 8 bytes to the output stream as signed 64-bit integer in little endian format. */
    public static void int64ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
        stream.write((int) (0xFF & (val >> 32)));
        stream.write((int) (0xFF & (val >> 40)));
        stream.write((int) (0xFF & (val >> 48)));
        stream.write((int) (0xFF & (val >> 56)));
    }

    /** Write 8 bytes to the output stream as unsigned 64-bit integer in little endian format. */
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

    /** Parse 2 bytes from the byte array (starting at the offset) as unsigned 16-bit integer in little endian format. */
    public static int readUint16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) |
                ((bytes[offset + 1] & 0xff) << 8);
    }

    /** Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in little endian format. */
    public static long readUint32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffl) |
                ((bytes[offset + 1] & 0xffl) << 8) |
                ((bytes[offset + 2] & 0xffl) << 16) |
                ((bytes[offset + 3] & 0xffl) << 24);
    }

    /** Parse 8 bytes from the byte array (starting at the offset) as signed 64-bit integer in little endian format. */
    public static long readInt64(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffl) |
               ((bytes[offset + 1] & 0xffl) << 8) |
               ((bytes[offset + 2] & 0xffl) << 16) |
               ((bytes[offset + 3] & 0xffl) << 24) |
               ((bytes[offset + 4] & 0xffl) << 32) |
               ((bytes[offset + 5] & 0xffl) << 40) |
               ((bytes[offset + 6] & 0xffl) << 48) |
               ((bytes[offset + 7] & 0xffl) << 56);
    }

    /** Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in big endian format. */
    public static long readUint32BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xffl) << 24) |
                ((bytes[offset + 1] & 0xffl) << 16) |
                ((bytes[offset + 2] & 0xffl) << 8) |
                (bytes[offset + 3] & 0xffl);
    }

    /** Parse 2 bytes from the byte array (starting at the offset) as unsigned 16-bit integer in big endian format. */
    public static int readUint16BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) |
                (bytes[offset + 1] & 0xff);
    }

    /** Parse 2 bytes from the stream as unsigned 16-bit integer in little endian format. */
    public static int readUint16FromStream(InputStream is) {
        try {
            return (is.read() & 0xff) |
                    ((is.read() & 0xff) << 8);
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    /** Parse 4 bytes from the stream as unsigned 32-bit integer in little endian format. */
    public static long readUint32FromStream(InputStream is) {
        try {
            return (is.read() & 0xffl) |
                    ((is.read() & 0xffl) << 8) |
                    ((is.read() & 0xffl) << 16) |
                    ((is.read() & 0xffl) << 24);
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
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
     * Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
     */
    public static byte[] sha256hash160(byte[] input) {
        byte[] sha256 = Sha256Hash.hash(input);
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256, 0, sha256.length);
        byte[] out = new byte[20];
        digest.doFinal(out, 0);
        return out;
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
        boolean isNegative = value.signum() < 0;
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

    /**
     * <p>The "compact" format is a representation of a whole number N using an unsigned 32 bit number similar to a
     * floating point format. The most significant 8 bits are the unsigned exponent of base 256. This exponent can
     * be thought of as "number of bytes of N". The lower 23 bits are the mantissa. Bit number 24 (0x800000) represents
     * the sign of N. Therefore, N = (-1^sign) * mantissa * 256^(exponent-3).</p>
     *
     * <p>Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn(). MPI uses the most significant bit of the
     * first byte as sign. Thus 0x1234560000 is compact 0x05123456 and 0xc0de000000 is compact 0x0600c0de. Compact
     * 0x05c0de00 would be -0x40de000000.</p>
     *
     * <p>Bitcoin only uses this "compact" format for encoding difficulty targets, which are unsigned 256bit quantities.
     * Thus, all the complexities of the sign bit and using base 256 are probably an implementation accident.</p>
     */
    public static BigInteger decodeCompactBits(long compact) {
        int size = ((int) (compact >> 24)) & 0xFF;
        byte[] bytes = new byte[4 + size];
        bytes[3] = (byte) size;
        if (size >= 1) bytes[4] = (byte) ((compact >> 16) & 0xFF);
        if (size >= 2) bytes[5] = (byte) ((compact >> 8) & 0xFF);
        if (size >= 3) bytes[6] = (byte) (compact & 0xFF);
        return decodeMPI(bytes, true);
    }

    /**
     * @see Utils#decodeCompactBits(long)
     */
    public static long encodeCompactBits(BigInteger value) {
        long result;
        int size = value.toByteArray().length;
        if (size <= 3)
            result = value.longValue() << 8 * (3 - size);
        else
            result = value.shiftRight(8 * (size - 3)).longValue();
        // The 0x00800000 bit denotes the sign.
        // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
        if ((result & 0x00800000L) != 0) {
            result >>= 8;
            size++;
        }
        result |= size << 24;
        result |= value.signum() == -1 ? 0x00800000 : 0;
        return result;
    }

    /**
     * If non-null, overrides the return value of now().
     */
    public static volatile Date mockTime;

    /**
     * Advances (or rewinds) the mock clock by the given number of seconds.
     */
    public static Date rollMockClock(int seconds) {
        return rollMockClockMillis(seconds * 1000);
    }

    /**
     * Advances (or rewinds) the mock clock by the given number of milliseconds.
     */
    public static Date rollMockClockMillis(long millis) {
        if (mockTime == null)
            throw new IllegalStateException("You need to use setMockClock() first.");
        mockTime = new Date(mockTime.getTime() + millis);
        return mockTime;
    }

    /**
     * Sets the mock clock to the current time.
     */
    public static void setMockClock() {
        mockTime = new Date();
    }

    /**
     * Sets the mock clock to the given time (in seconds).
     */
    public static void setMockClock(long mockClockSeconds) {
        mockTime = new Date(mockClockSeconds * 1000);
    }

    /**
     * Returns the current time, or a mocked out equivalent.
     */
    public static Date now() {
        return mockTime != null ? mockTime : new Date();
    }

    // TODO: Replace usages of this where the result is / 1000 with currentTimeSeconds.
    /** Returns the current time in milliseconds since the epoch, or a mocked out equivalent. */
    public static long currentTimeMillis() {
        return mockTime != null ? mockTime.getTime() : System.currentTimeMillis();
    }

    public static long currentTimeSeconds() {
        return currentTimeMillis() / 1000;
    }

    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    /**
     * Formats a given date+time value to an ISO 8601 string.
     * @param dateTime value to format, as a Date
     */
    public static String dateTimeFormat(Date dateTime) {
        DateFormat iso8601 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        iso8601.setTimeZone(UTC);
        return iso8601.format(dateTime);
    }

    /**
     * Formats a given date+time value to an ISO 8601 string.
     * @param dateTime value to format, unix time (ms)
     */
    public static String dateTimeFormat(long dateTime) {
        DateFormat iso8601 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        iso8601.setTimeZone(UTC);
        return iso8601.format(dateTime);
    }

    // 00000001, 00000010, 00000100, 00001000, ...
    private static final int[] bitMask = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    
    /** Checks if the given bit is set in data, using little endian (not the same as Java native big endian) */
    public static boolean checkBitLE(byte[] data, int index) {
        return (data[index >>> 3] & bitMask[7 & index]) != 0;
    }
    
    /** Sets the given bit in data to one, using little endian (not the same as Java native big endian) */
    public static void setBitLE(byte[] data, int index) {
        data[index >>> 3] |= bitMask[7 & index];
    }

    /** Sleep for a span of time, or mock sleep if enabled */
    public static void sleep(long millis) {
        if (mockSleepQueue == null) {
            sleepUninterruptibly(millis, TimeUnit.MILLISECONDS);
        } else {
            try {
                boolean isMultiPass = mockSleepQueue.take();
                rollMockClockMillis(millis);
                if (isMultiPass)
                    mockSleepQueue.offer(true);
            } catch (InterruptedException e) {
                // Ignored.
            }
        }
    }

    /** Enable or disable mock sleep.  If enabled, set mock time to current time. */
    public static void setMockSleep(boolean isEnable) {
        if (isEnable) {
            mockSleepQueue = new ArrayBlockingQueue<>(1);
            mockTime = new Date(System.currentTimeMillis());
        } else {
            mockSleepQueue = null;
        }
    }

    /** Let sleeping thread pass the synchronization point.  */
    public static void passMockSleep() {
        mockSleepQueue.offer(false);
    }

    /** Let the sleeping thread pass the synchronization point any number of times. */
    public static void finishMockSleep() {
        if (mockSleepQueue != null) {
            mockSleepQueue.offer(true);
        }
    }

    private static class Pair implements Comparable<Pair> {
        int item, count;
        public Pair(int item, int count) { this.count = count; this.item = item; }
        // note that in this implementation compareTo() is not consistent with equals()
        @Override public int compareTo(Pair o) { return -Ints.compare(count, o.count); }
    }

    public static int maxOfMostFreq(int... items) {
        ArrayList<Integer> list = new ArrayList<>(items.length);
        for (int item : items) list.add(item);
        return maxOfMostFreq(list);
    }

    public static int maxOfMostFreq(List<Integer> items) {
        if (items.isEmpty())
            return 0;
        // This would be much easier in a functional language (or in Java 8).
        items = Ordering.natural().reverse().sortedCopy(items);
        LinkedList<Pair> pairs = Lists.newLinkedList();
        pairs.add(new Pair(items.get(0), 0));
        for (int item : items) {
            Pair pair = pairs.getLast();
            if (pair.item != item)
                pairs.add((pair = new Pair(item, 0)));
            pair.count++;
        }
        // pairs now contains a uniqified list of the sorted inputs, with counts for how often that item appeared.
        // Now sort by how frequently they occur, and pick the max of the most frequent.
        Collections.sort(pairs);
        int maxCount = pairs.getFirst().count;
        int maxItem = pairs.getFirst().item;
        for (Pair pair : pairs) {
            if (pair.count != maxCount)
                break;
            maxItem = Math.max(maxItem, pair.item);
        }
        return maxItem;
    }

    private static int isAndroid = -1;
    public static boolean isAndroidRuntime() {
        if (isAndroid == -1) {
            final String runtime = System.getProperty("java.runtime.name");
            isAndroid = (runtime != null && runtime.equals("Android Runtime")) ? 1 : 0;
        }
        return isAndroid == 1;
    }

    public static boolean isLinux() {
        return System.getProperty("os.name").toLowerCase().contains("linux");
    }

    public static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    public static boolean isMac() {
        return System.getProperty("os.name").toLowerCase().contains("mac");
    }
}
