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

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.internal.InternalUtils;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Pattern;

/**
 * A collection of various utility methods that are helpful for working with the Bitcoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
public class Utils {

    /**
     * Joiner for concatenating words with a space inbetween.
     * @deprecated Use @link java.util.StringJoiner} or a direct Guava dependency
     */
    @Deprecated
    public static final Joiner SPACE_JOINER = Joiner.on(" ");

    /**
     * Splitter for splitting words on whitespaces.
     * @deprecated Use {@link java.lang.String#split(String)} or a direct Guava dependency
     */
    @Deprecated
    public static final Splitter WHITESPACE_SPLITTER = Splitter.on(Pattern.compile("\\s+"));

    /**
     * Max initial size of variable length arrays and ArrayLists that could be attacked.
     * Avoids this attack: Attacker sends a msg indicating it will contain a huge number (eg 2 billion) elements (eg transaction inputs) and
     * forces bitcoinj to try to allocate a huge piece of the memory resulting in OutOfMemoryError.
    */
    public static final int MAX_INITIAL_ARRAY_LENGTH = 20;

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

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
     * If non-null, overrides the return value of now().
     */
    private static volatile Date mockTime;

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
     * Clears the mock clock and sleep
     */
    public static void resetMocking() {
        mockTime = null;
    }

    /**
     * Returns the current time, or a mocked out equivalent.
     */
    public static Date now() {
        return mockTime != null ? mockTime : new Date();
    }

    /**
     * Returns the current time in milliseconds since the epoch, or a mocked out equivalent.
     */
    public static long currentTimeMillis() {
        return mockTime != null ? mockTime.getTime() : System.currentTimeMillis();
    }

    /**
     * Returns the current time in seconds since the epoch, or a mocked out equivalent.
     */
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

    private enum Runtime {
        ANDROID, OPENJDK, ORACLE_JAVA
    }

    private enum OS {
        LINUX, WINDOWS, MAC_OS
    }

    private static Runtime runtime = null;
    private static OS os = null;
    static {
        String runtimeProp = System.getProperty("java.runtime.name", "").toLowerCase(Locale.US);
        if (runtimeProp.equals(""))
            runtime = null;
        else if (runtimeProp.contains("android"))
            runtime = Runtime.ANDROID;
        else if (runtimeProp.contains("openjdk"))
            runtime = Runtime.OPENJDK;
        else if (runtimeProp.contains("java(tm) se"))
            runtime = Runtime.ORACLE_JAVA;
        else
            log.info("Unknown java.runtime.name '{}'", runtimeProp);

        String osProp = System.getProperty("os.name", "").toLowerCase(Locale.US);
        if (osProp.equals(""))
            os = null;
        else if (osProp.contains("linux"))
            os = OS.LINUX;
        else if (osProp.contains("win"))
            os = OS.WINDOWS;
        else if (osProp.contains("mac"))
            os = OS.MAC_OS;
        else
            log.info("Unknown os.name '{}'", runtimeProp);
    }

    public static boolean isAndroidRuntime() {
        return runtime == Runtime.ANDROID;
    }

    public static boolean isOpenJDKRuntime() {
        return runtime == Runtime.OPENJDK;
    }

    public static boolean isOracleJavaRuntime() {
        return runtime == Runtime.ORACLE_JAVA;
    }

    public static boolean isLinux() {
        return os == OS.LINUX;
    }

    public static boolean isWindows() {
        return os == OS.WINDOWS;
    }

    public static boolean isMac() {
        return os == OS.MAC_OS;
    }

    public static String toString(List<byte[]> stack) {
        List<String> parts = new ArrayList<>(stack.size());
        for (byte[] push : stack)
            parts.add('[' + ByteUtils.HEX.encode(push) + ']');
        return InternalUtils.SPACE_JOINER.join(parts);
    }
}
