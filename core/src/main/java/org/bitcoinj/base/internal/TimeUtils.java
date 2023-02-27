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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 *
 */
public class TimeUtils {
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
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
}
