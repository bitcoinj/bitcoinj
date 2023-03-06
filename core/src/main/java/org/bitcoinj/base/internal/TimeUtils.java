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
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Utilities for time and mock time.
 */
public class TimeUtils {
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    // TODO: See if java.time.Clock can help us in our mocking
    /**
     * If non-null, overrides the return value of now().
     */
    private static final AtomicReference<Instant> mockTime = new AtomicReference<>(null);

    /**
     * Advances (or rewinds) the mock clock by the given number of seconds.
     */
    public static Date rollMockClock(int seconds) {
        return rollMockClockMillis(seconds * 1000L);
    }

    /**
     * Advances (or rewinds) the mock clock by the given number of milliseconds.
     */
    public static Date rollMockClockMillis(long millis) {
        if (mockTime.get() == null)
            throw new IllegalStateException("You need to use setMockClock() first.");
        // TODO: Fix this race condition. It's probably ok to remove the check (at least I'm pretty sure updateAndGet will throw an RTE if mockTime is null)
        return Date.from(
                mockTime.updateAndGet(mt -> mt.plusMillis(millis))
        );
    }

    /**
     * Sets the mock clock to the current time.
     */
    public static void setMockClock() {
        mockTime.set(Instant.now());
    }

    /**
     * Sets the mock clock to the given time (in seconds).
     */
    public static void setMockClock(long mockClockSeconds) {
        mockTime.set(Instant.ofEpochSecond(mockClockSeconds));
    }

    /**
     * Clears the mock clock and sleep
     */
    public static void resetMocking() {
        mockTime.set(null);
    }

    /**
     * Returns the current time, or a mocked out equivalent.
     */
    public static Date now() {
        return Date.from(currentTime());
    }

    /**
     * Returns the current time in milliseconds since the epoch, or a mocked out equivalent.
     */
    public static long currentTimeMillis() {
        return currentTime().toEpochMilli();
    }

    /**
     * Returns the current time in seconds since the epoch, or a mocked out equivalent.
     */
    public static long currentTimeSeconds() {
        return currentTime().getEpochSecond();
    }

    /**
     * Returns the current time as an Instant, or a mocked out equivalent.
     */
    public static Instant currentTime() {
        Instant gotten = mockTime.get();
        return gotten != null ? gotten : Instant.now();
    }

    /**
     * Returns elapsed time between given start and current time as a Duration.
     */
    public static Duration elapsedTime(Instant start) {
        return Duration.between(start, currentTime());
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
