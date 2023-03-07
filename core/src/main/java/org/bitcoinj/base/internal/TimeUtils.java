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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Utilities for time and mock time.
 */
public class TimeUtils {
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    // Clock to be used for the return value of now() and currentTime() variants
    private static volatile Clock clock = Clock.systemUTC();

    /**
     * Sets the mock clock to the current time as a fixed instant.
     */
    public static void setMockClock() {
        setMockClock(Instant.now());
    }

    /**
     * Sets the mock clock to a fixed instant.
     * @param fixedInstant a fixed instant
     */
    public static void setMockClock(Instant fixedInstant) {
        clock = Clock.fixed(fixedInstant, UTC.toZoneId());
    }

    /**
     * Rolls an already set mock clock by the given duration.
     * @param delta amount to roll the mock clock, can be negative
     * @throws IllegalStateException if the mock clock isn't set
     */
    public static void rollMockClock(Duration delta) {
        if (clock.equals(Clock.systemUTC()))
            throw new IllegalStateException("You need to use setMockClock() first.");
        setMockClock(clock.instant().plus(delta));
    }

    /**
     * Clears the mock clock and causes time to tick again.
     */
    public static void clearMockClock() {
        clock = Clock.systemUTC();
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
        return Instant.now(clock);
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
