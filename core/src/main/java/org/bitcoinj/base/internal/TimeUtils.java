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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
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
     * Returns the current time as an Instant, or a mocked out equivalent.
     */
    public static Instant currentTime() {
        return Instant.now(clock);
    }

    /**
     * Returns the current time in "Bitcoin time", or a mocked out equivalent.
     * Bitcoin time is used in the P2P protocol and represents seconds since epoch.
     * It has no higher precision than the second.
     */
    public static Instant currentBitcoinTime() {
        return currentTime().truncatedTo(ChronoUnit.SECONDS);
    }

    /**
     * Ensures the given time is a "Bitcoin time".
     * Bitcoin time is used in the P2P protocol and represents seconds since epoch.
     * It has no higher precision than the second.
     * @param time time to be checked for absence of precision higher than the second
     * @return the time that was checked
     */
    public static Instant checkBitcoinTime(Instant time) {
        Preconditions.checkArgument(time.getNano() == 0, () ->
                "not a Bitcoin time: " + DateTimeFormatter.ISO_INSTANT.format(time));
        return time;
    }

    /**
     * Returns elapsed time between given start and current time as a Duration.
     */
    public static Duration elapsedTime(Instant start) {
        return Duration.between(start, currentTime());
    }

    /**
     * Determines the earlier of two instants.
     */
    public static Instant earlier(Instant time1, Instant time2) {
        return time1.isBefore(time2) ? time1 : time2;
    }

    /**
     * Determines the later of two instants.
     */
    public static Instant later(Instant time1, Instant time2) {
        return time1.isAfter(time2) ? time1 : time2;
    }

    /**
     * Determines the longest of two durations.
     */
    public static Duration longest(Duration duration1, Duration duration2) {
        return duration1.compareTo(duration2) > 0 ? duration1 : duration2;
    }

    /**
     * Formats a given date+time value to an ISO 8601 string.
     * @param time date and time to format
     */
    public static String dateTimeFormat(Instant time) {
        return DateTimeFormatter.ISO_INSTANT.format(time);
    }
}
