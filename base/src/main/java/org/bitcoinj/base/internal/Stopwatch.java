package org.bitcoinj.base.internal;

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

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.Temporal;
import java.time.temporal.TemporalAmount;
import java.time.temporal.TemporalUnit;
import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * A tool for measuring time, mainly for log messages. Note this class isn't affected by the mock clock of
 * {@link TimeUtils}.
 */
public class Stopwatch implements TemporalAmount {
    private final Instant startTime;
    private Instant stopTime = null;

    /**
     * Start a newly created stopwatch.
     *
     * @return the stopwatch that was just started
     */
    public static Stopwatch start() {
        return new Stopwatch();
    }

    private Stopwatch() {
        this.startTime = Instant.now();
    }

    /**
     * Stops the stopwatch, if it is running.
     *
     * @return the stopwatch that is stopped
     */
    public Stopwatch stop() {
        if (isRunning()) stopTime = Instant.now();
        return this;
    }

    /**
     * Returns true if the stopwatch is running.
     *
     * @return true if the stopwatch is running, false otherwise
     */
    public boolean isRunning() {
        return stopTime == null;
    }

    /**
     * Gets the elapsed time on the watch. This doesn't stop the watch.
     *
     * @return elapsed time
     */
    public Duration elapsed() {
        return Duration.between(startTime, isRunning() ? Instant.now() : stopTime);
    }

    @Override
    public long get(TemporalUnit temporalUnit) {
        checkArgument(temporalUnit.equals(ChronoUnit.MILLIS), () -> "unsupported temporal unit: " + temporalUnit);
        return elapsed().toMillis();
    }

    @Override
    public List<TemporalUnit> getUnits() {
        return Arrays.asList(ChronoUnit.MILLIS);
    }

    @Override
    public Temporal addTo(Temporal temporal) {
        return temporal.plus(elapsed());
    }

    @Override
    public Temporal subtractFrom(Temporal temporal) {
        return temporal.minus(elapsed());
    }

    @Override
    public String toString() {
        return elapsed().toMillis() + " ms";
    }
}
