/*
 * Copyright 2020 Michael Sean Gilligan
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
package org.bitcoinj.utils;

/**
 * A simple stopwatch function that is a subset of the Guava stopwatch.
 * The chosen subset is effectively what bitcoinj was using at the time this
 * class was created. Uses {@link System#nanoTime()} internally.
 */
public class Stopwatch {
    private boolean isRunning;
    private final long startTime;
    private long stopTime;

    private Stopwatch() {
        isRunning = true;
        startTime = System.nanoTime();
    }

    /**
     * Create and start a Stopwatch
     *
     * @return A running stopwatch
     */
    public static Stopwatch createStarted() {
        return new Stopwatch();
    }

    /**
     * Stop the stopwatch
     */
    public void stop() {
        stopTime = System.nanoTime();
        isRunning = false;
    }

    /**
     * Return elapsed time in nanoseconds
     *
     * @return Elapsed time in nanoseconds
     */
    public long elapsedNanos() {
        return isRunning ? System.nanoTime() - startTime : stopTime - startTime;
    }

    /**
     * Return elapsed time in microseconds
     *
     * @return Elapsed time in microseconds
     */
    public long elapsedMicros() {
        return elapsedNanos() / 1_000;
    }

    /**
     * Return elapsed time in milliseconds
     *
     * @return Elapsed time in milliseconds
     */
    public long elapsedMillis() {
        return elapsedNanos() / 1_000_000;
    }

    /**
     * Return elapsed time in microseconds as a string
     *
     * @return Elapsed time in microseconds
     */
    @Override
    public String toString() {
        return elapsedMicros() + " \u03bcs";  // time in microseconds
    }
}
