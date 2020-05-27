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

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class StopwatchTest {
    @Test
    public void testStartStop() {
        Stopwatch watch = Stopwatch.createStarted();
        watch.stop();
        assertTrue("No time has passed", watch.elapsedNanos() >= 0);
        assertEquals( "Inconsistent microseconds and nanoseconds", watch.elapsedMicros(), watch.elapsedNanos() / 1000);
        assertTrue("String without units", watch.toString().endsWith(" \u03bcs"));
    }

    @Test
    public void testElapsed() {
        Stopwatch watch = Stopwatch.createStarted();
        assertTrue("No time has passed", watch.elapsedNanos() >= 0);
        assertNotEquals("Clock didn't advance", watch.elapsedNanos(), watch.elapsedNanos());
        assertTrue("String without units", watch.toString().endsWith(" \u03bcs"));
    }

    @Test
    public void testWithShortSleep() throws InterruptedException {
        Stopwatch watch = Stopwatch.createStarted();
        Thread.sleep(0, 1000);
        watch.stop();
        assertTrue("Not enough time has passed",watch.elapsedNanos() >= 1_000);
        assertEquals( "Inconsistent microseconds and nanoseconds", watch.elapsedMicros(), watch.elapsedNanos() / 1000);
        assertTrue("String without units", watch.toString().endsWith(" \u03bcs"));
    }
}
