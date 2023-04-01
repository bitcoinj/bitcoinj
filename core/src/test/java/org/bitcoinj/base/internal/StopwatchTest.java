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

import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class StopwatchTest {
    private Stopwatch stopwatch;

    @Before
    public void setUp() {
        stopwatch = Stopwatch.start();
    }

    @Test
    public void toString_() {
        stopwatch.toString();
    }

    @Test
    public void stop() {
        stopwatch.stop();
    }

    @Test
    public void addSubstract() {
        Instant i1 = Instant.now();
        Instant i2 = i1.plus(stopwatch.stop());
        Instant i3 = i2.minus(stopwatch);
        assertEquals(i1, i3);
        assertTrue(i2.compareTo(i1) >= 0);
        assertTrue(i3.compareTo(i2) <= 0);
    }

    @Test
    public void compareTo() {
        Duration hour = Duration.ofHours(1);
        assertTrue(stopwatch.elapsed().compareTo(hour) < 0);
        assertTrue(hour.compareTo(stopwatch.elapsed()) > 0);
    }
}
