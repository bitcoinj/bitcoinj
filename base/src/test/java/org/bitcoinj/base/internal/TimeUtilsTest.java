/*
 * Copyright 2011 Thilo Planz
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Nicola Atzei
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
import java.time.format.DateTimeFormatter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TimeUtilsTest {
    @Before
    public void setUp() {
        TimeUtils.clearMockClock();
    }

    @Test
    public void setAndRollMockClock() {
        TimeUtils.setMockClock(Instant.ofEpochSecond(25200));
        assertEquals(Instant.from(DateTimeFormatter.ISO_INSTANT.parse("1970-01-01T07:00:00Z")), TimeUtils.currentTime());
        TimeUtils.rollMockClock(Duration.ofSeconds(8));
        assertEquals(Instant.from(DateTimeFormatter.ISO_INSTANT.parse("1970-01-01T07:00:08Z")), TimeUtils.currentTime());
    }

    @Test(expected = IllegalStateException.class)
    public void rollMockClock_uninitialized() {
        TimeUtils.rollMockClock(Duration.ofMinutes(1));
    }

    @Test
    public void dateTimeFormat() {
        long ms = 1416135273781L;
        assertEquals("2014-11-16T10:54:33.781Z", TimeUtils.dateTimeFormat(Instant.ofEpochMilli(ms)));
    }

    @Test
    public void earlier() {
        Instant t1 = Instant.now(); // earlier
        Instant t2 = t1.plusSeconds(1); // later
        assertEquals(t1, TimeUtils.earlier(t1, t2));
        assertEquals(t1, TimeUtils.earlier(t2, t1));
        assertEquals(t1, TimeUtils.earlier(t1, t1));
        assertEquals(t2, TimeUtils.earlier(t2, t2));
    }

    @Test
    public void later() {
        Instant t1 = Instant.now(); // earlier
        Instant t2 = t1.plusSeconds(1); // later
        assertEquals(t2, TimeUtils.later(t1, t2));
        assertEquals(t2, TimeUtils.later(t2, t1));
        assertEquals(t1, TimeUtils.later(t1, t1));
        assertEquals(t2, TimeUtils.later(t2, t2));
    }

    @Test
    public void longest() {
        Duration d1 = Duration.ofMinutes(1); // shorter
        Duration d2 = Duration.ofMinutes(1); // longer
        assertEquals(d2, TimeUtils.longest(d1, d2));
        assertEquals(d2, TimeUtils.longest(d2, d1));
        assertEquals(d1, TimeUtils.longest(d1, d1));
        assertEquals(d2, TimeUtils.longest(d2, d2));
    }
}
