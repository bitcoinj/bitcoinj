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

package org.bitcoinj.core;

import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.*;

public class LockTimeTest {
    @Test
    public void of() {
        assertEquals(0, LockTime.of(0).rawValue());
        assertEquals(499_999_999, LockTime.of(LockTime.THRESHOLD - 1).rawValue());
        assertEquals(500_000_000, LockTime.of(LockTime.THRESHOLD).rawValue());
        assertEquals(Long.MAX_VALUE, LockTime.of(Long.MAX_VALUE).rawValue());
    }

    @Test(expected = IllegalArgumentException.class)
    public void of_negative() {
        LockTime.of(-1);
    }

    @Test
    public void ofBlockHeight() {
        assertEquals(1, LockTime.ofBlockHeight(1).blockHeight());
        assertEquals(499_999_999, LockTime.ofBlockHeight((int) LockTime.THRESHOLD - 1).blockHeight());
    }

    @Test(expected = IllegalArgumentException.class)
    public void ofBlockHeight_negative() {
        LockTime.ofBlockHeight(-1);
    }

    @Test
    public void ofTimestamp() {
        Instant fiftyYears = Instant.EPOCH.plus(365 * 50, ChronoUnit.DAYS);
        assertEquals(fiftyYears, LockTime.ofTimestamp(fiftyYears).timestamp());
        Instant almostMax = Instant.MAX.truncatedTo(ChronoUnit.SECONDS);
        assertEquals(almostMax, LockTime.ofTimestamp(almostMax).timestamp());
    }

    @Test(expected = IllegalArgumentException.class)
    public void ofTimestamp_tooLow() {
        LockTime.ofTimestamp(Instant.EPOCH.plus(365, ChronoUnit.DAYS));
    }

    @Test(expected = IllegalArgumentException.class)
    public void ofTimestamp_negative() {
        LockTime.ofTimestamp(Instant.EPOCH.minusSeconds(1));
    }

    @Test
    public void unset() {
        assertEquals(0, LockTime.unset().rawValue());
    }

    @Test(expected = IllegalStateException.class)
    public void blockHeight_mismatch() {
        LockTime.ofTimestamp(Instant.MAX).blockHeight();
    }

    @Test(expected = IllegalStateException.class)
    public void timestamp_mismatch() {
        LockTime.ofBlockHeight(1).timestamp();
    }
}
