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

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.bitcoinj.core.LockTime.HeightLock;
import org.bitcoinj.core.LockTime.TimeLock;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitParamsRunner.class)
public class LockTimeTest {
    @Test
    public void ofBlockHeight() {
        assertEquals(1, LockTime.ofBlockHeight(1).blockHeight());
        assertEquals(499_999_999, LockTime.ofBlockHeight((int) LockTime.THRESHOLD - 1).blockHeight());
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
        LockTime unset = LockTime.unset();
        assertTrue(unset instanceof HeightLock);
        assertEquals(0, unset.rawValue());
    }

    @Test
    public void timestampSubtype() {
        LockTime timestamp = LockTime.ofTimestamp(Instant.now());
        assertTrue(timestamp instanceof TimeLock);
        assertTrue(((TimeLock) timestamp).timestamp().isAfter(Instant.EPOCH));
    }

    @Test
    public void blockHeightSubtype() {
        LockTime blockHeight = LockTime.ofBlockHeight(100);
        assertTrue(blockHeight instanceof HeightLock);
        assertTrue(((HeightLock) blockHeight).blockHeight() > 0);
    }

    @Test
    @Parameters(method = "validValueVectors")
    public void validValues(long value, Class<?> clazz) {
        LockTime lockTime = LockTime.of(value);

        assertTrue(clazz.isInstance(lockTime));
        assertEquals(value, lockTime.rawValue());
    }

    @Test(expected = IllegalArgumentException.class)
    @Parameters(method = "invalidValueVectors")
    public void invalidValues(long value) {
        LockTime lockTime = LockTime.of(value);
    }

    private Object[] validValueVectors() {
        return new Object[] {
                new Object[] { 0, HeightLock.class },
                new Object[] { 1, HeightLock.class },
                new Object[] { 499_999_999, HeightLock.class },
                new Object[] { 500_000_000, TimeLock.class },
                new Object[] { Long.MAX_VALUE, TimeLock.class },
                new Object[] { Instant.now().getEpochSecond(), TimeLock.class },
                new Object[] { Instant.MAX.getEpochSecond(), TimeLock.class }
        };
    }

    private Long[] invalidValueVectors() {
        return new Long[] { Long.MIN_VALUE, -1L };
    }
}
