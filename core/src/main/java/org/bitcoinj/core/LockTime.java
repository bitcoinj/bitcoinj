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

import org.bitcoinj.base.internal.TimeUtils;

import java.time.Instant;
import java.util.Objects;

/**
 * Wrapper for transaction lock time, specified either as a block height or as a timestamp (in seconds
 * since epoch). Both are encoded into the same long "raw value", as used in the Bitcoin protocol.
 * The lock time is said to be "not set" if its raw value is zero.
 * <p>
 * Instances of this class are immutable and should be treated as Java
 * <a href="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/doc-files/ValueBased.html#Value-basedClasses">value-based</a>.
 */
public class LockTime {
    /**
     * Wrap a raw value (as used in the Bitcoin protocol) into a lock time.
     * @param rawValue raw value to be wrapped
     * @return wrapped value
     */
    public static LockTime of(long rawValue) {
        if (rawValue < 0)
            throw new IllegalArgumentException("illegal negative lock time: " + rawValue);
        return new LockTime(rawValue);
    }

    /**
     * Wrap a block height into a lock time.
     * @param blockHeight block height to be wrapped
     * @return wrapped block height
     */
    public static LockTime ofBlockHeight(int blockHeight) {
        if (blockHeight < 0)
            throw new IllegalArgumentException("illegal negative block height: " + blockHeight);
        if (blockHeight >= THRESHOLD)
            throw new IllegalArgumentException("block height too high: " + blockHeight);
        return of(blockHeight);
    }

    /**
     * Wrap a timestamp into a lock time.
     * @param time timestamp to be wrapped
     * @return wrapped timestamp
     */
    public static LockTime ofTimestamp(Instant time) {
        long secs = time.getEpochSecond();
        if (secs < THRESHOLD)
            throw new IllegalArgumentException("timestamp too low: " + secs);
        return of(secs);
    }

    /**
     * Construct an unset lock time.
     * @return unset lock time
     */
    public static LockTime unset() {
        return of(0);
    }

    /**
     * Raw values below this threshold specify a block height, otherwise a timestamp in seconds since epoch.
     * Consider using {@link #isBlockHeight()} or {@link #isTimestamp()} before using this constant.
     */
    public static final long THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

    private final long value;

    private LockTime(long rawValue) {
        this.value = rawValue;
    }

    /**
     * Gets the raw value as used in the Bitcoin protocol
     * @return raw value
     */
    public long rawValue() {
        return value;
    }

    /**
     * The lock time is considered to be set only if its raw value is greater than zero.
     * @return true if lock time is set
     */
    public boolean isSet() {
        return value > 0;
    }

    /**
     * Determine if this lock time is specified as a block height. That means its raw value is below {@link #THRESHOLD}.
     * @return true if specified as a block height
     */
    public boolean isBlockHeight() {
        return value < THRESHOLD;
    }

    /**
     * Gets the lock time as a block height.
     * @return lock time as a block height
     * @throws IllegalStateException if the lock time is not specified as a block height
     */
    public int blockHeight() {
        if (!isBlockHeight())
            throw new IllegalStateException("lock time not specified as a block height");
        return Math.toIntExact(value);
    }

    /**
     * Determine if this lock time is specified as a timestamp in seconds since epoch. That means its raw value is
     * equal or above {@link #THRESHOLD}.
     * @return true if specified as a timestamp
     */
    public boolean isTimestamp() {
        return value >= THRESHOLD;
    }

    /**
     * Gets the lock time as a timestamp.
     * @return lock time as a timestamp
     * @throws IllegalStateException if the lock time is not specified as a timestamp
     */
    public Instant timestamp() {
        if (!isTimestamp())
            throw new IllegalStateException("lock time not specified as a timestamp");
        return Instant.ofEpochSecond(value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return this.value == ((LockTime) o).value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return isBlockHeight() ?
                "block " + blockHeight() :
                TimeUtils.dateTimeFormat(timestamp());
    }
}
