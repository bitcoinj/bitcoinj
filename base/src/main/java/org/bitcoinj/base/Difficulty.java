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

package org.bitcoinj.base;

import org.bitcoinj.base.internal.ByteUtils;

import java.math.BigInteger;
import java.time.Duration;
import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * The target difficulty is a value which a block hash must be equal to or below in order for that block to be a
 * valid part of the block chain.
 * <p>
 * Difficulty values cannot be negative. A high value means low difficulty, and a low value means high difficulty.
 * <p>
 * The value is stored in only 32 bits of space, so it uses a less precise “compact form”, or "nBits". Think of it as a
 * base-256 version of the scientific notation, consisting of a 1 byte exponent and 3 bytes of mantissa. As an example,
 * see {@link #STANDARD_MAX_DIFFICULTY_TARGET}. That form is used for storing the value in this class as well, so
 * when constructing from an integer value, be prepared to lose precision.
 * <p>
 * This is a value-based class; use of identity-sensitive operations (including reference equality (==), identity
 * hash code, or synchronization) on instances of Difficulty may have unpredictable results and should be avoided.
 */
public class Difficulty implements Comparable<Difficulty> {

    /**
     * Standard maximum value for difficulty target. For most chains this is declared to be "difficulty 1", because
     * it is fairly easy.
     */
    public static final Difficulty STANDARD_MAX_DIFFICULTY_TARGET = Difficulty.ofCompact(0x1d00ffff);
    /**
     * The easiest difficulty target possible, allowing (slightly less than) half of all possible hash solutions.
     * This is the highest value this class can represent. Used for testing.
     */
    public static final Difficulty EASIEST_DIFFICULTY_TARGET = Difficulty.ofCompact(0x207fffff);

    // for bounds checking
    private static final BigInteger MAX_INTEGER_VALUE = Difficulty.EASIEST_DIFFICULTY_TARGET.asInteger();

    private final long compact;

    private Difficulty(long compact) {
        this.compact = compact;
    }

    /**
     * Construct a difficulty from a compact form, sometimes called "nBits".
     *
     * @param compact compact form
     * @return constructed difficulty
     */
    public static Difficulty ofCompact(long compact) {
        long exponent = (compact >> 24) & 0xff;
        checkArgument(exponent <= 32, () ->
                "exponent cannot exceed 32: " + Long.toHexString(compact));
        long mantissa = compact & 0xffffff;
        checkArgument(mantissa <= 0x7fffff, () ->
                "sign bit 24 cannot be set: " + Long.toHexString(compact));
        checkArgument(mantissa >= 0x008000, () ->
                "not optimally encoded, can shift to left: " + Long.toHexString(compact));
        return new Difficulty(compact);
    }

    /**
     * Construct a difficulty from an 256-bit integer value. Because the value is stored in compact form, it will
     * likely lose precision.
     *
     * @param value 256-bit integer value
     * @return constructed difficulty
     */
    public static Difficulty ofInteger(BigInteger value) {
        checkArgument(value.signum() >= 0, () ->
                "cannot be negative: " + value.toString(16));
        checkArgument(value.compareTo(MAX_INTEGER_VALUE) <= 0, () ->
                "too high: " + value.toString(16));
        return new Difficulty(ByteUtils.encodeCompactBits(value));
    }

    /**
     * Inside a block the difficulty target is represented using a compact form, sometimes called "nBits".
     *
     * @return difficulty target as a long in compact form
     */
    public long compact() {
        return compact;
    }

    /**
     * Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash.
     *
     * @return difficulty target as 256-bit integer value
     */
    public BigInteger asInteger() {
        return ByteUtils.decodeCompactBits(compact);
    }

    /**
     * Adjust this difficulty so that actual time between blocks closely matches our target. This method doesn't take
     * hash rate changes between intervals into account.
     *
     * @param actualTimespan the actual duration of the last block interval, according to the headers
     * @param targetTimespan the duration of block intervals we're targetting at
     * @param maxTarget      make sure adjusted difficulty doesn't get any easier than this value
     * @return adjusted difficulty to be used for the next interval
     */
    public Difficulty adjust(Duration actualTimespan, Duration targetTimespan, Difficulty maxTarget) {
        checkArgument(!actualTimespan.isNegative(), () -> "cannot be negative: " + actualTimespan);
        checkArgument(!actualTimespan.isZero(), () -> "cannot be zero: " + actualTimespan);
        checkArgument(!targetTimespan.isNegative(), () -> "cannot be negative: " + targetTimespan);
        checkArgument(!targetTimespan.isZero(), () -> "cannot be zero: " + targetTimespan);
        BigInteger actualSecs = BigInteger.valueOf(actualTimespan.getSeconds());
        BigInteger targetSecs = BigInteger.valueOf(targetTimespan.getSeconds());
        BigInteger adjusted = asInteger().multiply(actualSecs).divide(targetSecs);
        return adjusted.compareTo(maxTarget.asInteger()) > 0 ?
                maxTarget :
                Difficulty.ofInteger(adjusted);
    }

    /**
     * Determines if the work represented by a given block hash meets or exceeds this difficulty target. The more
     * leading zero bits the hash has, the more work has been put into creating it.
     *
     * @param blockHash block hash that represents work
     * @return true if this target is met or exceeded by given work
     */
    public boolean isMetByWork(Sha256Hash blockHash) {
        BigInteger work = blockHash.toBigInteger();
        return work.compareTo(this.asInteger()) <= 0;
    }

    /**
     * Returns the compact form, encoded as a 4-byte hex string.
     *
     * @return compact form encoded in hex
     */
    public String toCompactString() {
        return Long.toHexString(compact);
    }

    /**
     * Returns the integer form, encoded as a hex string. Leading zero bytes are omitted.
     *
     * @return integer form encoded in hex
     */
    public String toIntegerString() {
        return asInteger().toString(16);
    }

    @Override
    public String toString() {
        return toCompactString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return this.compact == ((Difficulty) o).compact;
    }

    @Override
    public int hashCode() {
        return Objects.hash(compact);
    }

    @Override
    public int compareTo(Difficulty other) {
        // This yields the same order as if we were comparing the integer
        // forms, due to the optimal encoding rule of the compact format.
        return Long.compare(this.compact, other.compact);
    }
}
