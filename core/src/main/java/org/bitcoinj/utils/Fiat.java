/*
 * Copyright 2014 Andreas Schildbach
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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.Serializable;
import java.math.BigDecimal;

import org.bitcoinj.core.Monetary;
import com.google.common.base.Objects;
import com.google.common.math.LongMath;
import com.google.common.primitives.Longs;

/**
 * Represents a monetary fiat value. It was decided to not fold this into {@link org.bitcoinj.core.Coin} because of type
 * safety. Fiat values always come with an attached currency code.
 * 
 * This class is immutable.
 */
public final class Fiat implements Monetary, Comparable<Fiat>, Serializable {

    /**
     * The absolute value of exponent of the value of a "smallest unit" in scientific notation. We picked 4 rather than
     * 2, because in financial applications it's common to use sub-cent precision.
     */
    public static final int SMALLEST_UNIT_EXPONENT = 4;

    /**
     * The number of smallest units of this monetary value.
     */
    public final long value;
    public final String currencyCode;

    private Fiat(final String currencyCode, final long value) {
        this.value = value;
        this.currencyCode = currencyCode;
    }

    public static Fiat valueOf(final String currencyCode, final long value) {
        return new Fiat(currencyCode, value);
    }

    @Override
    public int smallestUnitExponent() {
        return SMALLEST_UNIT_EXPONENT;
    }

    /**
     * Returns the number of "smallest units" of this monetary value.
     */
    @Override
    public long getValue() {
        return value;
    }

    public String getCurrencyCode() {
        return currencyCode;
    }

    /**
     * Parses an amount expressed in the way humans are used to.
     * <p>
     * <p/>
     * This takes string in a format understood by {@link BigDecimal#BigDecimal(String)}, for example "0", "1", "0.10",
     * "1.23E3", "1234.5E-5".
     * 
     * @throws IllegalArgumentException
     *             if you try to specify more than 4 digits after the comma, or a value out of range.
     */
    public static Fiat parseFiat(final String currencyCode, final String str) {
        try {
            long val = new BigDecimal(str).movePointRight(SMALLEST_UNIT_EXPONENT)
                    .toBigIntegerExact().longValue();
            return Fiat.valueOf(currencyCode, val);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public Fiat add(final Fiat value) {
        checkArgument(value.currencyCode.equals(currencyCode));
        return new Fiat(currencyCode, LongMath.checkedAdd(this.value, value.value));
    }

    public Fiat subtract(final Fiat value) {
        checkArgument(value.currencyCode.equals(currencyCode));
        return new Fiat(currencyCode, LongMath.checkedSubtract(this.value, value.value));
    }

    public Fiat multiply(final long factor) {
        return new Fiat(currencyCode, LongMath.checkedMultiply(this.value, factor));
    }

    public Fiat divide(final long divisor) {
        return new Fiat(currencyCode, this.value / divisor);
    }

    public Fiat[] divideAndRemainder(final long divisor) {
        return new Fiat[] { new Fiat(currencyCode, this.value / divisor), new Fiat(currencyCode, this.value % divisor) };
    }

    public long divide(final Fiat divisor) {
        checkArgument(divisor.currencyCode.equals(currencyCode));
        return this.value / divisor.value;
    }

    /**
     * Returns true if and only if this instance represents a monetary value greater than zero, otherwise false.
     */
    public boolean isPositive() {
        return signum() == 1;
    }

    /**
     * Returns true if and only if this instance represents a monetary value less than zero, otherwise false.
     */
    public boolean isNegative() {
        return signum() == -1;
    }

    /**
     * Returns true if and only if this instance represents zero monetary value, otherwise false.
     */
    public boolean isZero() {
        return signum() == 0;
    }

    /**
     * Returns true if the monetary value represented by this instance is greater than that of the given other Fiat,
     * otherwise false.
     */
    public boolean isGreaterThan(Fiat other) {
        return compareTo(other) > 0;
    }

    /**
     * Returns true if the monetary value represented by this instance is less than that of the given other Fiat,
     * otherwise false.
     */
    public boolean isLessThan(Fiat other) {
        return compareTo(other) < 0;
    }

    @Override
    public int signum() {
        if (this.value == 0)
            return 0;
        return this.value < 0 ? -1 : 1;
    }

    public Fiat negate() {
        return new Fiat(currencyCode, -this.value);
    }

    /**
     * Returns the number of "smallest units" of this monetary value. It's deprecated in favour of accessing {@link #value}
     * directly.
     */
    public long longValue() {
        return this.value;
    }

    private static final MonetaryFormat FRIENDLY_FORMAT = MonetaryFormat.FIAT.postfixCode();

    /**
     * Returns the value as a 0.12 type string. More digits after the decimal place will be used if necessary, but two
     * will always be present.
     */
    public String toFriendlyString() {
        return FRIENDLY_FORMAT.code(0, currencyCode).format(this).toString();
    }

    private static final MonetaryFormat PLAIN_FORMAT = MonetaryFormat.FIAT.minDecimals(0).repeatOptionalDecimals(1, 4).noCode();

    /**
     * <p>
     * Returns the value as a plain string. The result is unformatted with no trailing zeroes. For
     * instance, a value of 150000 "smallest units" gives an output string of "0.0015".
     * </p>
     */
    public String toPlainString() {
        return PLAIN_FORMAT.format(this).toString();
    }

    @Override
    public String toString() {
        return Long.toString(value);
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this) return true;
        if (o == null || o.getClass() != getClass()) return false;
        final Fiat other = (Fiat) o;
        return this.value == other.value && this.currencyCode.equals(other.currencyCode);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value, currencyCode);
    }

    @Override
    public int compareTo(final Fiat other) {
        if (!this.currencyCode.equals(other.currencyCode))
            return this.currencyCode.compareTo(other.currencyCode);
        return Longs.compare(this.value, other.value);
    }
}
