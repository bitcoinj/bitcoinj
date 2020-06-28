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

package org.bitcoinj.core;

import org.bitcoinj.utils.MonetaryFormat;
import com.google.common.math.LongMath;
import com.google.common.primitives.Longs;

import java.io.Serializable;
import java.math.BigDecimal;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Represents a monetary Bitcoin value. This class is immutable.
 */
public final class Coin implements Monetary, Comparable<Coin>, Serializable {

    /**
     * Number of decimals for one Bitcoin. This constant is useful for quick adapting to other coins because a lot of
     * constants derive from it.
     */
    public static final int SMALLEST_UNIT_EXPONENT = 8;

    /**
     * The number of satoshis equal to one bitcoin.
     */
    private static final long COIN_VALUE = LongMath.pow(10, SMALLEST_UNIT_EXPONENT);

    /**
     * Zero Bitcoins.
     */
    public static final Coin ZERO = Coin.valueOf(0);

    /**
     * One Bitcoin.
     */
    public static final Coin COIN = Coin.valueOf(COIN_VALUE);

    /**
     * 0.01 Bitcoins. This unit is not really used much.
     */
    public static final Coin CENT = COIN.divide(100);

    /**
     * 0.001 Bitcoins, also known as 1 mBTC.
     */
    public static final Coin MILLICOIN = COIN.divide(1000);

    /**
     * 0.000001 Bitcoins, also known as 1 µBTC or 1 uBTC.
     */
    public static final Coin MICROCOIN = MILLICOIN.divide(1000);

    /**
     * A satoshi is the smallest unit that can be transferred. 100 million of them fit into a Bitcoin.
     */
    public static final Coin SATOSHI = Coin.valueOf(1);

    public static final Coin FIFTY_COINS = COIN.multiply(50);

    /**
     * Represents a monetary value of minus one satoshi.
     */
    public static final Coin NEGATIVE_SATOSHI = Coin.valueOf(-1);

    /**
     * The number of satoshis of this monetary value.
     */
    public final long value;

    private Coin(final long satoshis) {
        this.value = satoshis;
    }

    public static Coin valueOf(final long satoshis) {
        return new Coin(satoshis);
    }

    @Override
    public int smallestUnitExponent() {
        return SMALLEST_UNIT_EXPONENT;
    }

    /**
     * Returns the number of satoshis of this monetary value.
     */
    @Override
    public long getValue() {
        return value;
    }

    /**
     * Convert an amount expressed in the way humans are used to into satoshis.
     *
     * @param coins Number of bitcoins
     * @param cents Number of bitcents (0.01 bitcoin)
     * @return {@code Coin} object containing value in satoshis
     */
    public static Coin valueOf(final int coins, final int cents) {
        checkArgument(cents < 100);
        checkArgument(cents >= 0);
        checkArgument(coins >= 0);
        final Coin coin = COIN.multiply(coins).add(CENT.multiply(cents));
        return coin;
    }

    /**
     * Parses an amount expressed in the way humans are used to.
     * 
     * @param str string in a format understood by {@link BigDecimal#BigDecimal(String)}, for example "0", "1", "0.10",
     *      * "1.23E3", "1234.5E-5".
     * @return {@code Coin} object containing value in satoshis
     * @throws IllegalArgumentException
     *             if you try to specify fractional satoshis, or a value out of range.
     */
    public static Coin parseCoin(final String str) {
        try {
            long satoshis = new BigDecimal(str).movePointRight(SMALLEST_UNIT_EXPONENT).longValueExact();
            return Coin.valueOf(satoshis);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(e); // Repackage exception to honor method contract
        }
    }

    /**
     * Parses an amount expressed in the way humans are used to. The amount is cut to satoshi precision.
     * 
     * @param str string in a format understood by {@link BigDecimal#BigDecimal(String)}, for example "0", "1", "0.10",
     *      * "1.23E3", "1234.5E-5".
     * @return {@code Coin} object containing value in satoshis
     * @throws IllegalArgumentException
     *             if you try to specify a value out of range.
     */
    public static Coin parseCoinInexact(final String str) {
        try {
            long satoshis = new BigDecimal(str).movePointRight(SMALLEST_UNIT_EXPONENT).longValue();
            return Coin.valueOf(satoshis);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(e); // Repackage exception to honor method contract
        }
    }

    public Coin add(final Coin value) {
        return new Coin(LongMath.checkedAdd(this.value, value.value));
    }

    /** Alias for add */
    public Coin plus(final Coin value) {
        return add(value);
    }

    public Coin subtract(final Coin value) {
        return new Coin(LongMath.checkedSubtract(this.value, value.value));
    }

    /** Alias for subtract */
    public Coin minus(final Coin value) {
        return subtract(value);
    }

    public Coin multiply(final long factor) {
        return new Coin(LongMath.checkedMultiply(this.value, factor));
    }

    /** Alias for multiply */
    public Coin times(final long factor) {
        return multiply(factor);
    }

    /** Alias for multiply */
    public Coin times(final int factor) {
        return multiply(factor);
    }

    public Coin divide(final long divisor) {
        return new Coin(this.value / divisor);
    }

    /** Alias for divide */
    public Coin div(final long divisor) {
        return divide(divisor);
    }

    /** Alias for divide */
    public Coin div(final int divisor) {
        return divide(divisor);
    }

    public Coin[] divideAndRemainder(final long divisor) {
        return new Coin[] { new Coin(this.value / divisor), new Coin(this.value % divisor) };
    }

    public long divide(final Coin divisor) {
        return this.value / divisor.value;
    }

    /**
     * Returns true if and only if this instance represents a monetary value greater than zero,
     * otherwise false.
     */
    public boolean isPositive() {
        return signum() == 1;
    }

    /**
     * Returns true if and only if this instance represents a monetary value less than zero,
     * otherwise false.
     */
    public boolean isNegative() {
        return signum() == -1;
    }

    /**
     * Returns true if and only if this instance represents zero monetary value,
     * otherwise false.
     */
    public boolean isZero() {
        return signum() == 0;
    }

    /**
     * Returns true if the monetary value represented by this instance is greater than that
     * of the given other Coin, otherwise false.
     */
    public boolean isGreaterThan(Coin other) {
        return compareTo(other) > 0;
    }

    /**
     * Returns true if the monetary value represented by this instance is less than that
     * of the given other Coin, otherwise false.
     */
    public boolean isLessThan(Coin other) {
        return compareTo(other) < 0;
    }

    public Coin shiftLeft(final int n) {
        return new Coin(this.value << n);
    }

    public Coin shiftRight(final int n) {
        return new Coin(this.value >> n);
    }

    @Override
    public int signum() {
        if (this.value == 0)
            return 0;
        return this.value < 0 ? -1 : 1;
    }

    public Coin negate() {
        return new Coin(-this.value);
    }

    /**
     * Returns the number of satoshis of this monetary value. It's deprecated in favour of accessing {@link #value}
     * directly.
     */
    public long longValue() {
        return this.value;
    }

    private static final MonetaryFormat FRIENDLY_FORMAT = MonetaryFormat.BTC.minDecimals(2).repeatOptionalDecimals(1, 6).postfixCode();

    /**
     * Returns the value as a 0.12 type string. More digits after the decimal place will be used
     * if necessary, but two will always be present.
     */
    public String toFriendlyString() {
        return FRIENDLY_FORMAT.format(this).toString();
    }

    private static final MonetaryFormat PLAIN_FORMAT = MonetaryFormat.BTC.minDecimals(0).repeatOptionalDecimals(1, 8).noCode();

    /**
     * <p>
     * Returns the value as a plain string denominated in BTC.
     * The result is unformatted with no trailing zeroes.
     * For instance, a value of 150000 satoshis gives an output string of "0.0015" BTC
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
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return this.value == ((Coin)o).value;
    }

    @Override
    public int hashCode() {
        return (int) this.value;
    }

    @Override
    public int compareTo(final Coin other) {
        return Longs.compare(this.value, other.value);
    }
}
