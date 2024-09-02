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

package org.bitcoinj.base;

import org.bitcoinj.base.utils.MonetaryFormat;

import java.math.BigDecimal;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * Represents a monetary Bitcoin value. This class is immutable and should be treated as a Java <a href="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/doc-files/ValueBased.html#Value-basedClasses">Value-based class</a>.
 * We recommend using the {@code Coin} class wherever possible to represent Bitcoin monetary values. If you have existing
 * code that uses other numeric types and need to convert there are conversion methods.
 * <p>
 * Internally {@code Coin} is implemented as a {@code long} (see {@link #value}) that represents a number of <a href="https://en.bitcoin.it/wiki/Satoshi_(unit)">satoshis</a>. It
 * can also be considered a <a href="https://en.wikipedia.org/wiki/Fixed-point_arithmetic">fixed-point</a> number of <a href="https://en.bitcoin.it/wiki/Units">bitcoins</a>.
 * <p>
 * To create a {@code Coin} from an integer number of satoshis, use {@link #ofSat(long)}. To convert to a {@code long} number
 * of satoshis use {@link #toSat()}. (You can also use {@link #valueOf(long)}, {@link #getValue()} or {@link #value}.)
 * <p>
 * To create a {@code Coin} from a decimal number of bitcoins, use {@link #ofBtc(BigDecimal)}. To convert to a {@link BigDecimal}
 * of bitcoins use {@link #toBtc()}. (Performing fixed-point <a href="https://en.wikipedia.org/wiki/Fixed-point_arithmetic#Conversion_to_and_from_floating-point">conversion</a>, these methods essentially multiply or divide by {@code Coin.COIN.toSat()}.)
 * <p>
 * <b>Never ever</b> use {@code float} or {@code double} to represent monetary values.
 */
public final class Coin implements Monetary, Comparable<Coin> {

    /**
     * Number of decimals for one Bitcoin. This constant is useful for quick adapting to other coins because a lot of
     * constants derive from it.
     */
    public static final int SMALLEST_UNIT_EXPONENT = 8;

    /**
     * The number of satoshis equal to one bitcoin.
     */
    private static final long COIN_VALUE = 100_000_000;

    /**
     * Zero Bitcoins.
     */
    public static final Coin ZERO = new Coin(0);

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

    /** Number of bytes to store this amount. */
    public static final int BYTES = 8;

    /**
     * The number of satoshis of this monetary value.
     */
    public final long value;

    private Coin(final long satoshis) {
        this.value = satoshis;
    }

    /**
     * Create a {@code Coin} from a long integer number of satoshis.
     *
     * @param satoshis number of satoshis
     * @return {@code Coin} object containing value in satoshis
     */
    public static Coin valueOf(final long satoshis) {
        // Avoid allocating a new object for Coins of value zero
        return satoshis == 0 ? Coin.ZERO : new Coin(satoshis);
    }

    /**
     * Read a Coin amount from the given buffer as 8 bytes in little-endian order.
     *
     * @param buf buffer to read from
     * @return read amount
     * @throws BufferUnderflowException if the read value extends beyond the remaining bytes of the buffer
     */
    public static Coin read(ByteBuffer buf) throws BufferUnderflowException {
        return valueOf(buf.order(ByteOrder.LITTLE_ENDIAN).getLong());
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
     * Create a {@code Coin} from an amount expressed in "the way humans are used to".
     *
     * @param coins Number of bitcoins
     * @param cents Number of bitcents (0.01 bitcoin)
     * @return {@code Coin} object containing value in satoshis
     */
    public static Coin valueOf(final int coins, final int cents) {
        checkArgument(cents < 100, () -> "cents nust be below 100: " + cents);
        checkArgument(cents >= 0, () -> "cents cannot be negative: " + cents);
        checkArgument(coins >= 0, () -> "coins cannot be negative: " + cents);
        final Coin coin = COIN.multiply(coins).add(CENT.multiply(cents));
        return coin;
    }

    /**
     * Convert a decimal amount of BTC into satoshis.
     *
     * @param coins number of coins
     * @return number of satoshis
     * @throws ArithmeticException if value has too much precision or will not fit in a long
     */
    public static long btcToSatoshi(BigDecimal coins) throws ArithmeticException {
        return coins.movePointRight(SMALLEST_UNIT_EXPONENT).longValueExact();
    }

    /**
     * Convert an amount in satoshis to an amount in BTC.
     *
     * @param satoshis number of satoshis
     * @return number of bitcoins (in BTC)
     */
    public static BigDecimal satoshiToBtc(long satoshis) {
        return new BigDecimal(satoshis).movePointLeft(SMALLEST_UNIT_EXPONENT);
    }

    /**
     * Create a {@code Coin} from a decimal amount of BTC.
     *
     * @param coins number of coins (in BTC)
     * @return {@code Coin} object containing value in satoshis
     * @throws ArithmeticException if value has too much precision or will not fit in a long
     */
    public static Coin ofBtc(BigDecimal coins) throws ArithmeticException {
        return Coin.valueOf(btcToSatoshi(coins));
    }

    /**
     * Create a {@code Coin} from a long integer number of satoshis.
     *
     * @param satoshis number of satoshis
     * @return {@code Coin} object containing value in satoshis
     */
    public static Coin ofSat(long satoshis) {
        return Coin.valueOf(satoshis);
    }

    /**
     * Create a {@code Coin} by parsing a {@code String} amount expressed in "the way humans are used to".
     * 
     * @param str string in a format understood by {@link BigDecimal#BigDecimal(String)}, for example "0", "1", "0.10",
     *      * "1.23E3", "1234.5E-5".
     * @return {@code Coin} object containing value in satoshis
     * @throws IllegalArgumentException
     *             if you try to specify fractional satoshis, or a value out of range.
     */
    public static Coin parseCoin(final String str) {
        try {
            long satoshis = btcToSatoshi(new BigDecimal(str));
            return Coin.valueOf(satoshis);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(e); // Repackage exception to honor method contract
        }
    }

    /**
     * Create a {@code Coin} by parsing a {@code String} amount expressed in "the way humans are used to".
     * The amount is cut to satoshi precision.
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
        return Coin.valueOf(Math.addExact(this.value, value.value));
    }

    /** Alias for add */
    public Coin plus(final Coin value) {
        return add(value);
    }

    public Coin subtract(final Coin value) {
        return Coin.valueOf(Math.subtractExact(this.value, value.value));
    }

    /** Alias for subtract */
    public Coin minus(final Coin value) {
        return subtract(value);
    }

    public Coin multiply(final long factor) {
        return Coin.valueOf(Math.multiplyExact(this.value, factor));
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
        return Coin.valueOf(this.value / divisor);
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
        return new Coin[] { Coin.valueOf(this.value / divisor), Coin.valueOf(this.value % divisor) };
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
        return Coin.valueOf(this.value << n);
    }

    public Coin shiftRight(final int n) {
        return Coin.valueOf(this.value >> n);
    }

    @Override
    public int signum() {
        if (this.value == 0)
            return 0;
        return this.value < 0 ? -1 : 1;
    }

    public Coin negate() {
        return Coin.valueOf(-this.value);
    }

    /**
     * Returns the number of satoshis of this monetary value. It's deprecated in favour of accessing {@link #value}
     * directly.
     */
    public long longValue() {
        return this.value;
    }

    /**
     * Convert to number of satoshis
     *
     * @return decimal number of satoshis
     */
    public long toSat() {
        return this.value;
    }

    /**
     * Convert to number of bitcoin (in BTC)
     *
     * @return decimal number of bitcoin (in BTC)
     */
    public BigDecimal toBtc() {
        return satoshiToBtc(this.value);
    }

    /**
     * Write the amount into the given buffer as 8 bytes in little-endian order.
     *
     * @param buf buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the value doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        return buf.order(ByteOrder.LITTLE_ENDIAN).putLong(this.value);
    }

    /**
     * Allocates a byte array and serializes the amount.
     *
     * @return serialized amount
     */
    public byte[] serialize() {
        ByteBuffer buf = ByteBuffer.allocate(BYTES);
        return write(buf).array();
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
        return Long.compare(this.value, other.value);
    }
}
