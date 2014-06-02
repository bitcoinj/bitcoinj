/**
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

package com.google.bitcoin.core;

import static com.google.common.base.Preconditions.checkArgument;

import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;

import com.google.common.math.LongMath;

/**
 * Represents a monetary Bitcoin value. This class is immutable.
 */
public final class Coin implements Comparable<Coin>, Serializable {

    /**
     * Zero Bitcoins.
     */
    public static final Coin ZERO = Coin.valueOf(0);

    /**
     * One Bitcoin.
     */
    public static final Coin COIN = Coin.valueOf(100000000);

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
    public static final Coin NEGATIVE_ONE = Coin.valueOf(-1);

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

    /**
     * Convert an amount expressed in the way humans are used to into satoshis.
     */
    public static Coin valueOf(final int coins, final int cents) {
        checkArgument(cents < 100);
        checkArgument(cents >= 0);
        checkArgument(coins >= 0);
        final Coin coin = COIN.multiply(coins).add(CENT.multiply(cents));
        checkArgument(coin.compareTo(NetworkParameters.MAX_MONEY) <= 0);
        return coin;
    }

    /**
     * Parses an amount expressed in the way humans are used to.<p>
     * <p/>
     * This takes string in a format understood by {@link BigDecimal#BigDecimal(String)},
     * for example "0", "1", "0.10", "1.23E3", "1234.5E-5".
     *
     * @throws ArithmeticException if you try to specify fractional satoshis, or a value out of range.
     */
    public static Coin parseCoin(final String str) {
        Coin coin = Coin.valueOf(new BigDecimal(str).movePointRight(8).toBigIntegerExact().longValue());
        if (coin.signum() < 0)
            throw new ArithmeticException("Negative coins specified");
        if (coin.compareTo(NetworkParameters.MAX_MONEY) > 0)
            throw new ArithmeticException("Amount larger than the total quantity of Bitcoins possible specified.");
        return coin;
    }

    public Coin add(final Coin value) {
        return new Coin(LongMath.checkedAdd(this.value, value.value));
    }

    public Coin subtract(final Coin value) {
        return new Coin(LongMath.checkedSubtract(this.value, value.value));
    }

    public Coin multiply(final long factor) {
        return new Coin(LongMath.checkedMultiply(this.value, factor));
    }

    public Coin divide(final long divisor) {
        return new Coin(this.value / divisor);
    }

    public Coin[] divideAndRemainder(final long divisor) {
        return new Coin[] { new Coin(this.value / divisor), new Coin(this.value % divisor) };
    }

    public long divide(final Coin divisor) {
        return this.value / divisor.value;
    }

    public Coin shiftLeft(final int n) {
        return new Coin(this.value << n);
    }

    public Coin shiftRight(final int n) {
        return new Coin(this.value >> n);
    }

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

    /**
     * Returns the value as a 0.12 type string. More digits after the decimal place will be used
     * if necessary, but two will always be present.
     */
    public String toFriendlyString() {
        Coin value = this;
        boolean negative = value.signum() < 0;
        if (negative)
            value = value.negate();
        BigDecimal bd = new BigDecimal(BigInteger.valueOf(value.value), 8);
        String formatted = bd.toPlainString();   // Don't use scientific notation.
        int decimalPoint = formatted.indexOf(".");
        // Drop unnecessary zeros from the end.
        int toDelete = 0;
        for (int i = formatted.length() - 1; i > decimalPoint + 2; i--) {
            if (formatted.charAt(i) == '0')
                toDelete++;
            else
                break;
        }
        return (negative ? "-" : "") + formatted.substring(0, formatted.length() - toDelete);
    }

    /**
     * <p>
     * Returns the value as a plain string denominated in BTC.
     * The result is unformatted with no trailing zeroes.
     * For instance, a value of 150000 satoshis gives an output string of "0.0015" BTC
     * </p>
     */
    public String toPlainString() {
        BigDecimal valueInBTC = new BigDecimal(BigInteger.valueOf(value)).divide(new BigDecimal(BigInteger.valueOf(COIN.value)));
        return valueInBTC.toPlainString();
    }

    @Override
    public String toString() {
        return Long.toString(value);
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this)
            return true;
        if (o == null || o.getClass() != getClass())
            return false;
        final Coin other = (Coin) o;
        if (this.value != other.value)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        return (int) this.value;
    }

    @Override
    public int compareTo(final Coin other) {
        if (this.value == other.value)
            return 0;
        return this.value > other.value ? 1 : -1;
    }
}
