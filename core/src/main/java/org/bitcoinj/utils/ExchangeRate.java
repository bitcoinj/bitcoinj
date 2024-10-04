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

import org.bitcoinj.base.utils.Fiat;
import org.bitcoinj.base.Coin;

import java.math.BigInteger;
import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * An exchange rate is expressed as a ratio of a {@link Coin} and a {@link Fiat} amount.
 */
public class ExchangeRate {

    public final Coin coin;
    public final Fiat fiat;

    /** Construct exchange rate. This amount of coin is worth that amount of fiat. */
    public ExchangeRate(Coin coin, Fiat fiat) {
        checkArgument(coin.isPositive());
        checkArgument(fiat.isPositive());
        checkArgument(fiat.currencyCode != null, () ->
                "currency code required");
        this.coin = coin;
        this.fiat = fiat;
    }

    /** Construct exchange rate. One coin is worth this amount of fiat. */
    public ExchangeRate(Fiat fiat) {
        this(Coin.COIN, fiat);
    }

    /**
     * Convert a coin amount to a fiat amount using this exchange rate.
     */
    public Fiat coinToFiat(Coin convertCoin) {
        // Use BigInteger because it's much easier to maintain full precision without overflowing.
        final BigInteger converted = convert(convertCoin.value, fiat.value, coin.value);

        checkOverflow(converted);

        return Fiat.valueOf(fiat.currencyCode, converted.longValue());
    }

    /**
     * Convert a fiat amount to a coin amount using this exchange rate.
     * @throws ArithmeticException if the converted coin amount is too high or too low.
     */
    public Coin fiatToCoin(Fiat convertFiat) {
        checkArgument(convertFiat.currencyCode.equals(fiat.currencyCode), () ->
                "currency mismatch: " + convertFiat.currencyCode + " vs " + fiat.currencyCode);

        // Use BigInteger because it's much easier to maintain full precision without overflowing.
        final BigInteger converted = convert(convertFiat.value, coin.value, fiat.value);

        checkOverflow(converted);

        try {
            return Coin.valueOf(converted.longValue());
        } catch (IllegalArgumentException x) {
            throw new ArithmeticException("Overflow: " + x.getMessage());
        }
    }

    /**
     * Checks for overflow in the BigInteger value.
     * @throws ArithmeticException if the value is outside the range of Long.MIN_VALUE to Long.MAX_VALUE.
     */
    private void checkOverflow(BigInteger value) throws ArithmeticException {
        if (value.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || value.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0) {
            throw new ArithmeticException("Overflow");
        }
    }

    /**
     * Common conversion logic.
     */
    private BigInteger convert(long fromValue, long toValue, long targetValue) {
        return BigInteger.valueOf(fromValue).multiply(BigInteger.valueOf(toValue))
                .divide(BigInteger.valueOf(targetValue));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExchangeRate other = (ExchangeRate) o;
        return Objects.equals(this.coin, other.coin) && Objects.equals(this.fiat, other.fiat);
    }

    @Override
    public int hashCode() {
        return Objects.hash(coin, fiat);
    }
}
