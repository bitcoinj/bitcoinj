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

package com.google.bitcoin.utils;

import static com.google.common.base.Preconditions.checkArgument;

import java.io.Serializable;
import java.math.BigInteger;

import com.google.bitcoin.core.Coin;

/**
 * An exchange rate is expressed as a ratio of a {@link Coin} and a {@link Fiat} amount.
 */
public class ExchangeRate implements Serializable {

    public final Coin coin;
    public final Fiat fiat;

    public ExchangeRate(Coin coin, Fiat fiat) {
        this.coin = coin;
        this.fiat = fiat;
    }

    public ExchangeRate(Fiat fiat) {
        this.coin = Coin.COIN;
        this.fiat = fiat;
    }

    public Fiat coinToFiat(Coin convertCoin) {
        // Use BigInteger because it's much easier to maintain full precision without overflowing.
        final BigInteger converted = BigInteger.valueOf(convertCoin.value).multiply(BigInteger.valueOf(fiat.value))
                .divide(BigInteger.valueOf(coin.value));
        if (converted.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || converted.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0)
            throw new ArithmeticException("Overflow");
        return Fiat.valueOf(fiat.currencyCode, converted.longValue());
    }

    public Coin fiatToCoin(Fiat convertFiat) {
        checkArgument(convertFiat.currencyCode.equals(fiat.currencyCode), "Currency mismatch: %s vs %s",
                convertFiat.currencyCode, fiat.currencyCode);
        // Use BigInteger because it's much easier to maintain full precision without overflowing.
        final BigInteger converted = BigInteger.valueOf(convertFiat.value).multiply(BigInteger.valueOf(coin.value))
                .divide(BigInteger.valueOf(fiat.value));
        if (converted.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || converted.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0)
            throw new ArithmeticException("Overflow");
        return Coin.valueOf(converted.longValue());
    }
}
