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
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ExchangeRateTest {

    @Test
    public void normalRate() {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("EUR", "500"));
        assertEquals("0.5", rate.coinToFiat(Coin.MILLICOIN).toPlainString());
        assertEquals("0.002", rate.fiatToCoin(Fiat.parseFiat("EUR", "1")).toPlainString());
    }

    @Test
    public void bigRate() {
        ExchangeRate rate = new ExchangeRate(Coin.parseCoin("0.0001"), Fiat.parseFiat("BYR", "5320387.3"));
        assertEquals("53203873000", rate.coinToFiat(Coin.COIN).toPlainString());
        assertEquals("0", rate.fiatToCoin(Fiat.parseFiat("BYR", "1")).toPlainString()); // Tiny value!
    }

    @Test
    public void smallRate() {
        ExchangeRate rate = new ExchangeRate(Coin.parseCoin("1000"), Fiat.parseFiat("XXX", "0.0001"));
        assertEquals("0", rate.coinToFiat(Coin.COIN).toPlainString()); // Tiny value!
        assertEquals("10000000", rate.fiatToCoin(Fiat.parseFiat("XXX", "1")).toPlainString());
    }

    @Test(expected = IllegalArgumentException.class)
    public void currencyCodeMismatch() {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("EUR", "500"));
        rate.fiatToCoin(Fiat.parseFiat("USD", "1"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructMissingCurrencyCode() {
        new ExchangeRate(Fiat.valueOf(null, 1));
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructNegativeCoin() {
        new ExchangeRate(Coin.valueOf(-1), Fiat.valueOf("EUR", 1));
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructFiatCoin() {
        new ExchangeRate(Fiat.valueOf("EUR", -1));
    }
}
