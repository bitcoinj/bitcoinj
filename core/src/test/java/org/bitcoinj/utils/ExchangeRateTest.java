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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import org.bitcoinj.core.Coin;

public class ExchangeRateTest {

    @Test
    public void normalRate() throws Exception {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("EUR", "500"));
        assertEquals("0.5", rate.coinToFiat(Coin.MILLICOIN).toPlainString());
        assertEquals("0.002", rate.fiatToCoin(Fiat.parseFiat("EUR", "1")).toPlainString());
    }

    @Test
    public void bigRate() throws Exception {
        ExchangeRate rate = new ExchangeRate(Coin.parseCoin("0.0001"), Fiat.parseFiat("BYR", "5320387.3"));
        assertEquals("53203873000", rate.coinToFiat(Coin.COIN).toPlainString());
        assertEquals("0", rate.fiatToCoin(Fiat.parseFiat("BYR", "1")).toPlainString()); // Tiny value!
    }

    @Test
    public void smallRate() throws Exception {
        ExchangeRate rate = new ExchangeRate(Coin.parseCoin("1000"), Fiat.parseFiat("XXX", "0.0001"));
        assertEquals("0", rate.coinToFiat(Coin.COIN).toPlainString()); // Tiny value!
        assertEquals("10000000", rate.fiatToCoin(Fiat.parseFiat("XXX", "1")).toPlainString());
    }

    @Test(expected = IllegalArgumentException.class)
    public void currencyCodeMismatch() throws Exception {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("EUR", "500"));
        rate.fiatToCoin(Fiat.parseFiat("USD", "1"));
    }

    @Test(expected = ArithmeticException.class)
    public void fiatToCoinTooLarge() throws Exception {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("XXX", "1"));
        rate.fiatToCoin(Fiat.parseFiat("XXX", "21000001"));
    }

    @Test(expected = ArithmeticException.class)
    public void fiatToCoinTooSmall() throws Exception {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("XXX", "1"));
        rate.fiatToCoin(Fiat.parseFiat("XXX", "-21000001"));
    }

    @Test(expected = ArithmeticException.class)
    public void coinToFiatTooLarge() throws Exception {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("XXX", "1000000000"));
        rate.coinToFiat(Coin.parseCoin("1000000"));
    }

    @Test(expected = ArithmeticException.class)
    public void coinToFiatTooSmall() throws Exception {
        ExchangeRate rate = new ExchangeRate(Fiat.parseFiat("XXX", "1000000000"));
        rate.coinToFiat(Coin.parseCoin("-1000000"));
    }
}
