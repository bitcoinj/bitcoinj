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

package com.google.bitcoin.utils;

import static com.google.bitcoin.core.Coin.COIN;
import static com.google.bitcoin.core.Coin.SATOSHI;
import static com.google.bitcoin.core.Coin.ZERO;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.google.bitcoin.core.Coin;

public class CoinFormatTest {

    @Test
    public void testSigns() throws Exception {
        assertEquals("-1.00", CoinFormat.BTC.format(Coin.COIN.negate()).toString());
        assertEquals("@1.00", CoinFormat.BTC.negativeSign('@').format(Coin.COIN.negate()).toString());
        assertEquals("1.00", CoinFormat.BTC.format(Coin.COIN).toString());
        assertEquals("+1.00", CoinFormat.BTC.positiveSign('+').format(Coin.COIN).toString());
    }

    @Test
    public void testDecimalMark() throws Exception {
        assertEquals("1.00", CoinFormat.BTC.format(Coin.COIN).toString());
        assertEquals("1,00", CoinFormat.BTC.decimalMark(',').format(Coin.COIN).toString());
    }

    @Test
    public void testGrouping() throws Exception {
        assertEquals("0.1", format(Coin.parseCoin("0.1"), 0, 1, 2, 3));
        assertEquals("0.010", format(Coin.parseCoin("0.01"), 0, 1, 2, 3));
        assertEquals("0.001", format(Coin.parseCoin("0.001"), 0, 1, 2, 3));
        assertEquals("0.000100", format(Coin.parseCoin("0.0001"), 0, 1, 2, 3));
        assertEquals("0.000010", format(Coin.parseCoin("0.00001"), 0, 1, 2, 3));
        assertEquals("0.000001", format(Coin.parseCoin("0.000001"), 0, 1, 2, 3));
    }

    @Test
    public void btcRounding() throws Exception {
        assertEquals("0", format(ZERO, 0, 0));
        assertEquals("0.00", format(ZERO, 0, 2));

        assertEquals("1", format(COIN, 0, 0));
        assertEquals("1.0", format(COIN, 0, 1));
        assertEquals("1.00", format(COIN, 0, 2, 2));
        assertEquals("1.00", format(COIN, 0, 2, 2, 2));
        assertEquals("1.00", format(COIN, 0, 2, 2, 2, 2));
        assertEquals("1.000", format(COIN, 0, 3));
        assertEquals("1.0000", format(COIN, 0, 4));

        final Coin justNot = COIN.subtract(SATOSHI);
        assertEquals("1", format(justNot, 0, 0));
        assertEquals("1.0", format(justNot, 0, 1));
        assertEquals("1.00", format(justNot, 0, 2, 2));
        assertEquals("1.00", format(justNot, 0, 2, 2, 2));
        assertEquals("0.99999999", format(justNot, 0, 2, 2, 2, 2));
        assertEquals("1.000", format(justNot, 0, 3));
        assertEquals("1.0000", format(justNot, 0, 4));

        final Coin slightlyMore = COIN.add(SATOSHI);
        assertEquals("1", format(slightlyMore, 0, 0));
        assertEquals("1.0", format(slightlyMore, 0, 1));
        assertEquals("1.00", format(slightlyMore, 0, 2, 2));
        assertEquals("1.00", format(slightlyMore, 0, 2, 2, 2));
        assertEquals("1.00000001", format(slightlyMore, 0, 2, 2, 2, 2));
        assertEquals("1.000", format(slightlyMore, 0, 3));
        assertEquals("1.0000", format(slightlyMore, 0, 4));

        final Coin pivot = COIN.add(SATOSHI.multiply(5));
        assertEquals("1.00000005", format(pivot, 0, 8));
        assertEquals("1.00000005", format(pivot, 0, 7, 1));
        assertEquals("1.0000001", format(pivot, 0, 7));

        final Coin value = Coin.valueOf(1122334455667788l);
        assertEquals("11223345", format(value, 0, 0));
        assertEquals("11223344.6", format(value, 0, 1));
        assertEquals("11223344.5567", format(value, 0, 2, 2));
        assertEquals("11223344.556678", format(value, 0, 2, 2, 2));
        assertEquals("11223344.55667788", format(value, 0, 2, 2, 2, 2));
        assertEquals("11223344.557", format(value, 0, 3));
        assertEquals("11223344.5567", format(value, 0, 4));
    }

    @Test
    public void mBtcRounding() throws Exception {
        assertEquals("0", format(ZERO, 3, 0));
        assertEquals("0.00", format(ZERO, 3, 2));

        assertEquals("1000", format(COIN, 3, 0));
        assertEquals("1000.0", format(COIN, 3, 1));
        assertEquals("1000.00", format(COIN, 3, 2));
        assertEquals("1000.00", format(COIN, 3, 2, 2));
        assertEquals("1000.000", format(COIN, 3, 3));
        assertEquals("1000.0000", format(COIN, 3, 4));

        final Coin justNot = COIN.subtract(SATOSHI.multiply(10));
        assertEquals("1000", format(justNot, 3, 0));
        assertEquals("1000.0", format(justNot, 3, 1));
        assertEquals("1000.00", format(justNot, 3, 2));
        assertEquals("999.9999", format(justNot, 3, 2, 2));
        assertEquals("1000.000", format(justNot, 3, 3));
        assertEquals("999.9999", format(justNot, 3, 4));

        final Coin slightlyMore = COIN.add(SATOSHI.multiply(10));
        assertEquals("1000", format(slightlyMore, 3, 0));
        assertEquals("1000.0", format(slightlyMore, 3, 1));
        assertEquals("1000.00", format(slightlyMore, 3, 2));
        assertEquals("1000.000", format(slightlyMore, 3, 3));
        assertEquals("1000.0001", format(slightlyMore, 3, 2, 2));
        assertEquals("1000.0001", format(slightlyMore, 3, 4));

        final Coin pivot = COIN.add(SATOSHI.multiply(50));
        assertEquals("1000.0005", format(pivot, 3, 4));
        assertEquals("1000.0005", format(pivot, 3, 3, 1));
        assertEquals("1000.001", format(pivot, 3, 3));

        final Coin value = Coin.valueOf(1122334455667788l);
        assertEquals("11223344557", format(value, 3, 0));
        assertEquals("11223344556.7", format(value, 3, 1));
        assertEquals("11223344556.68", format(value, 3, 2));
        assertEquals("11223344556.6779", format(value, 3, 2, 2));
        assertEquals("11223344556.678", format(value, 3, 3));
        assertEquals("11223344556.6779", format(value, 3, 4));
    }

    @Test
    public void uBtcRounding() throws Exception {
        assertEquals("0", format(ZERO, 6, 0));
        assertEquals("0.00", format(ZERO, 6, 2));

        assertEquals("1000000", format(COIN, 6, 0));
        assertEquals("1000000", format(COIN, 6, 0, 2));
        assertEquals("1000000.0", format(COIN, 6, 1));
        assertEquals("1000000.00", format(COIN, 6, 2));

        final Coin justNot = COIN.subtract(SATOSHI);
        assertEquals("1000000", format(justNot, 6, 0));
        assertEquals("999999.99", format(justNot, 6, 0, 2));
        assertEquals("1000000.0", format(justNot, 6, 1));
        assertEquals("999999.99", format(justNot, 6, 2));

        final Coin slightlyMore = COIN.add(SATOSHI);
        assertEquals("1000000", format(slightlyMore, 6, 0));
        assertEquals("1000000.01", format(slightlyMore, 6, 0, 2));
        assertEquals("1000000.0", format(slightlyMore, 6, 1));
        assertEquals("1000000.01", format(slightlyMore, 6, 2));

        final Coin pivot = COIN.add(SATOSHI.multiply(5));
        assertEquals("1000000.05", format(pivot, 6, 2));
        assertEquals("1000000.05", format(pivot, 6, 0, 2));
        assertEquals("1000000.1", format(pivot, 6, 1));
        assertEquals("1000000.1", format(pivot, 6, 0, 1));

        final Coin value = Coin.valueOf(1122334455667788l);
        assertEquals("11223344556678", format(value, 6, 0));
        assertEquals("11223344556677.88", format(value, 6, 2));
        assertEquals("11223344556677.9", format(value, 6, 1));
        assertEquals("11223344556677.88", format(value, 6, 2));
    }

    private String format(Coin coin, int shift, int minDecimals, int... decimalGroups) {
        return new CoinFormat().shift(shift).minDecimals(minDecimals).optionalDecimals(decimalGroups).format(coin)
                .toString();
    }

    @Test
    public void parse() throws Exception {
        assertEquals(Coin.COIN, CoinFormat.BTC.parse("1"));
        assertEquals(Coin.COIN, CoinFormat.BTC.parse("1."));
        assertEquals(Coin.COIN, CoinFormat.BTC.parse("1.0"));
        assertEquals(Coin.COIN, CoinFormat.BTC.decimalMark(',').parse("1,0"));
        assertEquals(Coin.COIN, CoinFormat.BTC.parse("01.0000000000"));
        assertEquals(Coin.COIN, CoinFormat.BTC.positiveSign('+').parse("+1.0"));
        assertEquals(Coin.COIN.negate(), CoinFormat.BTC.parse("-1"));
        assertEquals(Coin.COIN.negate(), CoinFormat.BTC.parse("-1.0"));

        assertEquals(Coin.CENT, CoinFormat.BTC.parse(".01"));

        assertEquals(Coin.MILLICOIN, CoinFormat.MBTC.parse("1"));
        assertEquals(Coin.MILLICOIN, CoinFormat.MBTC.parse("1.0"));
        assertEquals(Coin.MILLICOIN, CoinFormat.MBTC.parse("01.0000000000"));
        assertEquals(Coin.MILLICOIN, CoinFormat.MBTC.positiveSign('+').parse("+1.0"));
        assertEquals(Coin.MILLICOIN.negate(), CoinFormat.MBTC.parse("-1"));
        assertEquals(Coin.MILLICOIN.negate(), CoinFormat.MBTC.parse("-1.0"));

        assertEquals(Coin.MICROCOIN, CoinFormat.UBTC.parse("1"));
        assertEquals(Coin.MICROCOIN, CoinFormat.UBTC.parse("1.0"));
        assertEquals(Coin.MICROCOIN, CoinFormat.UBTC.parse("01.0000000000"));
        assertEquals(Coin.MICROCOIN, CoinFormat.UBTC.positiveSign('+').parse("+1.0"));
        assertEquals(Coin.MICROCOIN.negate(), CoinFormat.UBTC.parse("-1"));
        assertEquals(Coin.MICROCOIN.negate(), CoinFormat.UBTC.parse("-1.0"));
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidEmpty() throws Exception {
        CoinFormat.BTC.parse("");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidWhitespaceBefore() throws Exception {
        CoinFormat.BTC.parse(" 1");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidWhitespaceSign() throws Exception {
        CoinFormat.BTC.parse("- 1");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidWhitespaceAfter() throws Exception {
        CoinFormat.BTC.parse("1 ");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidMultipleDecimalMarks() throws Exception {
        CoinFormat.BTC.parse("1.0.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidDecimalMark() throws Exception {
        CoinFormat.BTC.decimalMark(',').parse("1.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidPositiveSign() throws Exception {
        CoinFormat.BTC.positiveSign('@').parse("+1.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidNegativeSign() throws Exception {
        CoinFormat.BTC.negativeSign('@').parse("-1.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidHugeNumber() throws Exception {
        System.out.println(CoinFormat.BTC.parse("99999999999999999999"));
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidHugeNegativeNumber() throws Exception {
        System.out.println(CoinFormat.BTC.parse("-99999999999999999999"));
    }
}
