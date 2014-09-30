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

import static org.bitcoinj.core.Coin.CENT;
import static org.bitcoinj.core.Coin.COIN;
import static org.bitcoinj.core.Coin.SATOSHI;
import static org.bitcoinj.core.Coin.ZERO;
import static org.junit.Assert.assertEquals;

import java.util.Locale;

import org.junit.Test;

import org.bitcoinj.core.Coin;

public class MonetaryFormatTest {

    private static final MonetaryFormat NO_CODE = MonetaryFormat.BTC.noCode();

    @Test
    public void testSigns() throws Exception {
        assertEquals("-1.00", NO_CODE.format(Coin.COIN.negate()).toString());
        assertEquals("@1.00", NO_CODE.negativeSign('@').format(Coin.COIN.negate()).toString());
        assertEquals("1.00", NO_CODE.format(Coin.COIN).toString());
        assertEquals("+1.00", NO_CODE.positiveSign('+').format(Coin.COIN).toString());
    }

    @Test
    public void testDigits() throws Exception {
        assertEquals("١٢.٣٤٥٦٧٨٩٠", NO_CODE.digits('\u0660').format(Coin.valueOf(1234567890l)).toString());
    }

    @Test
    public void testDecimalMark() throws Exception {
        assertEquals("1.00", NO_CODE.format(Coin.COIN).toString());
        assertEquals("1,00", NO_CODE.decimalMark(',').format(Coin.COIN).toString());
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
        return NO_CODE.shift(shift).minDecimals(minDecimals).optionalDecimals(decimalGroups).format(coin).toString();
    }

    @Test
    public void repeatOptionalDecimals() {
        assertEquals("0.00000001", formatRepeat(SATOSHI, 2, 4));
        assertEquals("0.00000010", formatRepeat(SATOSHI.multiply(10), 2, 4));
        assertEquals("0.01", formatRepeat(CENT, 2, 4));
        assertEquals("0.10", formatRepeat(CENT.multiply(10), 2, 4));

        assertEquals("0", formatRepeat(SATOSHI, 2, 2));
        assertEquals("0", formatRepeat(SATOSHI.multiply(10), 2, 2));
        assertEquals("0.01", formatRepeat(CENT, 2, 2));
        assertEquals("0.10", formatRepeat(CENT.multiply(10), 2, 2));

        assertEquals("0", formatRepeat(CENT, 2, 0));
        assertEquals("0", formatRepeat(CENT.multiply(10), 2, 0));
    }

    private String formatRepeat(Coin coin, int decimals, int repetitions) {
        return NO_CODE.minDecimals(0).repeatOptionalDecimals(decimals, repetitions).format(coin).toString();
    }

    @Test
    public void standardCodes() throws Exception {
        assertEquals("BTC 0.00", MonetaryFormat.BTC.format(Coin.ZERO).toString());
        assertEquals("mBTC 0.00", MonetaryFormat.MBTC.format(Coin.ZERO).toString());
        assertEquals("µBTC 0", MonetaryFormat.UBTC.format(Coin.ZERO).toString());
    }

    @Test
    public void customCode() throws Exception {
        assertEquals("dBTC 0", MonetaryFormat.UBTC.code(1, "dBTC").shift(1).format(Coin.ZERO).toString());
    }

    @Test
    public void codeOrientation() throws Exception {
        assertEquals("BTC 0.00", MonetaryFormat.BTC.prefixCode().format(Coin.ZERO).toString());
        assertEquals("0.00 BTC", MonetaryFormat.BTC.postfixCode().format(Coin.ZERO).toString());
    }

    @Test
    public void codeSeparator() throws Exception {
        assertEquals("BTC@0.00", MonetaryFormat.BTC.codeSeparator('@').format(Coin.ZERO).toString());
    }

    @Test(expected = NumberFormatException.class)
    public void missingCode() throws Exception {
        MonetaryFormat.UBTC.shift(1).format(Coin.ZERO);
    }

    @Test
    public void withLocale() throws Exception {
        final Coin value = Coin.valueOf(-1234567890l);
        assertEquals("-12.34567890", NO_CODE.withLocale(Locale.US).format(value).toString());
        assertEquals("-12,34567890", NO_CODE.withLocale(Locale.GERMANY).format(value).toString());
        assertEquals("-१२.३४५६७८९०", NO_CODE.withLocale(new Locale("hi", "IN")).format(value).toString()); // Devanagari
    }

    @Test
    public void parse() throws Exception {
        assertEquals(Coin.COIN, NO_CODE.parse("1"));
        assertEquals(Coin.COIN, NO_CODE.parse("1."));
        assertEquals(Coin.COIN, NO_CODE.parse("1.0"));
        assertEquals(Coin.COIN, NO_CODE.decimalMark(',').parse("1,0"));
        assertEquals(Coin.COIN, NO_CODE.parse("01.0000000000"));
        assertEquals(Coin.COIN, NO_CODE.positiveSign('+').parse("+1.0"));
        assertEquals(Coin.COIN.negate(), NO_CODE.parse("-1"));
        assertEquals(Coin.COIN.negate(), NO_CODE.parse("-1.0"));

        assertEquals(Coin.CENT, NO_CODE.parse(".01"));

        assertEquals(Coin.MILLICOIN, MonetaryFormat.MBTC.parse("1"));
        assertEquals(Coin.MILLICOIN, MonetaryFormat.MBTC.parse("1.0"));
        assertEquals(Coin.MILLICOIN, MonetaryFormat.MBTC.parse("01.0000000000"));
        assertEquals(Coin.MILLICOIN, MonetaryFormat.MBTC.positiveSign('+').parse("+1.0"));
        assertEquals(Coin.MILLICOIN.negate(), MonetaryFormat.MBTC.parse("-1"));
        assertEquals(Coin.MILLICOIN.negate(), MonetaryFormat.MBTC.parse("-1.0"));

        assertEquals(Coin.MICROCOIN, MonetaryFormat.UBTC.parse("1"));
        assertEquals(Coin.MICROCOIN, MonetaryFormat.UBTC.parse("1.0"));
        assertEquals(Coin.MICROCOIN, MonetaryFormat.UBTC.parse("01.0000000000"));
        assertEquals(Coin.MICROCOIN, MonetaryFormat.UBTC.positiveSign('+').parse("+1.0"));
        assertEquals(Coin.MICROCOIN.negate(), MonetaryFormat.UBTC.parse("-1"));
        assertEquals(Coin.MICROCOIN.negate(), MonetaryFormat.UBTC.parse("-1.0"));

        assertEquals(Coin.CENT, NO_CODE.withLocale(new Locale("hi", "IN")).parse(".०१")); // Devanagari
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidEmpty() throws Exception {
        NO_CODE.parse("");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidWhitespaceBefore() throws Exception {
        NO_CODE.parse(" 1");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidWhitespaceSign() throws Exception {
        NO_CODE.parse("- 1");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidWhitespaceAfter() throws Exception {
        NO_CODE.parse("1 ");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidMultipleDecimalMarks() throws Exception {
        NO_CODE.parse("1.0.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidDecimalMark() throws Exception {
        NO_CODE.decimalMark(',').parse("1.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidPositiveSign() throws Exception {
        NO_CODE.positiveSign('@').parse("+1.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidNegativeSign() throws Exception {
        NO_CODE.negativeSign('@').parse("-1.0");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidHugeNumber() throws Exception {
        NO_CODE.parse("99999999999999999999");
    }

    @Test(expected = NumberFormatException.class)
    public void parseInvalidHugeNegativeNumber() throws Exception {
        NO_CODE.parse("-99999999999999999999");
    }

    private static final Fiat ONE_EURO = Fiat.parseFiat("EUR", "1");

    @Test
    public void fiat() throws Exception {
        assertEquals(ONE_EURO, NO_CODE.parseFiat("EUR", "1"));
    }
}
