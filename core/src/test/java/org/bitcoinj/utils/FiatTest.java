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

import static org.bitcoinj.utils.Fiat.parseFiat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class FiatTest {

    @Test
    public void testParseAndValueOf() {
        assertEquals(Fiat.valueOf("EUR", 10000), parseFiat("EUR", "1"));
        assertEquals(Fiat.valueOf("EUR", 100), parseFiat("EUR", "0.01"));
        assertEquals(Fiat.valueOf("EUR", 1), parseFiat("EUR", "0.0001"));
        assertEquals(Fiat.valueOf("EUR", -10000), parseFiat("EUR", "-1"));
    }

    @Test
    public void testParseFiat() {
        assertEquals(1, Fiat.parseFiat("EUR", "0.0001").value);
        assertEquals(1, Fiat.parseFiat("EUR", "0.00010").value);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseFiatOverprecise() {
        Fiat.parseFiat("EUR", "0.00011");
    }

    @Test
    public void testParseFiatInexact() {
        assertEquals(1, Fiat.parseFiatInexact("EUR", "0.0001").value);
        assertEquals(1, Fiat.parseFiatInexact("EUR", "0.00011").value);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseFiatInexactInvalidAmount() {
        Fiat.parseFiatInexact("USD", "33.xx");
    }

    @Test
    public void testToFriendlyString() {
        assertEquals("1.00 EUR", parseFiat("EUR", "1").toFriendlyString());
        assertEquals("1.23 EUR", parseFiat("EUR", "1.23").toFriendlyString());
        assertEquals("0.0010 EUR", parseFiat("EUR", "0.001").toFriendlyString());
        assertEquals("-1.23 EUR", parseFiat("EUR", "-1.23").toFriendlyString());
    }

    @Test
    public void testToPlainString() {
        assertEquals("0.0015", Fiat.valueOf("EUR", 15).toPlainString());
        assertEquals("1.23", parseFiat("EUR", "1.23").toPlainString());

        assertEquals("0.1", parseFiat("EUR", "0.1").toPlainString());
        assertEquals("1.1", parseFiat("EUR", "1.1").toPlainString());
        assertEquals("21.12", parseFiat("EUR", "21.12").toPlainString());
        assertEquals("321.123", parseFiat("EUR", "321.123").toPlainString());
        assertEquals("4321.1234", parseFiat("EUR", "4321.1234").toPlainString());

        // check there are no trailing zeros
        assertEquals("1", parseFiat("EUR", "1.0").toPlainString());
        assertEquals("2", parseFiat("EUR", "2.00").toPlainString());
        assertEquals("3", parseFiat("EUR", "3.000").toPlainString());
        assertEquals("4", parseFiat("EUR", "4.0000").toPlainString());
    }

    @Test
    public void testComparing() {
        assertTrue(parseFiat("EUR", "1.11").isLessThan(parseFiat("EUR", "6.66")));
        assertTrue(parseFiat("EUR", "6.66").isGreaterThan(parseFiat("EUR", "2.56")));
    }

    @Test
    public void testSign() {
        assertTrue(parseFiat("EUR", "-1").isNegative());
        assertTrue(parseFiat("EUR", "-1").negate().isPositive());
        assertTrue(parseFiat("EUR", "1").isPositive());
        assertTrue(parseFiat("EUR", "0.00").isZero());

    }

    @Test
    public void testCurrencyCode() {
        assertEquals("RUB", parseFiat("RUB", "66.6").getCurrencyCode());
    }

    @Test
    public void testValueFetching() {
        Fiat fiat = parseFiat("USD", "666");
        assertEquals(6660000, fiat.longValue());
        assertEquals("6660000", fiat.toString());
    }

    @Test
    public void testOperations() {
        Fiat fiatA = parseFiat("USD", "666");
        Fiat fiatB = parseFiat("USD", "2");

        Fiat sumResult = fiatA.add(fiatB);
        assertEquals(6680000, sumResult.getValue());
        assertEquals("USD", sumResult.getCurrencyCode());

        Fiat subResult = fiatA.subtract(fiatB);
        assertEquals(6640000, subResult.getValue());
        assertEquals("USD", subResult.getCurrencyCode());

        Fiat divResult = fiatA.divide(2);
        assertEquals(3330000, divResult.getValue());
        assertEquals("USD", divResult.getCurrencyCode());

        long ldivResult = fiatA.divide(fiatB);
        assertEquals(333, ldivResult);

        Fiat mulResult = fiatA.multiply(2);
        assertEquals(13320000, mulResult.getValue());

        Fiat[] fiats = fiatA.divideAndRemainder(3);
        assertEquals(2, fiats.length);

        Fiat fiat1 = fiats[0];
        assertEquals(2220000, fiat1.getValue());
        assertEquals("USD", fiat1.getCurrencyCode());

        Fiat fiat2 = fiats[1];
        assertEquals(0, fiat2.getValue());
        assertEquals("USD", fiat2.getCurrencyCode());
    }
}
