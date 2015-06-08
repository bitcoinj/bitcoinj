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

package org.bitcoinj.utils;

import static org.bitcoinj.utils.Fiat.parseFiat;
import static org.junit.Assert.assertEquals;

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
}
