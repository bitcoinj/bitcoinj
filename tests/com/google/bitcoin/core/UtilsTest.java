/**
 * Copyright 2011 Thilo Planz
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

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;

import static com.google.bitcoin.core.Utils.*;

import org.junit.Assert;
import org.junit.Test;

public class UtilsTest {

    @Test
    public void testToNanoCoins() {
        // String version
        assertEquals(CENT, toNanoCoins("0.01"));
        assertEquals(CENT, toNanoCoins("1E-2"));
        assertEquals(COIN.add(Utils.CENT), toNanoCoins("1.01"));
        try {
            toNanoCoins("2E-20");
            fail("should not have accepted fractional nanocoins");
        } catch (ArithmeticException e) {
        }

        // int version
        assertEquals(CENT, toNanoCoins(0, 1));

        // TODO: should this really pass?
        assertEquals(COIN.subtract(CENT), toNanoCoins(1, -1));
        assertEquals(COIN.negate(), toNanoCoins(-1, 0));
        assertEquals(COIN.negate(), toNanoCoins("-1"));
    }

    @Test
    public void testFormatting() {
        assertEquals("1.23", bitcoinValueToFriendlyString(toNanoCoins(1, 23)));
        assertEquals("-1.23", bitcoinValueToFriendlyString(toNanoCoins(1, 23).negate()));
    }
    
    @Test
    public void testReverseBytes() {
        Assert.assertArrayEquals(new byte[] {1,2,3,4,5}, Utils.reverseBytes(new byte[] {5,4,3,2,1}));
    }

    @Test
    public void testReverseDwordBytes() {
        Assert.assertArrayEquals(new byte[] {1,2,3,4,5,6,7,8}, Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, -1));
        Assert.assertArrayEquals(new byte[] {1,2,3,4}, Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, 4));
        Assert.assertArrayEquals(new byte[0], Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, 0));
        Assert.assertArrayEquals(new byte[0], Utils.reverseDwordBytes(new byte[0], 0));
    }
}
