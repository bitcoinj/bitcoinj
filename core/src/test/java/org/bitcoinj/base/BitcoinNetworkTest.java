/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.base;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class BitcoinNetworkTest {
    @Test
    public void valueOf() {
        assertEquals(BitcoinNetwork.MAIN, BitcoinNetwork.valueOf("MAIN"));
        assertEquals(BitcoinNetwork.TEST, BitcoinNetwork.valueOf("TEST"));
        assertEquals(BitcoinNetwork.SIGNET, BitcoinNetwork.valueOf("SIGNET"));
        assertEquals(BitcoinNetwork.REGTEST, BitcoinNetwork.valueOf("REGTEST"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValueOf_alternate() {
        BitcoinNetwork.valueOf("PROD");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValueOf_notExisting() {
        BitcoinNetwork.valueOf("xxx");
    }

    @Test
    public void testFromString() {
        assertEquals(BitcoinNetwork.MAIN, BitcoinNetwork.fromString("main").get());
        assertEquals(BitcoinNetwork.TEST, BitcoinNetwork.fromString("test").get());
        assertEquals(BitcoinNetwork.SIGNET, BitcoinNetwork.fromString("signet").get());
        assertEquals(BitcoinNetwork.REGTEST, BitcoinNetwork.fromString("regtest").get());
    }

    @Test
    public void testFromString_uppercase() {
        assertFalse(BitcoinNetwork.fromString("MAIN").isPresent());
    }

    @Test
    public void testFromString_notExisting() {
        assertFalse(BitcoinNetwork.fromString("xxx").isPresent());
    }

    @Test
    public void testFromIdString() {
        assertEquals(BitcoinNetwork.MAIN, BitcoinNetwork.fromIdString("org.bitcoin.production").get());
        assertEquals(BitcoinNetwork.TEST, BitcoinNetwork.fromIdString("org.bitcoin.test").get());
        assertEquals(BitcoinNetwork.SIGNET, BitcoinNetwork.fromIdString("org.bitcoin.signet").get());
        assertEquals(BitcoinNetwork.REGTEST, BitcoinNetwork.fromIdString("org.bitcoin.regtest").get());
    }

    @Test
    public void testFromIdString_uppercase() {
        assertFalse(BitcoinNetwork.fromIdString("ORG.BITCOIN.PRODUCTION").isPresent());
    }

    @Test
    public void testFromIdString_notExisting() {
        assertFalse(BitcoinNetwork.fromIdString("a.b.c").isPresent());
    }
}
