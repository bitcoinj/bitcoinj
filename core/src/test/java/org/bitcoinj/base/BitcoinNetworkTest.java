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
        assertEquals(BitcoinNetwork.MAINNET, BitcoinNetwork.valueOf("MAINNET"));
        assertEquals(BitcoinNetwork.TESTNET, BitcoinNetwork.valueOf("TESTNET"));
        assertEquals(BitcoinNetwork.SIGNET, BitcoinNetwork.valueOf("SIGNET"));
        assertEquals(BitcoinNetwork.REGTEST, BitcoinNetwork.valueOf("REGTEST"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void valueOf_alternate() {
        BitcoinNetwork.valueOf("PROD");
    }

    @Test(expected = IllegalArgumentException.class)
    public void valueOf_notExisting() {
        BitcoinNetwork.valueOf("xxx");
    }

    @Test
    public void fromString() {
        assertEquals(BitcoinNetwork.MAINNET, BitcoinNetwork.fromString("mainnet").get());
        assertEquals(BitcoinNetwork.MAINNET, BitcoinNetwork.fromString("main").get());
        assertEquals(BitcoinNetwork.MAINNET, BitcoinNetwork.fromString("prod").get());
        assertEquals(BitcoinNetwork.TESTNET, BitcoinNetwork.fromString("test").get());
        assertEquals(BitcoinNetwork.TESTNET, BitcoinNetwork.fromString("testnet").get());
        assertEquals(BitcoinNetwork.SIGNET, BitcoinNetwork.fromString("signet").get());
        assertEquals(BitcoinNetwork.SIGNET, BitcoinNetwork.fromString("sig").get());
        assertEquals(BitcoinNetwork.REGTEST, BitcoinNetwork.fromString("regtest").get());
    }

    @Test
    public void fromString_uppercase() {
        assertFalse(BitcoinNetwork.fromString("MAIN").isPresent());
    }

    @Test
    public void fromString_notExisting() {
        assertFalse(BitcoinNetwork.fromString("xxx").isPresent());
    }

    @Test
    public void fromIdString() {
        assertEquals(BitcoinNetwork.MAINNET, BitcoinNetwork.fromIdString("org.bitcoin.production").get());
        assertEquals(BitcoinNetwork.TESTNET, BitcoinNetwork.fromIdString("org.bitcoin.test").get());
        assertEquals(BitcoinNetwork.SIGNET, BitcoinNetwork.fromIdString("org.bitcoin.signet").get());
        assertEquals(BitcoinNetwork.REGTEST, BitcoinNetwork.fromIdString("org.bitcoin.regtest").get());
    }

    @Test
    public void fromIdString_uppercase() {
        assertFalse(BitcoinNetwork.fromIdString("ORG.BITCOIN.PRODUCTION").isPresent());
    }

    @Test
    public void fromIdString_notExisting() {
        assertFalse(BitcoinNetwork.fromIdString("a.b.c").isPresent());
    }
}
