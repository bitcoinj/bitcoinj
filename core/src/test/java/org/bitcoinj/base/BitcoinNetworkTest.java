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

import static org.bitcoinj.base.BitcoinNetwork.MAINNET;
import static org.bitcoinj.base.BitcoinNetwork.REGTEST;
import static org.bitcoinj.base.BitcoinNetwork.SIGNET;
import static org.bitcoinj.base.BitcoinNetwork.TESTNET;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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

    @Test
    public void testLegacyAddressValidity() {
        LegacyAddress m = LegacyAddress.fromBase58("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL", MAINNET);
        LegacyAddress t = LegacyAddress.fromBase58("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", TESTNET);

        assertTrue(MAINNET.isValidAddress(m));
        assertTrue(TESTNET.isValidAddress(t));
        assertTrue(SIGNET.isValidAddress(t));
        assertTrue(REGTEST.isValidAddress(t));

        assertFalse(MAINNET.isValidAddress(t));
        assertFalse(TESTNET.isValidAddress(m));
        assertFalse(SIGNET.isValidAddress(m));
        assertFalse(REGTEST.isValidAddress(m));
    }

    @Test
    public void testSegwitAddressValidity() {
        SegwitAddress m = SegwitAddress.fromBech32("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", MAINNET);
        SegwitAddress t = SegwitAddress.fromBech32("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", TESTNET);
        SegwitAddress rt = SegwitAddress.fromBech32("bcrt1qspfueag7fvty7m8htuzare3xs898zvh30fttu2", REGTEST);

        assertTrue(MAINNET.isValidAddress(m));
        assertTrue(TESTNET.isValidAddress(t));
        assertTrue(SIGNET.isValidAddress(t));
        assertTrue(REGTEST.isValidAddress(rt));

        assertFalse(MAINNET.isValidAddress(t));
        assertFalse(MAINNET.isValidAddress(rt));
        assertFalse(TESTNET.isValidAddress(m));
        assertFalse(TESTNET.isValidAddress(rt));
        assertFalse(SIGNET.isValidAddress(m));
        assertFalse(SIGNET.isValidAddress(rt));
        assertFalse(REGTEST.isValidAddress(m));
        assertFalse(REGTEST.isValidAddress(t));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testLegacyAddressCheckThrow() {
        MAINNET.checkAddress(LegacyAddress.fromBase58("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", TESTNET));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSegwitAddressCheckThrow() {
        MAINNET.checkAddress(SegwitAddress.fromBech32("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", TESTNET));
    }
}
