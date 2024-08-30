/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.base;

import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.Networks;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.testing.MockAltNetworkParams;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import static org.bitcoinj.base.BitcoinNetwork.MAINNET;
import static org.bitcoinj.base.BitcoinNetwork.TESTNET;
import static org.bitcoinj.base.BitcoinNetwork.SIGNET;
import static org.bitcoinj.base.BitcoinNetwork.REGTEST;

public class LegacyAddressTest {
    @Test
    public void equalsContract() {
        EqualsVerifier.forClass(LegacyAddress.class)
                .withPrefabValues(BitcoinNetwork.class, MAINNET, TESTNET)
                .suppress(Warning.NULL_FIELDS)
                .suppress(Warning.TRANSIENT_FIELDS)
                .usingGetClass()
                .verify();
    }

    @Test
    public void stringification() {
        // Test a testnet address.
        LegacyAddress a = LegacyAddress.fromPubKeyHash(TESTNET, ByteUtils.parseHex("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        assertEquals("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", a.toString());
        assertEquals(ScriptType.P2PKH, a.getOutputScriptType());

        LegacyAddress b = LegacyAddress.fromPubKeyHash(MAINNET, ByteUtils.parseHex("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        assertEquals("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL", b.toString());
        assertEquals(ScriptType.P2PKH, b.getOutputScriptType());
    }

    @Test
    public void decoding() {
        LegacyAddress a = LegacyAddress.fromBase58("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", TESTNET);
        assertEquals("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc", ByteUtils.formatHex(a.getHash()));

        LegacyAddress b = LegacyAddress.fromBase58("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL", MAINNET);
        assertEquals("4a22c3c4cbb31e4d03b15550636762bda0baf85a", ByteUtils.formatHex(b.getHash()));
    }

    @Test
    public void equalityOfEquivalentNetworks() {
        LegacyAddress a = LegacyAddress.fromBase58("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", TESTNET);
        LegacyAddress b = LegacyAddress.fromBase58("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", SIGNET);
        LegacyAddress c = LegacyAddress.fromBase58("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", REGTEST);
        assertEquals(a, b);
        assertEquals(b, c);
        assertEquals(a, c);
        assertEquals(a.toString(), b.toString());
        assertEquals(b.toString(), c.toString());
        assertEquals(a.toString(), c.toString());
    }

    @Test
    public void errorPaths() {
        // Check what happens if we try and decode garbage.
        try {
            LegacyAddress.fromBase58("this is not a valid address!", TESTNET);
            fail();
        } catch (AddressFormatException.WrongNetwork e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the empty case.
        try {
            LegacyAddress.fromBase58("", TESTNET);
            fail();
        } catch (AddressFormatException.WrongNetwork e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the case of a mismatched network.
        try {
            LegacyAddress.fromBase58("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL", TESTNET);
            fail();
        } catch (AddressFormatException.WrongNetwork e) {
            // Success.
        } catch (AddressFormatException e) {
            fail();
        }
    }

    @Test
    @Deprecated
    // Test a deprecated method just to make sure we didn't break it
    public void getNetworkViaParameters() {
        NetworkParameters params = LegacyAddress.getParametersFromAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        assertEquals(MAINNET.id(), params.getId());
        params = LegacyAddress.getParametersFromAddress("n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        assertEquals(TESTNET.id(), params.getId());
    }

    @Test
    public void getNetwork() {
        AddressParser parser = AddressParser.getDefault();
        Network mainNet = parser.parseAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL").network();
        assertEquals(MAINNET, mainNet);
        Network testNet = parser.parseAddress("n4eA2nbYqErp7H6jebchxAN59DmNpksexv").network();
        assertEquals(TESTNET, testNet);
    }

    @Test
    public void getAltNetworkUsingNetworks() {
        // An alternative network
        NetworkParameters altNetParams = new MockAltNetworkParams();
        // Add new network params, this MODIFIES GLOBAL STATE in `Networks`
        Networks.register(altNetParams);
        try {
            // Check if can parse address
            Address altAddress = AddressParser.getLegacy().parseAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
            assertEquals(altNetParams.getId(), altAddress.network().id());
            // Check if main network works as before
            Address mainAddress = AddressParser.getLegacy(MAINNET).parseAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
            assertEquals(MAINNET.id(), mainAddress.network().id());
        } finally {
            // Unregister network. Do this in a finally block so other tests don't fail if the try block fails to complete
            Networks.unregister(altNetParams);
        }
        try {
            AddressParser.getLegacy().parseAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
            fail();
        } catch (AddressFormatException e) { }
    }

    @Test
    public void getAltNetworkUsingList() {
        // An alternative network
        NetworkParameters altNetParams = new MockAltNetworkParams();

        // Create a parser that knows about the new network (this does not modify global state)
        List<Network> nets = new ArrayList<>(DefaultAddressParserProvider.DEFAULT_NETWORKS_LEGACY);
        nets.add(altNetParams.network());
        AddressParser customParser = new DefaultAddressParserProvider(DefaultAddressParserProvider.DEFAULT_NETWORKS_SEGWIT, nets).forKnownNetworks();

        // Unfortunately for NetworkParameters.of() to work properly we still have to modify gobal state
        Networks.register(altNetParams);
        try {

            // Check if can parse address
            Address altAddress = customParser.parseAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
            assertEquals(altNetParams.getId(), altAddress.network().id());

            // Check if main network works with custom parser
            Address mainAddress = customParser.parseAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
            assertEquals(MAINNET.id(), mainAddress.network().id());

        } finally {
            // Unregister network. Do this in a finally block so other tests don't fail if the try block fails to complete
            Networks.unregister(altNetParams);
        }

        try {
            AddressParser.getLegacy().parseAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
            fail();
        } catch (AddressFormatException e) { }
    }

    @Test
    public void p2shAddress() {
        // Test that we can construct P2SH addresses
        LegacyAddress mainNetP2SHAddress = LegacyAddress.fromBase58("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU", MAINNET);
        assertEquals(mainNetP2SHAddress.getVersion(), MAINNET.legacyP2SHHeader());
        assertEquals(ScriptType.P2SH, mainNetP2SHAddress.getOutputScriptType());
        LegacyAddress testNetP2SHAddress = LegacyAddress.fromBase58("2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe", TESTNET);
        assertEquals(testNetP2SHAddress.getVersion(), TESTNET.legacyP2SHHeader());
        assertEquals(ScriptType.P2SH, testNetP2SHAddress.getOutputScriptType());

        AddressParser parser = AddressParser.getDefault();
        // Test that we can determine what network a P2SH address belongs to
        Network mainNet = parser.parseAddress("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU").network();
        assertEquals(MAINNET, mainNet);
        Network testNet = parser.parseAddress("2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe").network();
        assertEquals(TESTNET, testNet);

        // Test that we can convert them from hashes
        byte[] hex = ByteUtils.parseHex("2ac4b0b501117cc8119c5797b519538d4942e90e");
        LegacyAddress a = LegacyAddress.fromScriptHash(MAINNET, hex);
        assertEquals("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU", a.toString());
        LegacyAddress b = LegacyAddress.fromScriptHash(TESTNET, ByteUtils.parseHex("18a0e827269b5211eb51a4af1b2fa69333efa722"));
        assertEquals("2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe", b.toString());
        LegacyAddress c = LegacyAddress.fromScriptHash(MAINNET,
                ScriptPattern.extractHashFromP2SH(ScriptBuilder.createP2SHOutputScript(hex)));
        assertEquals("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU", c.toString());
    }

    @Test
    public void p2shAddressFromScriptHash() {
        byte[] p2shScriptHash = ByteUtils.parseHex("defdb71910720a2c854529019189228b4245eddd");
        LegacyAddress address = LegacyAddress.fromScriptHash(MAINNET, p2shScriptHash);
        assertEquals("3N25saC4dT24RphDAwLtD8LUN4E2gZPJke", address.toString());
    }

    @Test
    public void roundtripBase58() {
        String base58 = "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL";
        assertEquals(base58, LegacyAddress.fromBase58(base58, MAINNET).toBase58());
    }

    @Test
    public void comparisonLessThan() {
        LegacyAddress a = LegacyAddress.fromBase58("1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX", MAINNET);
        LegacyAddress b = LegacyAddress.fromBase58("1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P", MAINNET);

        int result = a.compareTo(b);
        assertTrue(result < 0);
    }

    @Test
    public void comparisonGreaterThan() {
        LegacyAddress a = LegacyAddress.fromBase58("1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P", MAINNET);
        LegacyAddress b = LegacyAddress.fromBase58("1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX", MAINNET);

        int result = a.compareTo(b);
        assertTrue(result > 0);
    }

    @Test
    public void comparisonNotEquals() {
        // These addresses only differ by version byte
        LegacyAddress a = LegacyAddress.fromBase58("14wivxvNTv9THhewPotsooizZawaWbEKE2", MAINNET);
        LegacyAddress b = LegacyAddress.fromBase58("35djrWQp1pTqNsMNWuZUES5vi7EJ74m9Eh", MAINNET);

        int result = a.compareTo(b);
        assertTrue(result != 0);
    }

    @Test
    public void comparisonBytesVsString() throws Exception {
        BufferedReader dataSetReader = new BufferedReader(
                new InputStreamReader(getClass().getResourceAsStream("LegacyAddressTestDataset.txt")));
        String line;
        while ((line = dataSetReader.readLine()) != null) {
            String addr[] = line.split(",");
            LegacyAddress first = LegacyAddress.fromBase58(addr[0], MAINNET);
            LegacyAddress second = LegacyAddress.fromBase58(addr[1], MAINNET);
            assertTrue(first.compareTo(second) < 0);
            assertTrue(first.toString().compareTo(second.toString()) < 0);
        }
    }
}
