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

package org.bitcoinj.core;

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.Networks;
import org.bitcoinj.params.TestNet3Params;
import org.junit.Test;

import java.io.*;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.*;

public class LegacyP2PKHAddressTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    @Test
    public void testJavaSerialization() throws Exception {
        LegacyP2PKHAddress testAddress = LegacyP2PKHAddress.fromBase58(TESTNET, "n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(testAddress);
        LegacyP2PKHAddress testAddressCopy = (LegacyP2PKHAddress) new ObjectInputStream(new ByteArrayInputStream(os.toByteArray()))
                .readObject();
        assertEquals(testAddress, testAddressCopy);

        LegacyP2PKHAddress mainAddress = LegacyP2PKHAddress.fromBase58(MAINNET, "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(mainAddress);
        LegacyP2PKHAddress mainAddressCopy = (LegacyP2PKHAddress) new ObjectInputStream(new ByteArrayInputStream(os.toByteArray()))
                .readObject();
        assertEquals(mainAddress, mainAddressCopy);
    }

    @Test
    public void stringification() {
        // Test a testnet address.
        LegacyP2PKHAddress a = LegacyP2PKHAddress.fromPubKeyHash(TESTNET, HEX.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        assertEquals("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", a.toString());

        LegacyP2PKHAddress b = LegacyP2PKHAddress.fromPubKeyHash(MAINNET, HEX.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        assertEquals("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL", b.toString());
    }

    @Test
    public void decoding() {
        LegacyAddress a = LegacyP2PKHAddress.fromBase58(TESTNET, "n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        assertEquals("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc", Utils.HEX.encode(a.getHash()));

        LegacyAddress b = LegacyP2PKHAddress.fromBase58(MAINNET, "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        assertEquals("4a22c3c4cbb31e4d03b15550636762bda0baf85a", Utils.HEX.encode(b.getHash()));
    }

    @Test
    public void errorPaths() {
        // Check what happens if we try and decode garbage.
        try {
            LegacyP2PKHAddress.fromBase58(TESTNET, "this is not a valid address!");
            fail();
        } catch (AddressFormatException.WrongNetwork | AddressFormatException.WrongAddressType e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the empty case.
        try {
            LegacyP2PKHAddress.fromBase58(TESTNET, "");
            fail();
        } catch (AddressFormatException.WrongNetwork | AddressFormatException.WrongAddressType e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the case of a mismatched network.
        try {
            LegacyP2PKHAddress.fromBase58(TESTNET, "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
            fail();
        } catch (AddressFormatException.WrongNetwork e) {
            // Success.
        } catch (AddressFormatException e) {
            fail();
        }

        // Check the case of decoding a P2SH address
        try {
            LegacyP2PKHAddress.fromBase58(TESTNET, "2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe");
            fail();
        } catch (AddressFormatException.WrongAddressType e) {
            // Success.
        } catch (AddressFormatException e) {
            fail();
        }
    }

    @Test
    public void getNetwork() {
        NetworkParameters params = LegacyP2PKHAddress.getParametersFromAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        assertEquals(MAINNET.getId(), params.getId());
        params = LegacyP2PKHAddress.getParametersFromAddress("n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        assertEquals(TESTNET.getId(), params.getId());
    }

    @Test
    public void getAltNetwork() throws Exception {
        // An alternative network
        class AltNetwork extends MainNetParams {
            private AltNetwork() {
                super();
                id = "alt.network";
                addressHeader = 48;
            }
        }
        AltNetwork altNetwork = new AltNetwork();
        // Add new network params
        Networks.register(altNetwork);
        // Check if can parse address
        NetworkParameters params = LegacyP2PKHAddress.getParametersFromAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
        assertEquals(altNetwork.getId(), params.getId());
        // Check if main network works as before
        params = LegacyP2PKHAddress.getParametersFromAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        assertEquals(MAINNET.getId(), params.getId());
        // Unregister network
        Networks.unregister(altNetwork);
        try {
            LegacyP2PKHAddress.getParametersFromAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
            fail();
        } catch (AddressFormatException e) { }
    }

    @Test
    public void cloning() throws Exception {
        LegacyP2PKHAddress a = LegacyP2PKHAddress.fromPubKeyHash(TESTNET,
                HEX.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        LegacyP2PKHAddress b = a.clone();

        assertEquals(a, b);
        assertNotSame(a, b);
    }

    @Test
    public void roundtripBase58() throws Exception {
        String base58 = "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL";
        assertEquals(base58, LegacyP2PKHAddress.fromBase58(null, base58).toBase58());
    }

    @Test
    public void comparisonCloneEqualTo() throws Exception {
        LegacyP2PKHAddress a = LegacyP2PKHAddress.fromBase58(MAINNET, "1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX");
        LegacyP2PKHAddress b = a.clone();

        int result = a.compareTo(b);
        assertEquals(0, result);
    }

    @Test
    public void comparisonLessThan() throws Exception {
        LegacyP2PKHAddress a = LegacyP2PKHAddress.fromBase58(MAINNET, "1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX");
        LegacyP2PKHAddress b = LegacyP2PKHAddress.fromBase58(MAINNET, "1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P");

        int result = a.compareTo(b);
        assertTrue(result < 0);
    }

    @Test
    public void comparisonGreaterThan() {
        LegacyP2PKHAddress a = LegacyP2PKHAddress.fromBase58(MAINNET, "1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P");
        LegacyP2PKHAddress b = LegacyP2PKHAddress.fromBase58(MAINNET, "1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX");

        int result = a.compareTo(b);
        assertTrue(result > 0);
    }

    @Test
    public void comparisonBytesVsString() throws Exception {
        BufferedReader dataSetReader = new BufferedReader(
                new InputStreamReader(getClass().getResourceAsStream("LegacyAddressTestDataset.txt")));
        String line;
        while ((line = dataSetReader.readLine()) != null) {
            String[] addr = line.split(",");
            LegacyP2PKHAddress first = LegacyP2PKHAddress.fromBase58(MAINNET, addr[0]);
            LegacyP2PKHAddress second = LegacyP2PKHAddress.fromBase58(MAINNET, addr[1]);
            assertTrue(first.compareTo(second) < 0);
            assertTrue(first.toString().compareTo(second.toString()) < 0);
        }
    }
}
