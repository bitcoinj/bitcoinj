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

public class P2PKHAddressTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    @Test
    public void testJavaSerialization() throws Exception {
        P2PKHAddress testAddress = P2PKHAddress.fromBase58(TESTNET, "n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(testAddress);
        P2PKHAddress testAddressCopy = (P2PKHAddress) new ObjectInputStream(new ByteArrayInputStream(os.toByteArray()))
                .readObject();
        assertEquals(testAddress, testAddressCopy);

        P2PKHAddress mainAddress = P2PKHAddress.fromBase58(MAINNET, "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(mainAddress);
        P2PKHAddress mainAddressCopy = (P2PKHAddress) new ObjectInputStream(new ByteArrayInputStream(os.toByteArray()))
                .readObject();
        assertEquals(mainAddress, mainAddressCopy);
    }

    @Test
    public void stringification() {
        // Test a testnet address.
        P2PKHAddress a = P2PKHAddress.fromPubKeyHash(TESTNET, HEX.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        assertEquals("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", a.toString());

        P2PKHAddress b = P2PKHAddress.fromPubKeyHash(MAINNET, HEX.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        assertEquals("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL", b.toString());
    }

    @Test
    public void decoding() {
        LegacyAddress a = P2PKHAddress.fromBase58(TESTNET, "n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        assertEquals("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc", Utils.HEX.encode(a.getHash()));

        LegacyAddress b = P2PKHAddress.fromBase58(MAINNET, "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        assertEquals("4a22c3c4cbb31e4d03b15550636762bda0baf85a", Utils.HEX.encode(b.getHash()));
    }

    @Test
    public void errorPaths() {
        // Check what happens if we try and decode garbage.
        try {
            P2PKHAddress.fromBase58(TESTNET, "this is not a valid address!");
            fail();
        } catch (AddressFormatException.WrongNetwork | AddressFormatException.WrongAddressType e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the empty case.
        try {
            P2PKHAddress.fromBase58(TESTNET, "");
            fail();
        } catch (AddressFormatException.WrongNetwork | AddressFormatException.WrongAddressType e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the case of a mismatched network.
        try {
            P2PKHAddress.fromBase58(TESTNET, "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
            fail();
        } catch (AddressFormatException.WrongNetwork e) {
            // Success.
        } catch (AddressFormatException e) {
            fail();
        }

        // Check the case of decoding a P2SH address
        try {
            P2PKHAddress.fromBase58(TESTNET, "2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe");
            fail();
        } catch (AddressFormatException.WrongAddressType e) {
            // Success.
        } catch (AddressFormatException e) {
            fail();
        }
    }

    @Test
    public void getNetwork() {
        NetworkParameters params = P2PKHAddress.getParametersFromAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        assertEquals(MAINNET.getId(), params.getId());
        params = P2PKHAddress.getParametersFromAddress("n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
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
        NetworkParameters params = P2PKHAddress.getParametersFromAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
        assertEquals(altNetwork.getId(), params.getId());
        // Check if main network works as before
        params = P2PKHAddress.getParametersFromAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
        assertEquals(MAINNET.getId(), params.getId());
        // Unregister network
        Networks.unregister(altNetwork);
        try {
            P2PKHAddress.getParametersFromAddress("LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6");
            fail();
        } catch (AddressFormatException e) { }
    }

    @Test
    public void cloning() throws Exception {
        P2PKHAddress a = P2PKHAddress.fromPubKeyHash(TESTNET,
                HEX.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        P2PKHAddress b = a.clone();

        assertEquals(a, b);
        assertNotSame(a, b);
    }

    @Test
    public void roundtripBase58() throws Exception {
        String base58 = "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL";
        assertEquals(base58, P2PKHAddress.fromBase58(null, base58).toBase58());
    }

    @Test
    public void comparisonCloneEqualTo() throws Exception {
        P2PKHAddress a = P2PKHAddress.fromBase58(MAINNET, "1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX");
        P2PKHAddress b = a.clone();

        int result = a.compareTo(b);
        assertEquals(0, result);
    }

    @Test
    public void comparisonLessThan() throws Exception {
        P2PKHAddress a = P2PKHAddress.fromBase58(MAINNET, "1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX");
        P2PKHAddress b = P2PKHAddress.fromBase58(MAINNET, "1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P");

        int result = a.compareTo(b);
        assertTrue(result < 0);
    }

    @Test
    public void comparisonGreaterThan() {
        P2PKHAddress a = P2PKHAddress.fromBase58(MAINNET, "1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P");
        P2PKHAddress b = P2PKHAddress.fromBase58(MAINNET, "1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX");

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
            P2PKHAddress first = P2PKHAddress.fromBase58(MAINNET, addr[0]);
            P2PKHAddress second = P2PKHAddress.fromBase58(MAINNET, addr[1]);
            assertTrue(first.compareTo(second) < 0);
            assertTrue(first.toString().compareTo(second.toString()) < 0);
        }
    }
}
