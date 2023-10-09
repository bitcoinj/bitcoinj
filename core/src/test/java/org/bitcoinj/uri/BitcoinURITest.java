/*
 * Copyright 2012, 2014 the original author or authors.
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

package org.bitcoinj.uri;

import org.bitcoinj.base.AddressParser;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.Networks;
import org.bitcoinj.testing.MockAltNetworkParams;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;

import static org.bitcoinj.base.Coin.CENT;
import static org.bitcoinj.base.Coin.parseCoin;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BitcoinURITest {
    private BitcoinURI testObject = null;

    private static final BitcoinNetwork MAINNET = BitcoinNetwork.MAINNET;
    private static final BitcoinNetwork TESTNET = BitcoinNetwork.TESTNET;
    private static final String MAINNET_GOOD_ADDRESS = "1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH";
    private static final String MAINNET_GOOD_SEGWIT_ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    private static final String BITCOIN_SCHEME = BitcoinNetwork.BITCOIN_SCHEME;

    @Test
    public void of_anyNetwork() throws Exception {
        BitcoinURI uri1 = BitcoinURI.of("bitcoin:" + MAINNET_GOOD_ADDRESS);
        assertEquals(BitcoinNetwork.MAINNET, uri1.getAddress().network());
        BitcoinURI uri2 = BitcoinURI.of("bitcoin:" + MAINNET_GOOD_SEGWIT_ADDRESS);
        assertEquals(BitcoinNetwork.MAINNET, uri2.getAddress().network());
        BitcoinURI uri3 = BitcoinURI.of("bitcoin:mutDLVyes4YNWkL4j8g9oUsSUSTtnt13hP");
        assertEquals(BitcoinNetwork.TESTNET, uri3.getAddress().network());
        BitcoinURI uri4 = BitcoinURI.of("bitcoin:tb1qn96rzewt04q0vtnh8lh0kelekkj2lpjh29lg6x");
        assertEquals(BitcoinNetwork.TESTNET, uri4.getAddress().network());
        BitcoinURI uri5 = BitcoinURI.of("BITCOIN:TB1QN96RZEWT04Q0VTNH8LH0KELEKKJ2LPJH29LG6X");
        assertEquals(BitcoinNetwork.TESTNET, uri5.getAddress().network());
    }

    @Test
    public void testConvertToBitcoinURI() {
        Address goodAddress = AddressParser.getDefault(MAINNET).parseAddress(MAINNET_GOOD_ADDRESS);
        
        // simple example
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello&message=AMessage", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("12.34"), "Hello", "AMessage"));
        
        // example with spaces, ampersand and plus
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello%20World&message=Mess%20%26%20age%20%2B%20hope", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("12.34"), "Hello World", "Mess & age + hope"));

        // no amount, label present, message present
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?label=Hello&message=glory", BitcoinURI.convertToBitcoinURI(goodAddress, null, "Hello", "glory"));
        
        // amount present, no label, message present
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=0.1&message=glory", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("0.1"), null, "glory"));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=0.1&message=glory", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("0.1"), "", "glory"));

        // amount present, label present, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("12.34"), "Hello", null));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=12.34&label=Hello", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("12.34"), "Hello", ""));
              
        // amount present, no label, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=1000", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("1000"), null, null));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?amount=1000", BitcoinURI.convertToBitcoinURI(goodAddress, parseCoin("1000"), "", ""));
        
        // no amount, label present, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?label=Hello", BitcoinURI.convertToBitcoinURI(goodAddress, null, "Hello", null));
        
        // no amount, no label, message present
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?message=Agatha", BitcoinURI.convertToBitcoinURI(goodAddress, null, null, "Agatha"));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS + "?message=Agatha", BitcoinURI.convertToBitcoinURI(goodAddress, null, "", "Agatha"));
      
        // no amount, no label, no message
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS, BitcoinURI.convertToBitcoinURI(goodAddress, null, null, null));
        assertEquals("bitcoin:" + MAINNET_GOOD_ADDRESS, BitcoinURI.convertToBitcoinURI(goodAddress, null, "", ""));

        // different scheme
        NetworkParameters alternativeParameters = new MockAltNetworkParams();
        String mockNetGoodAddress = MockAltNetworkParams.MOCKNET_GOOD_ADDRESS;

        Networks.register(alternativeParameters);
        try {
            assertEquals("mockcoin:" + mockNetGoodAddress + "?amount=12.34&label=Hello&message=AMessage",
                    BitcoinURI.convertToBitcoinURI(LegacyAddress.fromBase58(mockNetGoodAddress, alternativeParameters.network()), parseCoin("12.34"), "Hello", "AMessage"));
        } finally {
            Networks.unregister(alternativeParameters);
        }
    }

    @Test
    public void testConvertToBitcoinURI_segwit() {
        Address segwitAddress = AddressParser.getDefault(MAINNET).parseAddress(MAINNET_GOOD_SEGWIT_ADDRESS);
        assertEquals("bitcoin:" + MAINNET_GOOD_SEGWIT_ADDRESS + "?message=segwit%20rules", BitcoinURI.convertToBitcoinURI(
                segwitAddress, null, null, "segwit rules"));
    }

    @Test
    public void testGood_legacy() throws BitcoinURIParseException {
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS, MAINNET);
        assertEquals(MAINNET_GOOD_ADDRESS, testObject.getAddress().toString());
        assertNull("Unexpected amount", testObject.getAmount());
        assertNull("Unexpected label", testObject.getLabel());
        assertEquals("Unexpected label", 20, testObject.getAddress().getHash().length);
    }

    @Test
    public void testGood_uppercaseScheme() throws BitcoinURIParseException {
        testObject = BitcoinURI.of(BITCOIN_SCHEME.toUpperCase(Locale.US) + ":" + MAINNET_GOOD_ADDRESS, MAINNET);
        assertEquals(MAINNET_GOOD_ADDRESS, testObject.getAddress().toString());
        assertNull("Unexpected amount", testObject.getAmount());
        assertNull("Unexpected label", testObject.getLabel());
        assertEquals("Unexpected label", 20, testObject.getAddress().getHash().length);
    }

    @Test
    public void testGood_segwit() throws BitcoinURIParseException {
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_SEGWIT_ADDRESS, MAINNET);
        assertEquals(MAINNET_GOOD_SEGWIT_ADDRESS, testObject.getAddress().toString());
        assertNull("Unexpected amount", testObject.getAmount());
        assertNull("Unexpected label", testObject.getLabel());
    }

    /**
     * Test a broken URI (bad scheme)
     */
    @Test
    public void testBad_Scheme() {
        try {
            testObject = BitcoinURI.of("blimpcoin:" + MAINNET_GOOD_ADDRESS, MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
        }
    }

    /**
     * Test a broken URI (bad syntax)
     */
    @Test
    public void testBad_BadSyntax() {
        // Various illegal characters
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + "|" + MAINNET_GOOD_ADDRESS, MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad URI syntax"));
        }

        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS + "\\", MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad URI syntax"));
        }

        // Separator without field
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":", MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad URI syntax"));
        }
    }

    /**
     * Test a broken URI (missing address)
     */
    @Test
    public void testBad_Address() {
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME, MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
        }
    }

    /**
     * Test a broken URI (bad address type)
     */
    @Test
    public void testBad_IncorrectAddressType() {
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS, TESTNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("Bad address"));
        }
    }

    /**
     * Handles a simple amount
     * 
     * @throws BitcoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Amount() throws BitcoinURIParseException {
        // Test the decimal parsing
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=6543210.12345678", MAINNET);
        assertEquals("654321012345678", testObject.getAmount().toString());

        // Test the decimal parsing
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=.12345678", MAINNET);
        assertEquals("12345678", testObject.getAmount().toString());

        // Test the integer parsing
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=6543210", MAINNET);
        assertEquals("654321000000000", testObject.getAmount().toString());

        // the maximum amount
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=" + new BigDecimal(Long.MAX_VALUE).movePointLeft(8), MAINNET);
        assertEquals(Long.MAX_VALUE, testObject.getAmount().longValue());
    }

    /**
     * Handles a simple label
     * 
     * @throws BitcoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Label() throws BitcoinURIParseException {
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?label=Hello%20World", MAINNET);
        assertEquals("Hello World", testObject.getLabel());
    }

    /**
     * Handles a simple label with an embedded ampersand and plus
     * 
     * @throws BitcoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_LabelWithAmpersandAndPlus() throws BitcoinURIParseException {
        String testString = "Hello Earth & Mars + Venus";
        String encodedLabel = BitcoinURI.encodeURLString(testString);
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS + "?label="
                + encodedLabel, MAINNET);
        assertEquals(testString, testObject.getLabel());
    }

    /**
     * Handles a Russian label (Unicode test)
     * 
     * @throws BitcoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_LabelWithRussian() throws BitcoinURIParseException {
        // Moscow in Russian in Cyrillic
        String moscowString = "\u041c\u043e\u0441\u043a\u0432\u0430";
        String encodedLabel = BitcoinURI.encodeURLString(moscowString); 
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS + "?label="
                + encodedLabel, MAINNET);
        assertEquals(moscowString, testObject.getLabel());
    }

    /**
     * Handles a simple message
     * 
     * @throws BitcoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Message() throws BitcoinURIParseException {
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?message=Hello%20World", MAINNET);
        assertEquals("Hello World", testObject.getMessage());
    }

    /**
     * Handles various well-formed combinations
     * 
     * @throws BitcoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testGood_Combinations() throws BitcoinURIParseException {
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=6543210&label=Hello%20World&message=Be%20well", MAINNET);
        assertEquals(
                "BitcoinURI['amount'='654321000000000','label'='Hello World','message'='Be well','address'='1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH']",
                testObject.toString());
    }

    /**
     * Handles a badly formatted amount field
     */
    @Test
    public void testBad_Amount() {
        // Missing
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?amount=", MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("amount"));
        }

        // Non-decimal (BIP 21)
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?amount=12X4", MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("amount"));
        }
    }

    @Test
    public void testEmpty_Label() throws BitcoinURIParseException {
        assertNull(BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?label=", MAINNET).getLabel());
    }

    @Test
    public void testEmpty_Message() throws BitcoinURIParseException {
        assertNull(BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?message=", MAINNET).getMessage());
    }

    /**
     * Handles duplicated fields (sneaky address overwrite attack)
     */
    @Test
    public void testBad_Duplicated() {
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?address=aardvark", MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("address"));
        }
    }

    @Test
    public void testGood_ManyEquals() throws BitcoinURIParseException {
        assertEquals("aardvark=zebra", BitcoinURI.of(BITCOIN_SCHEME + ":"
                + MAINNET_GOOD_ADDRESS + "?label=aardvark=zebra", MAINNET).getLabel());
    }
    
    /**
     * Handles unknown fields (required and not required)
     * 
     * @throws BitcoinURIParseException
     *             If something goes wrong
     */
    @Test
    public void testUnknown() throws BitcoinURIParseException {
        // Unknown not required field
        testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?aardvark=true", MAINNET);
        assertEquals("BitcoinURI['aardvark'='true','address'='1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH']", testObject.toString());

        assertEquals("true", testObject.getParameterByName("aardvark"));

        // Unknown not required field (isolated)
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?aardvark", MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("no separator"));
        }

        // Unknown and required field
        try {
            testObject = BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                    + "?req-aardvark=true", MAINNET);
            fail("Expecting BitcoinURIParseException");
        } catch (BitcoinURIParseException e) {
            assertTrue(e.getMessage().contains("req-aardvark"));
        }
    }

    @Test
    public void brokenURIs() throws BitcoinURIParseException {
        // Check we can parse the incorrectly formatted URIs produced by blockchain.info and its iPhone app.
        String str = "bitcoin://1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH?amount=0.01000000";
        BitcoinURI uri = BitcoinURI.of(str);
        assertEquals("1KzTSfqjF2iKCduwz59nv2uqh1W2JsTxZH", uri.getAddress().toString());
        assertEquals(CENT, uri.getAmount());
    }

    @Test(expected = BitcoinURIParseException.class)
    public void testBad_AmountTooPrecise() throws BitcoinURIParseException {
        BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=0.123456789", MAINNET);
    }

    @Test(expected = BitcoinURIParseException.class)
    public void testBad_NegativeAmount() throws BitcoinURIParseException {
        BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=-1", MAINNET);
    }

    @Test(expected = BitcoinURIParseException.class)
    public void testBad_TooLargeAmount() throws BitcoinURIParseException {
        BigDecimal tooLargeByOne = new BigDecimal(Long.MAX_VALUE).add(BigDecimal.ONE);
        BitcoinURI.of(BITCOIN_SCHEME + ":" + MAINNET_GOOD_ADDRESS
                + "?amount=" + tooLargeByOne.movePointLeft(8), MAINNET);
    }

    @Test
    public void testPaymentProtocolReq() throws Exception {
        // Non-backwards compatible form ...
        BitcoinURI uri = BitcoinURI.of("bitcoin:?r=https%3A%2F%2Fbitcoincore.org%2F%7Egavin%2Ff.php%3Fh%3Db0f02e7cea67f168e25ec9b9f9d584f9", TESTNET);
        assertEquals("https://bitcoincore.org/~gavin/f.php?h=b0f02e7cea67f168e25ec9b9f9d584f9", uri.getPaymentRequestUrl());
        assertEquals(Collections.singletonList("https://bitcoincore.org/~gavin/f.php?h=b0f02e7cea67f168e25ec9b9f9d584f9"),
                uri.getPaymentRequestUrls());
        assertNull(uri.getAddress());
    }

    @Test
    public void testMultiplePaymentProtocolReq() throws Exception {
        BitcoinURI uri = BitcoinURI.of("bitcoin:?r=https%3A%2F%2Fbitcoincore.org%2F%7Egavin&r1=bt:112233445566", MAINNET);
        assertEquals(Arrays.asList("bt:112233445566", "https://bitcoincore.org/~gavin"), uri.getPaymentRequestUrls());
        assertEquals("https://bitcoincore.org/~gavin", uri.getPaymentRequestUrl());
    }

    @Test
    public void testNoPaymentProtocolReq() throws Exception {
        BitcoinURI uri = BitcoinURI.of("bitcoin:" + MAINNET_GOOD_ADDRESS, MAINNET);
        assertNull(uri.getPaymentRequestUrl());
        assertEquals(Collections.emptyList(), uri.getPaymentRequestUrls());
        assertNotNull(uri.getAddress());
    }

    @Test
    public void testUnescapedPaymentProtocolReq() throws Exception {
        BitcoinURI uri = BitcoinURI.of("bitcoin:?r=https://merchant.example.com/pay?h%3D2a8628fc2fbe", TESTNET);
        assertEquals("https://merchant.example.com/pay?h=2a8628fc2fbe", uri.getPaymentRequestUrl());
        assertEquals(Collections.singletonList("https://merchant.example.com/pay?h=2a8628fc2fbe"), uri.getPaymentRequestUrls());
        assertNull(uri.getAddress());
    }
}
