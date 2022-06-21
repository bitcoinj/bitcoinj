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

package org.bitcoinj.protocols.payments;

import org.bitcoin.protocols.payments.Protos;
import org.bitcoin.protocols.payments.Protos.Payment;
import org.bitcoin.protocols.payments.Protos.PaymentACK;
import org.bitcoin.protocols.payments.Protos.PaymentRequest;
import org.bitcoinj.core.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.X509Utils;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.protocols.payments.PaymentProtocol.Output;
import org.bitcoinj.protocols.payments.PaymentProtocol.PkiVerificationData;
import org.bitcoinj.protocols.payments.PaymentProtocolException.PkiVerificationException;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.testing.FakeTxBuilder;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PaymentProtocolTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters TESTNET = TestNet3Params.get();

    // static test data
    private static final Coin AMOUNT = Coin.SATOSHI;
    private static final Address TO_ADDRESS = LegacyAddress.fromKey(UNITTEST, new ECKey());
    private static final String MEMO = "memo";
    private static final String PAYMENT_URL = "https://example.com";
    private static final byte[] MERCHANT_DATA = { 0, 1, 2 };

    private KeyStore caStore;
    private X509Certificate caCert;

    @Before
    public void setUp() throws Exception {
        caStore = X509Utils.loadKeyStore("JKS", "password", getClass().getResourceAsStream("test-cacerts"));
        caCert = (X509Certificate) caStore.getCertificate("test-cacert");
    }

    @Test
    public void testSignAndVerifyValid() throws Exception {
        Protos.PaymentRequest.Builder paymentRequest = minimalPaymentRequest().toBuilder();

        // Sign
        KeyStore keyStore = X509Utils
                .loadKeyStore("JKS", "password", getClass().getResourceAsStream("test-valid-cert"));
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("test-valid", "password".toCharArray());
        X509Certificate clientCert = (X509Certificate) keyStore.getCertificate("test-valid");
        PaymentProtocol.signPaymentRequest(paymentRequest, new X509Certificate[]{clientCert}, privateKey);

        // Verify
        PkiVerificationData verificationData = PaymentProtocol.verifyPaymentRequestPki(paymentRequest.build(), caStore);
        assertNotNull(verificationData);
        assertEquals(caCert, verificationData.rootAuthority.getTrustedCert());
    }

    @Test(expected = PkiVerificationException.class)
    public void testSignAndVerifyExpired() throws Exception {
        Protos.PaymentRequest.Builder paymentRequest = minimalPaymentRequest().toBuilder();

        // Sign
        KeyStore keyStore = X509Utils.loadKeyStore("JKS", "password",
                getClass().getResourceAsStream("test-expired-cert"));
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("test-expired", "password".toCharArray());
        X509Certificate clientCert = (X509Certificate) keyStore.getCertificate("test-expired");
        PaymentProtocol.signPaymentRequest(paymentRequest, new X509Certificate[]{clientCert}, privateKey);

        // Verify
        PaymentProtocol.verifyPaymentRequestPki(paymentRequest.build(), caStore);
    }

    private Protos.PaymentRequest minimalPaymentRequest() {
        Protos.PaymentDetails.Builder paymentDetails = Protos.PaymentDetails.newBuilder();
        paymentDetails.setTime(Utils.currentTimeSeconds());
        Protos.PaymentRequest.Builder paymentRequest = Protos.PaymentRequest.newBuilder();
        paymentRequest.setSerializedPaymentDetails(paymentDetails.build().toByteString());
        return paymentRequest.build();
    }

    @Test
    public void testPaymentRequest() throws Exception {
        // Create
        PaymentRequest paymentRequest = PaymentProtocol.createPaymentRequest(TESTNET, AMOUNT, TO_ADDRESS, MEMO,
                PAYMENT_URL, MERCHANT_DATA).build();
        byte[] paymentRequestBytes = paymentRequest.toByteArray();

        // Parse
        PaymentSession parsedPaymentRequest = PaymentProtocol.parsePaymentRequest(PaymentRequest
                .parseFrom(paymentRequestBytes));
        final List<Output> parsedOutputs = parsedPaymentRequest.getOutputs();
        assertEquals(1, parsedOutputs.size());
        assertEquals(AMOUNT, parsedOutputs.get(0).amount);
        assertArrayEquals(ScriptBuilder.createOutputScript(TO_ADDRESS).getProgram(), parsedOutputs.get(0).scriptData);
        assertEquals(MEMO, parsedPaymentRequest.getMemo());
        assertEquals(PAYMENT_URL, parsedPaymentRequest.getPaymentUrl());
        assertArrayEquals(MERCHANT_DATA, parsedPaymentRequest.getMerchantData());
    }

    @Test
    public void testPaymentMessage() throws Exception {
        // Create
        List<Transaction> transactions = new LinkedList<>();
        transactions.add(FakeTxBuilder.createFakeTx(UNITTEST, AMOUNT, TO_ADDRESS));
        Coin refundAmount = Coin.SATOSHI;
        Address refundAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
        Payment payment = PaymentProtocol.createPaymentMessage(transactions, refundAmount, refundAddress, MEMO,
                MERCHANT_DATA);
        byte[] paymentBytes = payment.toByteArray();

        // Parse
        Payment parsedPayment = Payment.parseFrom(paymentBytes);
        List<Transaction> parsedTransactions = PaymentProtocol.parseTransactionsFromPaymentMessage(UNITTEST,
                parsedPayment);
        assertEquals(transactions, parsedTransactions);
        assertEquals(1, parsedPayment.getRefundToCount());
        assertEquals(MEMO, parsedPayment.getMemo());
        assertArrayEquals(MERCHANT_DATA, parsedPayment.getMerchantData().toByteArray());
    }

    @Test
    public void testPaymentAck() throws Exception {
        // Create
        Payment paymentMessage = Protos.Payment.newBuilder().build();
        PaymentACK paymentAck = PaymentProtocol.createPaymentAck(paymentMessage, MEMO);
        byte[] paymentAckBytes = paymentAck.toByteArray();

        // Parse
        PaymentACK parsedPaymentAck = PaymentACK.parseFrom(paymentAckBytes);
        assertEquals(paymentMessage, parsedPaymentAck.getPayment());
        assertEquals(MEMO, parsedPaymentAck.getMemo());
    }
}
