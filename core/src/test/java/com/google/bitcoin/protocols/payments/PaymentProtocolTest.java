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

package com.google.bitcoin.protocols.payments;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.bitcoin.protocols.payments.Protos;
import org.bitcoin.protocols.payments.Protos.Payment;
import org.bitcoin.protocols.payments.Protos.PaymentACK;
import org.bitcoin.protocols.payments.Protos.PaymentRequest;
import org.junit.Before;
import org.junit.Test;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.Coin;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.crypto.X509Utils;
import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.protocols.payments.PaymentProtocol.Output;
import com.google.bitcoin.protocols.payments.PaymentProtocol.PkiVerificationData;
import com.google.bitcoin.protocols.payments.PaymentProtocolException.PkiVerificationException;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.testing.FakeTxBuilder;

public class PaymentProtocolTest {

    // static test data
    private static final NetworkParameters NETWORK_PARAMS = UnitTestParams.get();
    private static final Coin AMOUNT = Coin.ONE;
    private static final Address TO_ADDRESS = new ECKey().toAddress(NETWORK_PARAMS);
    private static final String MEMO = "memo";
    private static final String PAYMENT_URL = "https://example.com";
    private static final byte[] MERCHANT_DATA = new byte[] { 0, 1, 2 };

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
        paymentDetails.setTime(System.currentTimeMillis());
        Protos.PaymentRequest.Builder paymentRequest = Protos.PaymentRequest.newBuilder();
        paymentRequest.setSerializedPaymentDetails(paymentDetails.build().toByteString());
        return paymentRequest.build();
    }

    public void testPaymentRequest() throws Exception {
        // Create
        PaymentRequest paymentRequest = PaymentProtocol.createPaymentRequest(NETWORK_PARAMS, AMOUNT, TO_ADDRESS, MEMO,
                PAYMENT_URL, MERCHANT_DATA).build();
        byte[] paymentRequestBytes = paymentRequest.toByteArray();

        // Parse
        PaymentSession parsedPaymentRequest = PaymentProtocol.parsePaymentRequest(PaymentRequest
                .parseFrom(paymentRequestBytes));
        final List<Output> parsedOutputs = parsedPaymentRequest.getOutputs();
        assertEquals(1, parsedOutputs.size());
        assertEquals(AMOUNT, parsedOutputs.get(0).amount);
        assertEquals(ScriptBuilder.createOutputScript(TO_ADDRESS).getProgram(), parsedOutputs.get(0).scriptData);
        assertEquals(MEMO, parsedPaymentRequest.getMemo());
        assertEquals(PAYMENT_URL, parsedPaymentRequest.getPaymentUrl());
        assertEquals(MERCHANT_DATA, parsedPaymentRequest.getMerchantData());
    }

    @Test
    public void testPaymentMessage() throws Exception {
        // Create
        List<Transaction> transactions = new LinkedList<Transaction>();
        transactions.add(FakeTxBuilder.createFakeTx(NETWORK_PARAMS, AMOUNT, TO_ADDRESS));
        Coin refundAmount = Coin.ONE;
        Address refundAddress = new ECKey().toAddress(NETWORK_PARAMS);
        Payment payment = PaymentProtocol.createPaymentMessage(transactions, refundAmount, refundAddress, MEMO,
                MERCHANT_DATA);
        byte[] paymentBytes = payment.toByteArray();

        // Parse
        Payment parsedPayment = Payment.parseFrom(paymentBytes);
        List<Transaction> parsedTransactions = PaymentProtocol.parseTransactionsFromPaymentMessage(NETWORK_PARAMS,
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
