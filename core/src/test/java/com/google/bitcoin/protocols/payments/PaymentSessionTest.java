/**
 * Copyright 2013 Google Inc.
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

import com.google.bitcoin.core.*;
import com.google.bitcoin.params.TestNet3Params;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.protocols.payments.Protos;
import org.junit.Before;
import org.junit.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;

import static org.junit.Assert.*;

public class PaymentSessionTest {
    private static final NetworkParameters params = TestNet3Params.get();
    private static final String simplePaymentUrl = "http://a.simple.url.com/";
    private static final String paymentRequestMemo = "send coinz noa plz kthx";
    private static final String paymentMemo = "take ze coinz";
    private static final ByteString merchantData = ByteString.copyFromUtf8("merchant data");
    private static final long time = System.currentTimeMillis() / 1000L;
    private ECKey serverKey;
    private Transaction tx;
    private TransactionOutput outputToMe;
    BigInteger nanoCoins = Utils.toNanoCoins(1, 0);

    @Before
    public void setUp() throws Exception {
        serverKey = new ECKey();
        tx = new Transaction(params);
        outputToMe = new TransactionOutput(params, tx, nanoCoins, serverKey);
        tx.addOutput(outputToMe);
    }

    @Test
    public void testSimplePayment() throws Exception {
        // Create a PaymentRequest and make sure the correct values are parsed by the PaymentSession.
        MockPaymentSession paymentSession = new MockPaymentSession(newSimplePaymentRequest());
        assertEquals(paymentRequestMemo, paymentSession.getMemo());
        assertEquals(nanoCoins, paymentSession.getValue());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentUrl());
        assertTrue(new Date(time * 1000L).equals(paymentSession.getDate()));
        assertTrue(paymentSession.getSendRequest().tx.equals(tx));
        assertFalse(paymentSession.isExpired());

        // Send the payment and verify that the correct information is sent.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(params, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<Transaction>();
        txns.add(tx);
        Address refundAddr = new Address(params, serverKey.getPubKeyHash());
        paymentSession.sendPayment(txns, refundAddr, paymentMemo);
        assertEquals(1, paymentSession.getPaymentLog().size());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentLog().get(0).getUrl().toString());
        Protos.Payment payment = paymentSession.getPaymentLog().get(0).getPayment();
        assertEquals(paymentMemo, payment.getMemo());
        assertEquals(merchantData, payment.getMerchantData());
        assertEquals(1, payment.getRefundToCount());
        assertEquals(nanoCoins.longValue(), payment.getRefundTo(0).getAmount());
        TransactionOutput refundOutput = new TransactionOutput(params, null, nanoCoins, refundAddr);
        ByteString refundScript = ByteString.copyFrom(refundOutput.getScriptBytes());
        assertTrue(refundScript.equals(payment.getRefundTo(0).getScript()));
    }

    @Test
    public void testDefaults() throws Exception {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setTime(time)
                .addOutputs(outputBuilder)
                .build();
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder()
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
        MockPaymentSession paymentSession = new MockPaymentSession(paymentRequest);
        assertEquals(BigInteger.ZERO, paymentSession.getValue());
        assertNull(paymentSession.getPaymentUrl());
        assertNull(paymentSession.getMemo());
    }

    @Test
    public void testExpiredPaymentRequest() throws Exception {
        MockPaymentSession paymentSession = new MockPaymentSession(newExpiredPaymentRequest());
        assertTrue(paymentSession.isExpired());
        // Send the payment and verify that an exception is thrown.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(params, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<Transaction>();
        txns.add(tx);
        try {
            paymentSession.sendPayment(txns, null, null);
        } catch(PaymentRequestException.Expired e) {
            assertEquals(0, paymentSession.getPaymentLog().size());
            assertEquals(e.getMessage(), "PaymentRequest is expired");
            return;
        }
        fail("Expected exception due to expired PaymentRequest");
    }

    @Test
    public void testPkiVerification() throws Exception {
        InputStream in = getClass().getResourceAsStream("pki_test.bitcoinpaymentrequest");
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder().mergeFrom(in).build();
        MockPaymentSession paymentSession = new MockPaymentSession(paymentRequest);
        PaymentSession.PkiVerificationData pkiData = paymentSession.verifyPki();
        assertEquals("www.bitcoincore.org", pkiData.name);
        assertEquals("The USERTRUST Network, Salt Lake City, US", pkiData.rootAuthorityName);
    }

    private Protos.PaymentRequest newSimplePaymentRequest() {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(nanoCoins.longValue())
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork("test")
                .setTime(time)
                .setPaymentUrl(simplePaymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
        return paymentRequest;
    }

    private Protos.PaymentRequest newExpiredPaymentRequest() {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(nanoCoins.longValue())
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork("test")
                .setTime(time - 10)
                .setExpires(time - 1)
                .setPaymentUrl(simplePaymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        Protos.PaymentRequest paymentRequest  = Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
        return paymentRequest ;
    }

    private class MockPaymentSession extends PaymentSession {
        private ArrayList<PaymentLogItem> paymentLog = new ArrayList<PaymentLogItem>();

        public MockPaymentSession(Protos.PaymentRequest request) throws PaymentRequestException {
            super(request);
        }

        public ArrayList<PaymentLogItem> getPaymentLog() {
            return paymentLog;
        }

        protected ListenableFuture<Ack> sendPayment(final URL url, final Protos.Payment payment) {
            paymentLog.add(new PaymentLogItem(url, payment));
            return null;
        }

        public class PaymentLogItem {
            private final URL url;
            private final Protos.Payment payment;

            PaymentLogItem(final URL url, final Protos.Payment payment) {
                this.url = url;
                this.payment = payment;
            }

            public URL getUrl() {
                return url;
            }

            public Protos.Payment getPayment() {
                return payment;
            }
        }
    }
}
