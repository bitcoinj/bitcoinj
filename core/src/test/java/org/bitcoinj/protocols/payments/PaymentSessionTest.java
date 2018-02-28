/*
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

package org.bitcoinj.protocols.payments;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TrustStoreLoader;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.protocols.payments.Protos;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;

import static org.bitcoinj.core.Coin.COIN;
import static org.junit.Assert.*;

public class PaymentSessionTest {
    private static final NetworkParameters PARAMS = TestNet3Params.get();
    private static final String simplePaymentUrl = "http://a.simple.url.com/";
    private static final String paymentRequestMemo = "send coinz noa plz kthx";
    private static final String paymentMemo = "take ze coinz";
    private static final ByteString merchantData = ByteString.copyFromUtf8("merchant data");
    private static final long time = System.currentTimeMillis() / 1000L;
    private ECKey serverKey;
    private Transaction tx;
    private TransactionOutput outputToMe;
    private Coin coin = COIN;

    @Before
    public void setUp() throws Exception {
        new Context(PARAMS);
        serverKey = new ECKey();
        tx = new Transaction(PARAMS);
        outputToMe = new TransactionOutput(PARAMS, tx, coin, serverKey);
        tx.addOutput(outputToMe);
    }

    @Test
    public void testSimplePayment() throws Exception {
        // Create a PaymentRequest and make sure the correct values are parsed by the PaymentSession.
        MockPaymentSession paymentSession = new MockPaymentSession(newSimplePaymentRequest("test"));
        assertEquals(paymentRequestMemo, paymentSession.getMemo());
        assertEquals(coin, paymentSession.getValue());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentUrl());
        assertTrue(new Date(time * 1000L).equals(paymentSession.getDate()));
        assertTrue(paymentSession.getSendRequest().tx.equals(tx));
        assertFalse(paymentSession.isExpired());

        // Send the payment and verify that the correct information is sent.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(PARAMS, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<Transaction>();
        txns.add(tx);
        Address refundAddr = new Address(PARAMS, serverKey.getPubKeyHash());
        paymentSession.sendPayment(txns, refundAddr, paymentMemo);
        assertEquals(1, paymentSession.getPaymentLog().size());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentLog().get(0).getUrl().toString());
        Protos.Payment payment = paymentSession.getPaymentLog().get(0).getPayment();
        assertEquals(paymentMemo, payment.getMemo());
        assertEquals(merchantData, payment.getMerchantData());
        assertEquals(1, payment.getRefundToCount());
        assertEquals(coin.value, payment.getRefundTo(0).getAmount());
        TransactionOutput refundOutput = new TransactionOutput(PARAMS, null, coin, refundAddr);
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
        assertEquals(Coin.ZERO, paymentSession.getValue());
        assertNull(paymentSession.getPaymentUrl());
        assertNull(paymentSession.getMemo());
    }

    @Test
    public void testExpiredPaymentRequest() throws Exception {
        MockPaymentSession paymentSession = new MockPaymentSession(newExpiredPaymentRequest());
        assertTrue(paymentSession.isExpired());
        // Send the payment and verify that an exception is thrown.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(PARAMS, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<Transaction>();
        txns.add(tx);
        try {
            paymentSession.sendPayment(txns, null, null);
        } catch(PaymentProtocolException.Expired e) {
            assertEquals(0, paymentSession.getPaymentLog().size());
            assertEquals(e.getMessage(), "PaymentRequest is expired");
            return;
        }
        fail("Expected exception due to expired PaymentRequest");
    }

    @Test
    @Ignore("certificate expired")
    public void testPkiVerification() throws Exception {
        InputStream in = getClass().getResourceAsStream("pki_test.bitcoinpaymentrequest");
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder().mergeFrom(in).build();
        PaymentProtocol.PkiVerificationData pkiData = PaymentProtocol.verifyPaymentRequestPki(paymentRequest,
                new TrustStoreLoader.DefaultTrustStoreLoader().getKeyStore());
        assertEquals("www.bitcoincore.org", pkiData.displayName);
        assertEquals("The USERTRUST Network, Salt Lake City, US", pkiData.rootAuthorityName);
    }

    @Test(expected = PaymentProtocolException.InvalidNetwork.class)
    public void testWrongNetwork() throws Exception {
        // Create a PaymentRequest and make sure the correct values are parsed by the PaymentSession.
        MockPaymentSession paymentSession = new MockPaymentSession(newSimplePaymentRequest("main"));
        assertEquals(MainNetParams.get(), paymentSession.getNetworkParameters());

        // Send the payment and verify that the correct information is sent.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(PARAMS, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<Transaction>();
        txns.add(tx);
        Address refundAddr = new Address(PARAMS, serverKey.getPubKeyHash());
        paymentSession.sendPayment(txns, refundAddr, paymentMemo);
        assertEquals(1, paymentSession.getPaymentLog().size());
    }

    private Protos.PaymentRequest newSimplePaymentRequest(String netID) {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(coin.value)
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork(netID)
                .setTime(time)
                .setPaymentUrl(simplePaymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        return Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
    }

    private Protos.PaymentRequest newExpiredPaymentRequest() {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(coin.value)
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
        return Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
    }

    private class MockPaymentSession extends PaymentSession {
        private ArrayList<PaymentLogItem> paymentLog = new ArrayList<PaymentLogItem>();

        public MockPaymentSession(Protos.PaymentRequest request) throws PaymentProtocolException {
            super(request);
        }

        public ArrayList<PaymentLogItem> getPaymentLog() {
            return paymentLog;
        }

        @Override
        protected ListenableFuture<PaymentProtocol.Ack> sendPayment(final URL url, final Protos.Payment payment) {
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
