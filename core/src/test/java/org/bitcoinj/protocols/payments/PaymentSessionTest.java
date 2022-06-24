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

import com.google.protobuf.ByteString;
import org.bitcoin.protocols.payments.Protos;
import org.bitcoinj.core.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.TrustStoreLoader;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.utils.ListenableCompletableFuture;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.bitcoinj.base.Coin.COIN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PaymentSessionTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private static final String simplePaymentUrl = "http://a.simple.url.com/";
    private static final String paymentRequestMemo = "send coinz noa plz kthx";
    private static final String paymentMemo = "take ze coinz";
    private static final ByteString merchantData = ByteString.copyFromUtf8("merchant data");
    private static final long time = Utils.currentTimeSeconds();
    private ECKey serverKey;
    private Transaction tx;
    private TransactionOutput outputToMe;
    private final Coin amount = COIN;

    @Before
    public void setUp() {
        serverKey = new ECKey();
        tx = new Transaction(TESTNET);
        outputToMe = new TransactionOutput(TESTNET, tx, amount, serverKey);
        tx.addOutput(outputToMe);
    }

    @Test
    public void testSimplePayment() throws Exception {
        // Create a PaymentRequest and make sure the correct values are parsed by the PaymentSession.
        MockPaymentSession paymentSession = new MockPaymentSession(newSimplePaymentRequest("test"));
        assertEquals(paymentRequestMemo, paymentSession.getMemo());
        assertEquals(amount, paymentSession.getValue());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentUrl());
        assertTrue(new Date(time * 1000L).equals(paymentSession.getDate()));
        assertTrue(paymentSession.getSendRequest().tx.equals(tx));
        assertFalse(paymentSession.isExpired());

        // Send the payment and verify that the correct information is sent.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(TESTNET, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<>();
        txns.add(tx);
        Address refundAddr = LegacyAddress.fromKey(TESTNET, serverKey);
        paymentSession.sendPayment(txns, refundAddr, paymentMemo);
        assertEquals(1, paymentSession.getPaymentLog().size());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentLog().get(0).getUrl().toString());
        Protos.Payment payment = paymentSession.getPaymentLog().get(0).getPayment();
        assertEquals(paymentMemo, payment.getMemo());
        assertEquals(merchantData, payment.getMerchantData());
        assertEquals(1, payment.getRefundToCount());
        assertEquals(amount.value, payment.getRefundTo(0).getAmount());
        TransactionOutput refundOutput = new TransactionOutput(TESTNET, null, amount, refundAddr);
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
    public void testExpiredPaymentRequest() throws PaymentProtocolException {
        MockPaymentSession paymentSession = new MockPaymentSession(newExpiredPaymentRequest());
        assertTrue(paymentSession.isExpired());
        // Send the payment and verify that an exception is thrown.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(TESTNET, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<>();
        txns.add(tx);

        CompletableFuture<PaymentProtocol.Ack> ack = paymentSession.sendPayment(txns, null, null);
        try {
            ack.get();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof PaymentProtocolException.Expired) {
                PaymentProtocolException.Expired cause = (PaymentProtocolException.Expired) e.getCause();
                assertEquals(0, paymentSession.getPaymentLog().size());
                assertEquals(cause.getMessage(), "PaymentRequest is expired");
                return;
            }
        } catch (InterruptedException e) {
            // Ignore
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
    public void testWrongNetwork() throws Throwable {
        // Create a PaymentRequest and make sure the correct values are parsed by the PaymentSession.
        MockPaymentSession paymentSession = new MockPaymentSession(newSimplePaymentRequest("main"));
        assertEquals(MAINNET, paymentSession.getNetworkParameters());

        // Send the payment and verify that the correct information is sent.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(TESTNET, tx, outputToMe.getScriptBytes()));
        ArrayList<Transaction> txns = new ArrayList<>();
        txns.add(tx);
        Address refundAddr = LegacyAddress.fromKey(TESTNET, serverKey);
        try {
            paymentSession.sendPayment(txns, refundAddr, paymentMemo).get();
        } catch (InterruptedException e) {
            fail("Incorrect exception type");
        } catch (ExecutionException e) {
            // We're expecting PaymentProtocolException.InvalidNetwork as the cause
            throw e.getCause();
        }
    }

    private Protos.PaymentRequest newSimplePaymentRequest(String netID) {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(amount.value)
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
                .setAmount(amount.value)
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

    private static class MockPaymentSession extends PaymentSession {
        private final ArrayList<PaymentLogItem> paymentLog = new ArrayList<>();

        public MockPaymentSession(Protos.PaymentRequest request) throws PaymentProtocolException {
            super(request);
        }

        public ArrayList<PaymentLogItem> getPaymentLog() {
            return paymentLog;
        }

        @Override
        protected ListenableCompletableFuture<PaymentProtocol.Ack> sendPayment(final URL url, final Protos.Payment payment) {
            paymentLog.add(new PaymentLogItem(url, payment));
            // Return a completed future that has a `null` value. This will satisfy the current tests.
            return ListenableCompletableFuture.completedFuture(null);
        }

        public static class PaymentLogItem {
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
