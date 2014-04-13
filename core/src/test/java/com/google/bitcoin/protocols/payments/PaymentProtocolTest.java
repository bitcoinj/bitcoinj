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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bitcoin.protocols.payments.Protos;
import org.junit.Before;
import org.junit.Test;

import com.google.bitcoin.crypto.X509Utils;
import com.google.bitcoin.protocols.payments.PaymentProtocol.PkiVerificationData;
import com.google.bitcoin.protocols.payments.PaymentRequestException.PkiVerificationException;

public class PaymentProtocolTest {

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
        PaymentProtocol.signPaymentRequestPki(paymentRequest, new X509Certificate[] { clientCert }, privateKey);

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
        PaymentProtocol.signPaymentRequestPki(paymentRequest, new X509Certificate[] { clientCert }, privateKey);

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
}
