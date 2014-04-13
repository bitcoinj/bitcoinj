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

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.Nullable;

import org.bitcoin.protocols.payments.Protos;

import com.google.bitcoin.crypto.X509Utils;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

public class PaymentProtocol {

    // MIME types as defined in BIP71.
    public static final String MIMETYPE_PAYMENTREQUEST = "application/bitcoin-paymentrequest";
    public static final String MIMETYPE_PAYMENT = "application/bitcoin-payment";
    public static final String MIMETYPE_PAYMENTACK = "application/bitcoin-paymentack";

    /**
     * Sign the provided payment request.
     * 
     * @param paymentRequest
     *            Payment request to sign, in its builder form.
     * @param certificateChain
     *            Certificate chain to send with the payment request, ordered from client certificate to root
     *            certificate. The root certificate itself may be omitted.
     * @param privateKey
     *            The key to sign with. Must match the public key from the first certificate of the certificate chain.
     */
    public static void signPaymentRequestPki(Protos.PaymentRequest.Builder paymentRequest,
            X509Certificate[] certificateChain, PrivateKey privateKey) {
        try {
            final Protos.X509Certificates.Builder certificates = Protos.X509Certificates.newBuilder();
            for (final Certificate certificate : certificateChain)
                certificates.addCertificate(ByteString.copyFrom(certificate.getEncoded()));

            paymentRequest.setPkiType("x509+sha256");
            paymentRequest.setPkiData(certificates.build().toByteString());
            paymentRequest.setSignature(ByteString.EMPTY);
            final Protos.PaymentRequest paymentRequestToSign = paymentRequest.build();

            final String algorithm;
            if (privateKey.getAlgorithm().equalsIgnoreCase("RSA"))
                algorithm = "SHA256withRSA";
            else
                throw new IllegalStateException(privateKey.getAlgorithm());

            final Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(paymentRequestToSign.toByteArray());

            paymentRequest.setSignature(ByteString.copyFrom(signature.sign()));
        } catch (final GeneralSecurityException x) {
            // Should never happen so don't make users have to think about it.
            throw new RuntimeException(x);
        }
    }

    /**
     * Uses the provided PKI method to find the corresponding public key and verify the provided signature.
     * 
     * @param paymentRequest
     *            Payment request to verify.
     * @param trustStore
     *            KeyStory of trusted root certificate authorities.
     * @return verification data, or null if no PKI method was specified in the {@link Protos.PaymentRequest}.
     * @throws PaymentRequestException
     *             if payment request could not be verified.
     */
    public static @Nullable PkiVerificationData verifyPaymentRequestPki(Protos.PaymentRequest paymentRequest, KeyStore trustStore)
            throws PaymentRequestException {
        List<X509Certificate> certs = null;
        try {
            final String pkiType = paymentRequest.getPkiType();
            if (pkiType.equals("none"))
                // Nothing to verify. Everything is fine. Move along.
                return null;

            String algorithm;
            if (pkiType.equals("x509+sha256"))
                algorithm = "SHA256withRSA";
            else if (pkiType.equals("x509+sha1"))
                algorithm = "SHA1withRSA";
            else
                throw new PaymentRequestException.InvalidPkiType("Unsupported PKI type: " + pkiType);

            Protos.X509Certificates protoCerts = Protos.X509Certificates.parseFrom(paymentRequest.getPkiData());
            if (protoCerts.getCertificateCount() == 0)
                throw new PaymentRequestException.InvalidPkiData("No certificates provided in message: server config error");

            // Parse the certs and turn into a certificate chain object. Cert factories can parse both DER and base64.
            // The ordering of certificates is defined by the payment protocol spec to be the same as what the Java
            // crypto API requires - convenient!
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            certs = Lists.newArrayList();
            for (ByteString bytes : protoCerts.getCertificateList())
                certs.add((X509Certificate) certificateFactory.generateCertificate(bytes.newInput()));
            CertPath path = certificateFactory.generateCertPath(certs);

            // Retrieves the most-trusted CAs from keystore.
            PKIXParameters params = new PKIXParameters(trustStore);
            // Revocation not supported in the current version.
            params.setRevocationEnabled(false);

            // Now verify the certificate chain is correct and trusted. This let's us get an identity linked pubkey.
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(path, params);
            PublicKey publicKey = result.getPublicKey();
            // OK, we got an identity, now check it was used to sign this message.
            Signature signature = Signature.getInstance(algorithm);
            // Note that we don't use signature.initVerify(certs.get(0)) here despite it being the most obvious
            // way to set it up, because we don't care about the constraints specified on the certificates: any
            // cert that links a key to a domain name or other identity will do for us.
            signature.initVerify(publicKey);
            Protos.PaymentRequest.Builder reqToCheck = paymentRequest.toBuilder();
            reqToCheck.setSignature(ByteString.EMPTY);
            signature.update(reqToCheck.build().toByteArray());
            if (!signature.verify(paymentRequest.getSignature().toByteArray()))
                throw new PaymentRequestException.PkiVerificationException("Invalid signature, this payment request is not valid.");

            // Signature verifies, get the names from the identity we just verified for presentation to the user.
            final X509Certificate cert = certs.get(0);
            String displayName = X509Utils.getDisplayNameFromCertificate(cert, true);
            if (displayName == null)
                throw new PaymentRequestException.PkiVerificationException("Could not extract name from certificate");
            // Everything is peachy. Return some useful data to the caller.
            return new PkiVerificationData(displayName, publicKey, result.getTrustAnchor());
        } catch (InvalidProtocolBufferException e) {
            // Data structures are malformed.
            throw new PaymentRequestException.InvalidPkiData(e);
        } catch (CertificateException e) {
            // The X.509 certificate data didn't parse correctly.
            throw new PaymentRequestException.PkiVerificationException(e);
        } catch (NoSuchAlgorithmException e) {
            // Should never happen so don't make users have to think about it. PKIX is always present.
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (CertPathValidatorException e) {
            // The certificate chain isn't known or trusted, probably, the server is using an SSL root we don't
            // know about and the user needs to upgrade to a new version of the software (or import a root cert).
            throw new PaymentRequestException.PkiVerificationException(e, certs);
        } catch (InvalidKeyException e) {
            // Shouldn't happen if the certs verified correctly.
            throw new PaymentRequestException.PkiVerificationException(e);
        } catch (SignatureException e) {
            // Something went wrong during hashing (yes, despite the name, this does not mean the sig was invalid).
            throw new PaymentRequestException.PkiVerificationException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Information about the X509 signature's issuer and subject.
     */
    public static class PkiVerificationData {
        /** Display name of the payment requestor, could be a domain name, email address, legal name, etc */
        public final String displayName;
        /** SSL public key that was used to sign. */
        public final PublicKey merchantSigningKey;
        /** Object representing the CA that verified the merchant's ID */
        public final TrustAnchor rootAuthority;
        /** String representing the display name of the CA that verified the merchant's ID */
        public final String rootAuthorityName;

        private PkiVerificationData(@Nullable String displayName, PublicKey merchantSigningKey,
                                    TrustAnchor rootAuthority) throws PaymentRequestException.PkiVerificationException {
            try {
                this.displayName = displayName;
                this.merchantSigningKey = merchantSigningKey;
                this.rootAuthority = rootAuthority;
                this.rootAuthorityName = X509Utils.getDisplayNameFromCertificate(rootAuthority.getTrustedCert(), true);
            } catch (CertificateParsingException x) {
                throw new PaymentRequestException.PkiVerificationException(x);
            }
        }
    }
}
