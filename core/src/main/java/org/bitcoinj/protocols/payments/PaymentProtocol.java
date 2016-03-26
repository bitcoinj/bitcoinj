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
import org.bitcoinj.crypto.X509Utils;
import org.bitcoinj.script.ScriptBuilder;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.bitcoin.protocols.payments.Protos;

import javax.annotation.Nullable;
import java.io.Serializable;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Utility methods and constants for working with <a href="https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki">
 * BIP 70 aka the payment protocol</a>. These are low level wrappers around the protocol buffers. If you're implementing
 * a wallet app, look at {@link PaymentSession} for a higher level API that should simplify working with the protocol.</p>
 *
 * <p>BIP 70 defines a binary, protobuf based protocol that runs directly between sender and receiver of funds. Payment
 * protocol data does not flow over the Bitcoin P2P network or enter the block chain. It's instead for data that is only
 * of interest to the parties involved but isn't otherwise needed for consensus.</p>
 */
public class PaymentProtocol {

    // MIME types as defined in BIP71.
    public static final String MIMETYPE_PAYMENTREQUEST = "application/bitcoin-paymentrequest";
    public static final String MIMETYPE_PAYMENT = "application/bitcoin-payment";
    public static final String MIMETYPE_PAYMENTACK = "application/bitcoin-paymentack";

    /**
     * Create a payment request with one standard pay to address output. You may want to sign the request using
     * {@link #signPaymentRequest}. Use {@link Protos.PaymentRequest.Builder#build} to get the actual payment
     * request.
     *
     * @param params network parameters
     * @param amount amount of coins to request, or null
     * @param toAddress address to request coins to
     * @param memo arbitrary, user readable memo, or null if none
     * @param paymentUrl URL to send payment message to, or null if none
     * @param merchantData arbitrary merchant data, or null if none
     * @return created payment request, in its builder form
     */
    public static Protos.PaymentRequest.Builder createPaymentRequest(NetworkParameters params,
            @Nullable Coin amount, Address toAddress, @Nullable String memo, @Nullable String paymentUrl,
            @Nullable byte[] merchantData) {
        return createPaymentRequest(params, ImmutableList.of(createPayToAddressOutput(amount, toAddress)), memo,
                paymentUrl, merchantData);
    }

    /**
     * Create a payment request. You may want to sign the request using {@link #signPaymentRequest}. Use
     * {@link Protos.PaymentRequest.Builder#build} to get the actual payment request.
     * 
     * @param params network parameters
     * @param outputs list of outputs to request coins to
     * @param memo arbitrary, user readable memo, or null if none
     * @param paymentUrl URL to send payment message to, or null if none
     * @param merchantData arbitrary merchant data, or null if none
     * @return created payment request, in its builder form
     */
    public static Protos.PaymentRequest.Builder createPaymentRequest(NetworkParameters params,
            List<Protos.Output> outputs, @Nullable String memo, @Nullable String paymentUrl,
            @Nullable byte[] merchantData) {
        final Protos.PaymentDetails.Builder paymentDetails = Protos.PaymentDetails.newBuilder();
        paymentDetails.setNetwork(params.getPaymentProtocolId());
        for (Protos.Output output : outputs)
            paymentDetails.addOutputs(output);
        if (memo != null)
            paymentDetails.setMemo(memo);
        if (paymentUrl != null)
            paymentDetails.setPaymentUrl(paymentUrl);
        if (merchantData != null)
            paymentDetails.setMerchantData(ByteString.copyFrom(merchantData));
        paymentDetails.setTime(Utils.currentTimeSeconds());

        final Protos.PaymentRequest.Builder paymentRequest = Protos.PaymentRequest.newBuilder();
        paymentRequest.setSerializedPaymentDetails(paymentDetails.build().toByteString());
        return paymentRequest;
    }

    /**
     * Parse a payment request.
     * 
     * @param paymentRequest payment request to parse
     * @return instance of {@link PaymentSession}, used as a value object
     * @throws PaymentProtocolException
     */
    public static PaymentSession parsePaymentRequest(Protos.PaymentRequest paymentRequest)
            throws PaymentProtocolException {
        return new PaymentSession(paymentRequest, false, null);
    }

    /**
     * Sign the provided payment request.
     * 
     * @param paymentRequest Payment request to sign, in its builder form.
     * @param certificateChain Certificate chain to send with the payment request, ordered from client certificate to root
     *            certificate. The root certificate itself may be omitted.
     * @param privateKey The key to sign with. Must match the public key from the first certificate of the certificate chain.
     */
    public static void signPaymentRequest(Protos.PaymentRequest.Builder paymentRequest,
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
            if ("RSA".equalsIgnoreCase(privateKey.getAlgorithm()))
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
     * @param paymentRequest Payment request to verify.
     * @param trustStore KeyStore of trusted root certificate authorities.
     * @return verification data, or null if no PKI method was specified in the {@link Protos.PaymentRequest}.
     * @throws PaymentProtocolException if payment request could not be verified.
     */
    @Nullable
    public static PkiVerificationData verifyPaymentRequestPki(Protos.PaymentRequest paymentRequest, KeyStore trustStore)
            throws PaymentProtocolException {
        List<X509Certificate> certs = null;
        try {
            final String pkiType = paymentRequest.getPkiType();
            if ("none".equals(pkiType))
                // Nothing to verify. Everything is fine. Move along.
                return null;

            String algorithm;
            if ("x509+sha256".equals(pkiType))
                algorithm = "SHA256withRSA";
            else if ("x509+sha1".equals(pkiType))
                algorithm = "SHA1withRSA";
            else
                throw new PaymentProtocolException.InvalidPkiType("Unsupported PKI type: " + pkiType);

            Protos.X509Certificates protoCerts = Protos.X509Certificates.parseFrom(paymentRequest.getPkiData());
            if (protoCerts.getCertificateCount() == 0)
                throw new PaymentProtocolException.InvalidPkiData("No certificates provided in message: server config error");

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
                throw new PaymentProtocolException.PkiVerificationException("Invalid signature, this payment request is not valid.");

            // Signature verifies, get the names from the identity we just verified for presentation to the user.
            final X509Certificate cert = certs.get(0);
            String displayName = X509Utils.getDisplayNameFromCertificate(cert, true);
            if (displayName == null)
                throw new PaymentProtocolException.PkiVerificationException("Could not extract name from certificate");
            // Everything is peachy. Return some useful data to the caller.
            return new PkiVerificationData(displayName, publicKey, result.getTrustAnchor());
        } catch (InvalidProtocolBufferException e) {
            // Data structures are malformed.
            throw new PaymentProtocolException.InvalidPkiData(e);
        } catch (CertificateException e) {
            // The X.509 certificate data didn't parse correctly.
            throw new PaymentProtocolException.PkiVerificationException(e);
        } catch (NoSuchAlgorithmException e) {
            // Should never happen so don't make users have to think about it. PKIX is always present.
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (CertPathValidatorException e) {
            // The certificate chain isn't known or trusted, probably, the server is using an SSL root we don't
            // know about and the user needs to upgrade to a new version of the software (or import a root cert).
            throw new PaymentProtocolException.PkiVerificationException(e, certs);
        } catch (InvalidKeyException e) {
            // Shouldn't happen if the certs verified correctly.
            throw new PaymentProtocolException.PkiVerificationException(e);
        } catch (SignatureException e) {
            // Something went wrong during hashing (yes, despite the name, this does not mean the sig was invalid).
            throw new PaymentProtocolException.PkiVerificationException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Information about the X.509 signature's issuer and subject.
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
                                    TrustAnchor rootAuthority) throws PaymentProtocolException.PkiVerificationException {
            try {
                this.displayName = displayName;
                this.merchantSigningKey = merchantSigningKey;
                this.rootAuthority = rootAuthority;
                this.rootAuthorityName = X509Utils.getDisplayNameFromCertificate(rootAuthority.getTrustedCert(), true);
            } catch (CertificateParsingException x) {
                throw new PaymentProtocolException.PkiVerificationException(x);
            }
        }

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("displayName", displayName)
                    .add("rootAuthorityName", rootAuthorityName)
                    .add("merchantSigningKey", merchantSigningKey)
                    .add("rootAuthority", rootAuthority)
                    .toString();
        }
    }

    /**
     * Create a payment message with one standard pay to address output.
     * 
     * @param transactions one or more transactions that satisfy the requested outputs.
     * @param refundAmount amount of coins to request as a refund, or null if no refund.
     * @param refundAddress address to refund coins to
     * @param memo arbitrary, user readable memo, or null if none
     * @param merchantData arbitrary merchant data, or null if none
     * @return created payment message
     */
    public static Protos.Payment createPaymentMessage(List<Transaction> transactions,
            @Nullable Coin refundAmount, @Nullable Address refundAddress, @Nullable String memo,
            @Nullable byte[] merchantData) {
        if (refundAddress != null) {
            if (refundAmount == null)
                throw new IllegalArgumentException("Specify refund amount if refund address is specified.");
            return createPaymentMessage(transactions,
                    ImmutableList.of(createPayToAddressOutput(refundAmount, refundAddress)), memo, merchantData);
        } else {
            return createPaymentMessage(transactions, null, memo, merchantData);
        }
    }

    /**
     * Create a payment message. This wraps up transaction data along with anything else useful for making a payment.
     * 
     * @param transactions transactions to include with the payment message
     * @param refundOutputs list of outputs to refund coins to, or null
     * @param memo arbitrary, user readable memo, or null if none
     * @param merchantData arbitrary merchant data, or null if none
     * @return created payment message
     */
    public static Protos.Payment createPaymentMessage(List<Transaction> transactions,
            @Nullable List<Protos.Output> refundOutputs, @Nullable String memo, @Nullable byte[] merchantData) {
        Protos.Payment.Builder builder = Protos.Payment.newBuilder();
        for (Transaction transaction : transactions) {
            transaction.verify();
            builder.addTransactions(ByteString.copyFrom(transaction.unsafeBitcoinSerialize()));
        }
        if (refundOutputs != null) {
            for (Protos.Output output : refundOutputs)
                builder.addRefundTo(output);
        }
        if (memo != null)
            builder.setMemo(memo);
        if (merchantData != null)
            builder.setMerchantData(ByteString.copyFrom(merchantData));
        return builder.build();
    }

    /**
     * Parse transactions from payment message.
     * 
     * @param params network parameters (needed for transaction deserialization)
     * @param paymentMessage payment message to parse
     * @return list of transactions
     */
    public static List<Transaction> parseTransactionsFromPaymentMessage(NetworkParameters params,
            Protos.Payment paymentMessage) {
        final List<Transaction> transactions = new ArrayList<Transaction>(paymentMessage.getTransactionsCount());
        for (final ByteString transaction : paymentMessage.getTransactionsList())
            transactions.add(params.getDefaultSerializer().makeTransaction(transaction.toByteArray()));
        return transactions;
    }

    /**
     * Message returned by the merchant in response to a Payment message.
     */
    public static class Ack {
        @Nullable private final String memo;

        Ack(@Nullable String memo) {
            this.memo = memo;
        }

        /**
         * Returns the memo included by the merchant in the payment ack. This message is typically displayed to the user
         * as a notification (e.g. "Your payment was received and is being processed"). If none was provided, returns
         * null.
         */
        @Nullable public String getMemo() {
            return memo;
        }
    }

    /**
     * Create a payment ack.
     * 
     * @param paymentMessage payment message to send with the ack
     * @param memo arbitrary, user readable memo, or null if none
     * @return created payment ack
     */
    public static Protos.PaymentACK createPaymentAck(Protos.Payment paymentMessage, @Nullable String memo) {
        final Protos.PaymentACK.Builder builder = Protos.PaymentACK.newBuilder();
        builder.setPayment(paymentMessage);
        if (memo != null)
            builder.setMemo(memo);
        return builder.build();
    }

    /**
     * Parse payment ack into an object.
     */
    public static Ack parsePaymentAck(Protos.PaymentACK paymentAck) {
        final String memo = paymentAck.hasMemo() ? paymentAck.getMemo() : null;
        return new Ack(memo);
    }

    /**
     * Create a standard pay to address output for usage in {@link #createPaymentRequest} and
     * {@link #createPaymentMessage}.
     * 
     * @param amount amount to pay, or null
     * @param address address to pay to
     * @return output
     */
    public static Protos.Output createPayToAddressOutput(@Nullable Coin amount, Address address) {
        Protos.Output.Builder output = Protos.Output.newBuilder();
        if (amount != null) {
            final NetworkParameters params = address.getParameters();
            if (params.hasMaxMoney() && amount.compareTo(params.getMaxMoney()) > 0)
                throw new IllegalArgumentException("Amount too big: " + amount);
            output.setAmount(amount.value);
        } else {
            output.setAmount(0);
        }
        output.setScript(ByteString.copyFrom(ScriptBuilder.createOutputScript(address).getProgram()));
        return output.build();
    }

    /**
     * Value object to hold amount/script pairs.
     */
    public static class Output implements Serializable {
        @Nullable public final Coin amount;
        public final byte[] scriptData;

        public Output(@Nullable Coin amount, byte[] scriptData) {
            this.amount = amount;
            this.scriptData = scriptData;
        }
    }
}
