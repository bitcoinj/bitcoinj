/**
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
import com.google.bitcoin.crypto.TrustStoreLoader;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.protocols.payments.PaymentProtocol.PkiVerificationData;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.uri.BitcoinURI;
import com.google.bitcoin.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.bitcoin.protocols.payments.Protos;

import javax.annotation.Nullable;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.KeyStoreException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * <p>Provides a standard implementation of the Payment Protocol (BIP 0070)</p>
 *
 * <p>A PaymentSession can be initialized from one of the following:</p>
 *
 * <ul>
 * <li>A {@link BitcoinURI} object that conforms to BIP 0072</li>
 * <li>A url where the {@link Protos.PaymentRequest} can be fetched</li>
 * <li>Directly with a {@link Protos.PaymentRequest} object</li>
 * </ul>
 *
 * <p>If initialized with a BitcoinURI or a url, a network request is made for the payment request object and a
 * ListenableFuture is returned that will be notified with the PaymentSession object after it is downloaded.</p>
 *
 * <p>Once the PaymentSession is initialized, typically a wallet application will prompt the user to confirm that the
 * amount and recipient are correct, perform any additional steps, and then construct a list of transactions to pass to
 * the sendPayment method.</p>
 *
 * <p>Call sendPayment with a list of transactions that will be broadcast. A {@link Protos.Payment} message will be sent
 * to the merchant if a payment url is provided in the PaymentRequest. NOTE: sendPayment does NOT broadcast the
 * transactions to the bitcoin network. Instead it returns a ListenableFuture that will be notified when a
 * {@link Protos.PaymentACK} is received from the merchant. Typically a wallet will show the message to the user
 * as a confirmation message that the payment is now "processing" or that an error occurred, and then broadcast the
 * tx itself later if needed.</p>
 *
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki">BIP 0070</a>
 */
public class PaymentSession {
    private static ListeningExecutorService executor = Threading.THREAD_POOL;
    private NetworkParameters params;
    private final TrustStoreLoader trustStoreLoader;
    private Protos.PaymentRequest paymentRequest;
    private Protos.PaymentDetails paymentDetails;
    private BigInteger totalValue = BigInteger.ZERO;

    /**
     * Stores the calculated PKI verification data, or null if none is available.
     * Only valid after the session is created with the verifyPki parameter set to true.
     */
    @Nullable public final PkiVerificationData pkiVerificationData;

    /**
     * Returns a future that will be notified with a PaymentSession object after it is fetched using the provided uri.
     * uri is a BIP-72-style BitcoinURI object that specifies where the {@link Protos.PaymentRequest} object may
     * be fetched in the r= parameter.
     * If the payment request object specifies a PKI method, then the system trust store will
     * be used to verify the signature provided by the payment request. An exception is thrown by the future if the
     * signature cannot be verified.
     */
    public static ListenableFuture<PaymentSession> createFromBitcoinUri(final BitcoinURI uri) throws PaymentRequestException {
        return createFromBitcoinUri(uri, true, null);
    }

    /**
     * Returns a future that will be notified with a PaymentSession object after it is fetched using the provided uri.
     * uri is a BIP-72-style BitcoinURI object that specifies where the {@link Protos.PaymentRequest} object may
     * be fetched in the r= parameter.
     * If verifyPki is specified and the payment request object specifies a PKI method, then the system trust store will
     * be used to verify the signature provided by the payment request. An exception is thrown by the future if the
     * signature cannot be verified.
     */
    public static ListenableFuture<PaymentSession> createFromBitcoinUri(final BitcoinURI uri, final boolean verifyPki)
            throws PaymentRequestException {
        return createFromBitcoinUri(uri, verifyPki, null);
    }

    /**
     * Returns a future that will be notified with a PaymentSession object after it is fetched using the provided uri.
     * uri is a BIP-72-style BitcoinURI object that specifies where the {@link Protos.PaymentRequest} object may
     * be fetched in the r= parameter.
     * If verifyPki is specified and the payment request object specifies a PKI method, then the system trust store will
     * be used to verify the signature provided by the payment request. An exception is thrown by the future if the
     * signature cannot be verified.
     * If trustStoreLoader is null, the system default trust store is used.
     */
    public static ListenableFuture<PaymentSession> createFromBitcoinUri(final BitcoinURI uri, final boolean verifyPki, @Nullable final TrustStoreLoader trustStoreLoader)
            throws PaymentRequestException {
        String url = uri.getPaymentRequestUrl();
        if (url == null)
            throw new PaymentRequestException.InvalidPaymentRequestURL("No payment request URL (r= parameter) in BitcoinURI " + uri);
        try {
            return fetchPaymentRequest(new URI(url), verifyPki, trustStoreLoader);
        } catch (URISyntaxException e) {
            throw new PaymentRequestException.InvalidPaymentRequestURL(e);
        }
    }

    /**
     * Returns a future that will be notified with a PaymentSession object after it is fetched using the provided url.
     * url is an address where the {@link Protos.PaymentRequest} object may be fetched.
     * If verifyPki is specified and the payment request object specifies a PKI method, then the system trust store will
     * be used to verify the signature provided by the payment request. An exception is thrown by the future if the
     * signature cannot be verified.
     */
    public static ListenableFuture<PaymentSession> createFromUrl(final String url) throws PaymentRequestException {
        return createFromUrl(url, true, null);
    }

    /**
     * Returns a future that will be notified with a PaymentSession object after it is fetched using the provided url.
     * url is an address where the {@link Protos.PaymentRequest} object may be fetched.
     * If the payment request object specifies a PKI method, then the system trust store will
     * be used to verify the signature provided by the payment request. An exception is thrown by the future if the
     * signature cannot be verified.
     */
    public static ListenableFuture<PaymentSession> createFromUrl(final String url, final boolean verifyPki)
            throws PaymentRequestException {
        return createFromUrl(url, verifyPki, null);
    }

    /**
     * Returns a future that will be notified with a PaymentSession object after it is fetched using the provided url.
     * url is an address where the {@link Protos.PaymentRequest} object may be fetched.
     * If the payment request object specifies a PKI method, then the system trust store will
     * be used to verify the signature provided by the payment request. An exception is thrown by the future if the
     * signature cannot be verified.
     * If trustStoreLoader is null, the system default trust store is used.
     */
    public static ListenableFuture<PaymentSession> createFromUrl(final String url, final boolean verifyPki, @Nullable final TrustStoreLoader trustStoreLoader)
            throws PaymentRequestException {
        if (url == null)
            throw new PaymentRequestException.InvalidPaymentRequestURL("null paymentRequestUrl");
        try {
            return fetchPaymentRequest(new URI(url), verifyPki, trustStoreLoader);
        } catch(URISyntaxException e) {
            throw new PaymentRequestException.InvalidPaymentRequestURL(e);
        }
    }

    private static ListenableFuture<PaymentSession> fetchPaymentRequest(final URI uri, final boolean verifyPki, @Nullable final TrustStoreLoader trustStoreLoader) {
        return executor.submit(new Callable<PaymentSession>() {
            @Override
            public PaymentSession call() throws Exception {
                HttpURLConnection connection = (HttpURLConnection)uri.toURL().openConnection();
                connection.setRequestProperty("Accept", PaymentProtocol.MIMETYPE_PAYMENTREQUEST);
                connection.setUseCaches(false);
                Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.parseFrom(connection.getInputStream());
                return new PaymentSession(paymentRequest, verifyPki, trustStoreLoader);
            }
        });
    }

    /**
     * Creates a PaymentSession from the provided {@link Protos.PaymentRequest}.
     * Verifies PKI by default.
     */
    public PaymentSession(Protos.PaymentRequest request) throws PaymentRequestException {
        this(request, true, null);
    }

    /**
     * Creates a PaymentSession from the provided {@link Protos.PaymentRequest}.
     * If verifyPki is true, also validates the signature and throws an exception if it fails.
     */
    public PaymentSession(Protos.PaymentRequest request, boolean verifyPki) throws PaymentRequestException {
        this(request, verifyPki, null);
    }

    /**
     * Creates a PaymentSession from the provided {@link Protos.PaymentRequest}.
     * If verifyPki is true, also validates the signature and throws an exception if it fails.
     * If trustStoreLoader is null, the system default trust store is used.
     */
    public PaymentSession(Protos.PaymentRequest request, boolean verifyPki, @Nullable final TrustStoreLoader trustStoreLoader) throws PaymentRequestException {
        this.trustStoreLoader = trustStoreLoader != null ? trustStoreLoader : new TrustStoreLoader.DefaultTrustStoreLoader();
        parsePaymentRequest(request);
        if (verifyPki) {
            try {
                pkiVerificationData = PaymentProtocol.verifyPaymentRequestPki(request, this.trustStoreLoader.getKeyStore());
            } catch (IOException x) {
                throw new PaymentRequestException(x);
            } catch (KeyStoreException x) {
                throw new PaymentRequestException(x);
            }
        } else {
            pkiVerificationData = null;
        }
    }

    /**
     * Message returned by the merchant in response to a Payment message.
     */
    public class Ack {
        @Nullable private String memo;

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
     * Returns the memo included by the merchant in the payment request, or null if not found.
     */
    @Nullable public String getMemo() {
        if (paymentDetails.hasMemo())
            return paymentDetails.getMemo();
        else
            return null;
    }

    /**
     * Returns the total amount of bitcoins requested.
     */
    public BigInteger getValue() {
        return totalValue;
    }

    /**
     * Returns the date that the payment request was generated.
     */
    public Date getDate() {
        return new Date(paymentDetails.getTime() * 1000);
    }

    /**
     * This should always be called before attempting to call sendPayment.
     */
    public boolean isExpired() {
        return paymentDetails.hasExpires() && System.currentTimeMillis() / 1000L > paymentDetails.getExpires();
    }

    /**
     * Returns the payment url where the Payment message should be sent.
     * Returns null if no payment url was provided in the PaymentRequest.
     */
    public @Nullable String getPaymentUrl() {
        if (paymentDetails.hasPaymentUrl())
            return paymentDetails.getPaymentUrl();
        return null;
    }

    /**
     * Returns a {@link Wallet.SendRequest} suitable for broadcasting to the network.
     */
    public Wallet.SendRequest getSendRequest() {
        Transaction tx = new Transaction(params);
        for (Protos.Output output : paymentDetails.getOutputsList())
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(output.getAmount()), output.getScript().toByteArray()));
        return Wallet.SendRequest.forTx(tx);
    }

    /**
     * Generates a Payment message and sends the payment to the merchant who sent the PaymentRequest.
     * Provide transactions built by the wallet.
     * NOTE: This does not broadcast the transactions to the bitcoin network, it merely sends a Payment message to the
     * merchant confirming the payment.
     * Returns an object wrapping PaymentACK once received.
     * If the PaymentRequest did not specify a payment_url, returns null and does nothing.
     * @param txns list of transactions to be included with the Payment message.
     * @param refundAddr will be used by the merchant to send money back if there was a problem.
     * @param memo is a message to include in the payment message sent to the merchant.
     */
    public @Nullable ListenableFuture<Ack> sendPayment(List<Transaction> txns, @Nullable Address refundAddr, @Nullable String memo)
            throws PaymentRequestException, VerificationException, IOException {
        Protos.Payment payment = getPayment(txns, refundAddr, memo);
        if (payment == null)
            return null;
        if (isExpired())
            throw new PaymentRequestException.Expired("PaymentRequest is expired");
        URL url;
        try {
            url = new URL(paymentDetails.getPaymentUrl());
        } catch (MalformedURLException e) {
            throw new PaymentRequestException.InvalidPaymentURL(e);
        }
        return sendPayment(url, payment);
    }

    /**
     * Generates a Payment message based on the information in the PaymentRequest.
     * Provide transactions built by the wallet.
     * If the PaymentRequest did not specify a payment_url, returns null.
     * @param txns list of transactions to be included with the Payment message.
     * @param refundAddr will be used by the merchant to send money back if there was a problem.
     * @param memo is a message to include in the payment message sent to the merchant.
     */
    public @Nullable Protos.Payment getPayment(List<Transaction> txns, @Nullable Address refundAddr, @Nullable String memo)
            throws IOException {
        if (!paymentDetails.hasPaymentUrl())
            return null;
        Protos.Payment.Builder payment = Protos.Payment.newBuilder();
        if (paymentDetails.hasMerchantData())
            payment.setMerchantData(paymentDetails.getMerchantData());
        if (refundAddr != null) {
            Protos.Output.Builder refundOutput = Protos.Output.newBuilder();
            refundOutput.setAmount(totalValue.longValue());
            refundOutput.setScript(ByteString.copyFrom(ScriptBuilder.createOutputScript(refundAddr).getProgram()));
            payment.addRefundTo(refundOutput);
        }
        if (memo != null) {
            payment.setMemo(memo);
        }
        for (Transaction txn : txns) {
            txn.verify();
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            txn.bitcoinSerialize(o);
            payment.addTransactions(ByteString.copyFrom(o.toByteArray()));
        }
        return payment.build();
    }

    @VisibleForTesting
    protected ListenableFuture<Ack> sendPayment(final URL url, final Protos.Payment payment) {
        return executor.submit(new Callable<Ack>() {
            @Override
            public Ack call() throws Exception {
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", PaymentProtocol.MIMETYPE_PAYMENT);
                connection.setRequestProperty("Accept", PaymentProtocol.MIMETYPE_PAYMENTACK);
                connection.setRequestProperty("Content-Length", Integer.toString(payment.getSerializedSize()));
                connection.setUseCaches(false);
                connection.setDoInput(true);
                connection.setDoOutput(true);

                // Send request.
                DataOutputStream outStream = new DataOutputStream(connection.getOutputStream());
                payment.writeTo(outStream);
                outStream.flush();
                outStream.close();

                // Get response.
                InputStream inStream = connection.getInputStream();
                Protos.PaymentACK.Builder paymentAckBuilder = Protos.PaymentACK.newBuilder().mergeFrom(inStream);
                Protos.PaymentACK paymentAck = paymentAckBuilder.build();
                String memo = null;
                if (paymentAck.hasMemo())
                    memo = paymentAck.getMemo();
                return new Ack(memo);
            }
        });
    }

    private void parsePaymentRequest(Protos.PaymentRequest request) throws PaymentRequestException {
        try {
            if (request == null)
                throw new PaymentRequestException("request cannot be null");
            if (request.getPaymentDetailsVersion() != 1)
                throw new PaymentRequestException.InvalidVersion("Version 1 required. Received version " + request.getPaymentDetailsVersion());
            paymentRequest = request;
            if (!request.hasSerializedPaymentDetails())
                throw new PaymentRequestException("No PaymentDetails");
            paymentDetails = Protos.PaymentDetails.newBuilder().mergeFrom(request.getSerializedPaymentDetails()).build();
            if (paymentDetails == null)
                throw new PaymentRequestException("Invalid PaymentDetails");
            if (!paymentDetails.hasNetwork())
                params = MainNetParams.get();
            else
                params = NetworkParameters.fromPmtProtocolID(paymentDetails.getNetwork());
            if (params == null)
                throw new PaymentRequestException.InvalidNetwork("Invalid network " + paymentDetails.getNetwork());
            if (paymentDetails.getOutputsCount() < 1)
                throw new PaymentRequestException.InvalidOutputs("No outputs");
            for (Protos.Output output : paymentDetails.getOutputsList()) {
                if (output.hasAmount())
                    totalValue = totalValue.add(BigInteger.valueOf(output.getAmount()));
            }
            // This won't ever happen in practice. It would only happen if the user provided outputs
            // that are obviously invalid. Still, we don't want to silently overflow.
            if (totalValue.compareTo(NetworkParameters.MAX_MONEY) > 0)
                throw new PaymentRequestException.InvalidOutputs("The outputs are way too big.");
        } catch (InvalidProtocolBufferException e) {
            throw new PaymentRequestException(e);
        }
    }

    /** Returns the value of pkiVerificationData or null if it wasn't verified at construction time. */
    @Nullable public PkiVerificationData verifyPki() {
        return pkiVerificationData;
    }

    /** Gets the params as read from the PaymentRequest.network field: main is the default if missing. */
    public NetworkParameters getNetworkParameters() {
        return params;
    }

    /** Returns the protobuf that this object was instantiated with. */
    public Protos.PaymentRequest getPaymentRequest() {
        return paymentRequest;
    }

    /** Returns the protobuf that describes the payment to be made. */
    public Protos.PaymentDetails getPaymentDetails() {
        return paymentDetails;
    }
}
