package com.google.bitcoin.protocols.channels;

import com.google.bitcoin.core.*;
import com.google.bitcoin.protocols.channels.PaymentChannelCloseException.CloseReason;
import com.google.bitcoin.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import net.jcip.annotations.GuardedBy;
import org.bitcoin.paymentchannel.Protos;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A class which handles most of the complexity of creating a payment channel connection by providing a
 * simple in/out interface which is provided with protobufs from the server and which generates protobufs which should
 * be sent to the server.</p>
 *
 * <p>Does all required verification of server messages and properly stores state objects in the wallet-attached
 * {@link StoredPaymentChannelClientStates} so that they are automatically closed when necessary and refund
 * transactions are not lost if the application crashes before it unlocks.</p>
 *
 * <p>Though this interface is largely designed with stateful protocols (eg simple TCP connections) in mind, it is also
 * possible to use it with stateless protocols (eg sending protobufs when required over HTTP headers). In this case, the
 * "connection" translates roughly into the server-client relationship. See the javadocs for specific functions for more
 * details.</p>
 */
public class PaymentChannelClient {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(PaymentChannelClient.class);

    protected final ReentrantLock lock = Threading.lock("channelclient");

    /**
     * Implements the connection between this client and the server, providing an interface which allows messages to be
     * sent to the server, requests for the connection to the server to be closed, and a callback which occurs when the
     * channel is fully open.
     */
    public interface ClientConnection {
        /**
         * <p>Requests that the given message be sent to the server. There are no blocking requirements for this method,
         * however the order of messages must be preserved.</p>
         *
         * <p>If the send fails, no exception should be thrown, however
         * {@link PaymentChannelClient#connectionClosed()} should be called immediately. In the case of messages which
         * are a part of initialization, initialization will simply fail and the refund transaction will be broadcasted
         * when it unlocks (if necessary).  In the case of a payment message, the payment will be lost however if the
         * channel is resumed it will begin again from the channel value <i>after</i> the failed payment.</p>
         *
         * <p>Called while holding a lock on the {@link PaymentChannelClient} object - be careful about reentrancy</p>
         */
        public void sendToServer(Protos.TwoWayChannelMessage msg);

        /**
         * <p>Requests that the connection to the server be closed. For stateless protocols, note that after this call,
         * no more messages should be received from the server and this object is no longer usable. A
         * {@link PaymentChannelClient#connectionClosed()} event should be generated immediately after this call.</p>
         *
         * <p>Called while holding a lock on the {@link PaymentChannelClient} object - be careful about reentrancy</p>
         *
         * @param reason The reason for the closure, see the individual values for more details.
         *               It is usually safe to ignore this and treat any value below
         *               {@link CloseReason#CLIENT_REQUESTED_CLOSE} as "unrecoverable error" and all others as
         *               "try again once and see if it works then"
         */
        public void destroyConnection(CloseReason reason);

        /**
         * <p>Indicates the channel has been successfully opened and
         * {@link PaymentChannelClient#incrementPayment(java.math.BigInteger)} may be called at will.</p>
         *
         * <p>Called while holding a lock on the {@link PaymentChannelClient} object - be careful about reentrancy</p>
         */
        public void channelOpen();
    }
    @GuardedBy("lock") private final ClientConnection conn;

    // Used to keep track of whether or not the "socket" ie connection is open and we can generate messages
    @VisibleForTesting @GuardedBy("lock") boolean connectionOpen = false;

    // The state object used to step through initialization and pay the server
    @GuardedBy("lock") private PaymentChannelClientState state;

    // The step we are at in initialization, this is partially duplicated in the state object
    private enum InitStep {
        WAITING_FOR_CONNECTION_OPEN,
        WAITING_FOR_VERSION_NEGOTIATION,
        WAITING_FOR_INITIATE,
        WAITING_FOR_REFUND_RETURN,
        WAITING_FOR_CHANNEL_OPEN,
        CHANNEL_OPEN
    }
    @GuardedBy("lock") private InitStep step = InitStep.WAITING_FOR_CONNECTION_OPEN;

    // Will either hold the StoredClientChannel of this channel or null after connectionOpen
    private StoredClientChannel storedChannel;
    // An arbitrary hash which identifies this channel (specified by the API user)
    private final Sha256Hash serverId;

    // The wallet associated with this channel
    private final Wallet wallet;

    // Information used during channel initialization to send to the server or check what the server sends to us
    private final ECKey myKey;
    private final BigInteger maxValue;

    /**
     * <p>The maximum amount of time for which we will accept the server locking up our funds for the multisig
     * contract.</p>
     *
     * <p>Note that though this is not final, it is in all caps because it should generally not be modified unless you
     * have some guarantee that the server will not request at least this (channels will fail if this is too small).</p>
     *
     * <p>24 hours is the default as it is expected that clients limit risk exposure by limiting channel size instead of
     * limiting lock time when dealing with potentially malicious servers.</p>
     */
    public long MAX_TIME_WINDOW = 24*60*60;

    /**
     * Constructs a new channel manager which waits for {@link PaymentChannelClient#connectionOpen()} before acting.
     *
     * @param wallet The wallet which will be paid from, and where completed transactions will be committed.
     *               Must already have a {@link StoredPaymentChannelClientStates} object in its extensions set.
     * @param myKey A freshly generated keypair used for the multisig contract and refund output.
     * @param maxValue The maximum value the server is allowed to request that we lock into this channel until the
     *                 refund transaction unlocks. Note that if there is a previously open channel, the refund
     *                 transaction used in this channel may be larger than maxValue. Thus, maxValue is not a method for
     *                 limiting the amount payable through this channel.
     * @param serverId An arbitrary hash representing this channel. This must uniquely identify the server. If an
     *                 existing stored channel exists in the wallet's {@link StoredPaymentChannelClientStates}, then an
     *                 attempt will be made to resume that channel.
     * @param conn A callback listener which represents the connection to the server (forwards messages we generate to
     *             the server)
     */
    public PaymentChannelClient(Wallet wallet, ECKey myKey, BigInteger maxValue, Sha256Hash serverId, ClientConnection conn) {
        this.wallet = checkNotNull(wallet);
        this.myKey = checkNotNull(myKey);
        this.maxValue = checkNotNull(maxValue);
        this.serverId = checkNotNull(serverId);
        this.conn = checkNotNull(conn);
    }

    @GuardedBy("lock")
    private void receiveInitiate(Protos.Initiate initiate, BigInteger contractValue) throws VerificationException, ValueOutOfRangeException {
        log.info("Got INITIATE message, providing refund transaction");

        state = new PaymentChannelClientState(wallet, myKey,
                new ECKey(null, initiate.getMultisigKey().toByteArray()),
                contractValue, initiate.getExpireTimeSecs());
        state.initiate();
        step = InitStep.WAITING_FOR_REFUND_RETURN;

        Protos.ProvideRefund.Builder provideRefundBuilder = Protos.ProvideRefund.newBuilder()
                .setMultisigKey(ByteString.copyFrom(myKey.getPubKey()))
                .setTx(ByteString.copyFrom(state.getIncompleteRefundTransaction().bitcoinSerialize()));

        conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                .setProvideRefund(provideRefundBuilder)
                .setType(Protos.TwoWayChannelMessage.MessageType.PROVIDE_REFUND)
                .build());
    }

    @GuardedBy("lock")
    private void receiveRefund(Protos.TwoWayChannelMessage msg) throws VerificationException {
        checkState(step == InitStep.WAITING_FOR_REFUND_RETURN && msg.hasReturnRefund());
        log.info("Got RETURN_REFUND message, providing signed contract");
        Protos.ReturnRefund returnedRefund = msg.getReturnRefund();
        state.provideRefundSignature(returnedRefund.getSignature().toByteArray());
        step = InitStep.WAITING_FOR_CHANNEL_OPEN;

        // Before we can send the server the contract (ie send it to the network), we must ensure that our refund
        // transaction is safely in the wallet - thus we store it (this also keeps it up-to-date when we pay)
        state.storeChannelInWallet(serverId);

        Protos.ProvideContract.Builder provideContractBuilder = Protos.ProvideContract.newBuilder()
                .setTx(ByteString.copyFrom(state.getMultisigContract().bitcoinSerialize()));

        conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                .setProvideContract(provideContractBuilder)
                .setType(Protos.TwoWayChannelMessage.MessageType.PROVIDE_CONTRACT)
                .build());
    }

    @GuardedBy("lock")
    private void receiveChannelOpen() throws VerificationException {
        checkState(step == InitStep.WAITING_FOR_CHANNEL_OPEN || (step == InitStep.WAITING_FOR_INITIATE && storedChannel != null), step);
        log.info("Got CHANNEL_OPEN message, ready to pay");

        if (step == InitStep.WAITING_FOR_INITIATE)
            state = new PaymentChannelClientState(storedChannel, wallet);
        step = InitStep.CHANNEL_OPEN;
        // channelOpen should disable timeouts, but
        // TODO accomodate high latency between PROVIDE_CONTRACT and here
        conn.channelOpen();
    }

    /**
     * Called when a message is received from the server. Processes the given message and generates events based on its
     * content.
     */
    public void receiveMessage(Protos.TwoWayChannelMessage msg) {
        lock.lock();
        try {
            checkState(connectionOpen);
            // If we generate an error, we set errorBuilder and closeReason and break, otherwise we return
            Protos.Error.Builder errorBuilder;
            CloseReason closeReason;
            try {
                switch (msg.getType()) {
                    case SERVER_VERSION:
                        checkState(step == InitStep.WAITING_FOR_VERSION_NEGOTIATION && msg.hasServerVersion());
                        // Server might send back a major version lower than our own if they want to fallback to a lower version
                        // We can't handle that, so we just close the channel
                        if (msg.getServerVersion().getMajor() != 0) {
                            errorBuilder = Protos.Error.newBuilder()
                                    .setCode(Protos.Error.ErrorCode.NO_ACCEPTABLE_VERSION);
                            closeReason = CloseReason.NO_ACCEPTABLE_VERSION;
                            break;
                        }
                        log.info("Got version handshake, awaiting INITIATE or resume CHANNEL_OPEN");
                        step = InitStep.WAITING_FOR_INITIATE;
                        return;
                    case INITIATE:
                        checkState(step == InitStep.WAITING_FOR_INITIATE && msg.hasInitiate());

                        Protos.Initiate initiate = msg.getInitiate();
                        checkState(initiate.getExpireTimeSecs() > 0 && initiate.getMinAcceptedChannelSize() >= 0);

                        if (initiate.getExpireTimeSecs() > Utils.now().getTime()/1000 + MAX_TIME_WINDOW) {
                            errorBuilder = Protos.Error.newBuilder()
                                    .setCode(Protos.Error.ErrorCode.TIME_WINDOW_TOO_LARGE);
                            closeReason = CloseReason.TIME_WINDOW_TOO_LARGE;
                            break;
                        }

                        BigInteger minChannelSize = BigInteger.valueOf(initiate.getMinAcceptedChannelSize());
                        if (maxValue.compareTo(minChannelSize) < 0) {
                            errorBuilder = Protos.Error.newBuilder()
                                    .setCode(Protos.Error.ErrorCode.CHANNEL_VALUE_TOO_LARGE);
                            closeReason = CloseReason.SERVER_REQUESTED_TOO_MUCH_VALUE;
                            break;
                        }

                        receiveInitiate(initiate, maxValue);
                        return;
                    case RETURN_REFUND:
                        receiveRefund(msg);
                        return;
                    case CHANNEL_OPEN:
                        receiveChannelOpen();
                        return;
                    case CLOSE:
                        conn.destroyConnection(CloseReason.SERVER_REQUESTED_CLOSE);
                        return;
                    case ERROR:
                        checkState(msg.hasError());
                        log.error("Server sent ERROR {} with explanation {}", msg.getError().getCode().name(),
                                msg.getError().hasExplanation() ? msg.getError().getExplanation() : "");
                        conn.destroyConnection(CloseReason.REMOTE_SENT_ERROR);
                        return;
                    default:
                        log.error("Got unknown message type or type that doesn't apply to clients.");
                        errorBuilder = Protos.Error.newBuilder()
                                .setCode(Protos.Error.ErrorCode.SYNTAX_ERROR);
                        closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
                        break;
                }
            } catch (VerificationException e) {
                log.error("Caught verification exception handling message from server", e);
                errorBuilder = Protos.Error.newBuilder()
                        .setCode(Protos.Error.ErrorCode.BAD_TRANSACTION)
                        .setExplanation(e.getMessage());
                closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
            } catch (ValueOutOfRangeException e) {
                log.error("Caught value out of range exception handling message from server", e);
                errorBuilder = Protos.Error.newBuilder()
                        .setCode(Protos.Error.ErrorCode.BAD_TRANSACTION)
                        .setExplanation(e.getMessage());
                closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
            } catch (IllegalStateException e) {
                log.error("Caught illegal state exception handling message from server", e);
                errorBuilder = Protos.Error.newBuilder()
                        .setCode(Protos.Error.ErrorCode.SYNTAX_ERROR);
                closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
            }
            conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                    .setError(errorBuilder)
                    .setType(Protos.TwoWayChannelMessage.MessageType.ERROR)
                    .build());
            conn.destroyConnection(closeReason);
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Called when the connection terminates. Notifies the {@link StoredClientChannel} object that we can attempt to
     * resume this channel in the future and stops generating messages for the server.</p>
     *
     * <p>For stateless protocols, this translates to a client not using the channel for the immediate future, but
     * intending to reopen the channel later. There is likely little reason to use this in a stateless protocol.</p>
     *
     * <p>Note that this <b>MUST</b> still be called even after either
     * {@link ClientConnection#destroyConnection(CloseReason)} or
     * {@link PaymentChannelClient#close()} is called to actually handle the connection close logic.</p>
     */
    public void connectionClosed() {
        lock.lock();
        try {
            connectionOpen = false;
            if (state != null)
                state.disconnectFromChannel();
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Closes the connection, notifying the server it should close the channel by broadcasting the most recent payment
     * transaction.</p>
     *
     * <p>Note that this only generates a CLOSE message for the server and calls
     * {@link ClientConnection#destroyConnection(CloseReason)} to close the connection, it does not
     * actually handle connection close logic, and {@link PaymentChannelClient#connectionClosed()} must still be called
     * after the connection fully closes.</p>
     *
     * @throws IllegalStateException If the connection is not currently open (ie the CLOSE message cannot be sent)
     */
    public void close() throws IllegalStateException {
        lock.lock();
        try {
            checkState(connectionOpen);
            conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                    .setType(Protos.TwoWayChannelMessage.MessageType.CLOSE)
                    .build());
            conn.destroyConnection(CloseReason.CLIENT_REQUESTED_CLOSE);
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Called to indicate the connection has been opened and messages can now be generated for the server.</p>
     *
     * <p>Attempts to find a channel to resume and generates a CLIENT_VERSION message for the server based on the
     * result.</p>
     */
    public void connectionOpen() {
        lock.lock();
        try {
            connectionOpen = true;

            StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates) wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
            if (channels != null)
                storedChannel = channels.getUsableChannelForServerID(serverId);

            step = InitStep.WAITING_FOR_VERSION_NEGOTIATION;

            Protos.ClientVersion.Builder versionNegotiationBuilder = Protos.ClientVersion.newBuilder()
                    .setMajor(0).setMinor(1);

            if (storedChannel != null) {
                versionNegotiationBuilder.setPreviousChannelContractHash(ByteString.copyFrom(storedChannel.contract.getHash().getBytes()));
                log.info("Begun version handshake, attempting to reopen channel with contract hash {}", storedChannel.contract.getHash());
            } else
                log.info("Begun version handshake creating new channel");

            conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                    .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                    .setClientVersion(versionNegotiationBuilder)
                    .build());
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Gets the {@link PaymentChannelClientState} object which stores the current state of the connection with the
     * server.</p>
     *
     * <p>Note that if you call any methods which update state directly the server will not be notified and channel
     * initialization logic in the connection may fail unexpectedly.</p>
     */
    public PaymentChannelClientState state() {
        lock.lock();
        try {
            return state;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Increments the total value which we pay the server.
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @throws ValueOutOfRangeException If the size is negative or would pay more than this channel's total value
     *                                  ({@link PaymentChannelClientConnection#state()}.getTotalValue())
     * @throws IllegalStateException If the channel has been closed or is not yet open
     *                               (see {@link PaymentChannelClientConnection#getChannelOpenFuture()} for the second)
     */
    public void incrementPayment(BigInteger size) throws ValueOutOfRangeException, IllegalStateException {
        lock.lock();
        try {
            if (state() == null || !connectionOpen || step != InitStep.CHANNEL_OPEN)
                throw new IllegalStateException("Channel is not fully initialized/has already been closed");

            byte[] signature = state().incrementPaymentBy(size);
            Protos.UpdatePayment.Builder updatePaymentBuilder = Protos.UpdatePayment.newBuilder()
                    .setSignature(ByteString.copyFrom(signature))
                    .setClientChangeValue(state.getValueRefunded().longValue());

            conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                    .setUpdatePayment(updatePaymentBuilder)
                    .setType(Protos.TwoWayChannelMessage.MessageType.UPDATE_PAYMENT)
                    .build());
        } finally {
            lock.unlock();
        }
    }
}
