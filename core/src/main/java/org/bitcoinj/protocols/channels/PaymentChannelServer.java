/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.*;
import org.bitcoinj.protocols.channels.PaymentChannelCloseException.CloseReason;
import org.bitcoinj.utils.Threading;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import net.jcip.annotations.GuardedBy;
import org.bitcoin.paymentchannel.Protos;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A handler class which handles most of the complexity of creating a payment channel connection by providing a
 * simple in/out interface which is provided with protobufs from the client and which generates protobufs which should
 * be sent to the client.</p>
 *
 * <p>Does all required verification of messages and properly stores state objects in the wallet-attached
 * {@link StoredPaymentChannelServerStates} so that they are automatically closed when necessary and payment
 * transactions are not lost if the application crashes before it unlocks.</p>
 */
public class PaymentChannelServer {
    //TODO: Update JavaDocs with notes for communication over stateless protocols
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(PaymentChannelServer.class);

    protected final ReentrantLock lock = Threading.lock("channelserver");
    public final int SERVER_MAJOR_VERSION = 1;
    public final int SERVER_MINOR_VERSION = 0;

    // The step in the initialization process we are in, some of this is duplicated in the PaymentChannelServerState
    private enum InitStep {
        WAITING_ON_CLIENT_VERSION,
        WAITING_ON_UNSIGNED_REFUND,
        WAITING_ON_CONTRACT,
        WAITING_ON_MULTISIG_ACCEPTANCE,
        CHANNEL_OPEN
    }
    @GuardedBy("lock") private InitStep step = InitStep.WAITING_ON_CLIENT_VERSION;

    /**
     * Implements the connection between this server and the client, providing an interface which allows messages to be
     * sent to the client, requests for the connection to the client to be closed, and callbacks which occur when the
     * channel is fully open or the client completes a payment.
     */
    public interface ServerConnection {
        /**
         * <p>Requests that the given message be sent to the client. There are no blocking requirements for this method,
         * however the order of messages must be preserved.</p>
         *
         * <p>If the send fails, no exception should be thrown, however
         * {@link PaymentChannelServer#connectionClosed()} should be called immediately.</p>
         *
         * <p>Called while holding a lock on the {@link PaymentChannelServer} object - be careful about reentrancy</p>
         */
        public void sendToClient(Protos.TwoWayChannelMessage msg);

        /**
         * <p>Requests that the connection to the client be closed</p>
         *
         * <p>Called while holding a lock on the {@link PaymentChannelServer} object - be careful about reentrancy</p>
         *
         * @param reason The reason for the closure, see the individual values for more details.
         *               It is usually safe to ignore this value.
         */
        public void destroyConnection(CloseReason reason);

        /**
         * <p>Triggered when the channel is opened and payments can begin</p>
         *
         * <p>Called while holding a lock on the {@link PaymentChannelServer} object - be careful about reentrancy</p>
         *
         * @param contractHash A unique identifier which represents this channel (actually the hash of the multisig contract)
         */
        public void channelOpen(Sha256Hash contractHash);

        /**
         * <p>Called when the payment in this channel was successfully incremented by the client</p>
         *
         * <p>Called while holding a lock on the {@link PaymentChannelServer} object - be careful about reentrancy</p>
         *
         * @param by The increase in total payment
         * @param to The new total payment to us (not including fees which may be required to claim the payment)
         * @param info Information about this payment increase, used to extend this protocol.
         * @return A future that completes with the ack message that will be included in the PaymentAck message to the client. Use null for no ack message.
         */
        @Nullable
        public ListenableFuture<ByteString> paymentIncrease(Coin by, Coin to, @Nullable ByteString info);
    }
    private final ServerConnection conn;

    // Used to keep track of whether or not the "socket" ie connection is open and we can generate messages
    @GuardedBy("lock") private boolean connectionOpen = false;
    // Indicates that no further messages should be sent and we intend to settle the connection
    @GuardedBy("lock") private boolean channelSettling = false;

    // The wallet and peergroup which are used to complete/broadcast transactions
    private final Wallet wallet;
    private final TransactionBroadcaster broadcaster;

    // The key used for multisig in this channel
    @GuardedBy("lock") private ECKey myKey;

    // The minimum accepted channel value
    private final Coin minAcceptedChannelSize;

    // The state manager for this channel
    @GuardedBy("lock") private PaymentChannelServerState state;

    // The time this channel expires (ie the refund transaction's locktime)
    @GuardedBy("lock") private long expireTime;

    public static final long DEFAULT_MAX_TIME_WINDOW = 7 * 24 * 60 * 60;

    /**
     * Maximum channel duration, in seconds, that the client can request. Defaults to 1 week.
     * Note that the server needs to be online for the whole time the channel is open.
     * Failure to do this could cause loss of all payments received on the channel.
     */
    protected final long maxTimeWindow;

    public static final long DEFAULT_MIN_TIME_WINDOW = 4 * 60 * 60;
    public static final long HARD_MIN_TIME_WINDOW = -StoredPaymentChannelServerStates.CHANNEL_EXPIRE_OFFSET;
    /**
     * Minimum channel duration, in seconds, that the client can request. Should always be larger than  than 2 hours, defaults to 4 hours
     */
    protected final long minTimeWindow;

    /**
     * Creates a new server-side state manager which handles a single client connection. The server will only accept
     * a channel with time window between 4 hours and 1 week. Note that the server need to be online for the whole time the channel is open.
     * Failure to do this could cause loss of all payments received on the channel.
     *
     * @param broadcaster The PeerGroup on which transactions will be broadcast - should have multiple connections.
     * @param wallet The wallet which will be used to complete transactions.
     *               Unlike {@link PaymentChannelClient}, this does not have to already contain a StoredState manager
     * @param minAcceptedChannelSize The minimum value the client must lock into this channel. A value too large will be
     *                               rejected by clients, and a value too low will require excessive channel reopening
     *                               and may cause fees to be require to settle the channel. A reasonable value depends
     *                               entirely on the expected maximum for the channel, and should likely be somewhere
     *                               between a few bitcents and a bitcoin.
     * @param conn A callback listener which represents the connection to the client (forwards messages we generate to
     *             the client and will close the connection on request)
     */
    public PaymentChannelServer(TransactionBroadcaster broadcaster, Wallet wallet,
                                Coin minAcceptedChannelSize, ServerConnection conn) {
        this(broadcaster, wallet, minAcceptedChannelSize, DEFAULT_MIN_TIME_WINDOW, DEFAULT_MAX_TIME_WINDOW, conn);
    }

    /**
     * Creates a new server-side state manager which handles a single client connection.
     *
     * @param broadcaster The PeerGroup on which transactions will be broadcast - should have multiple connections.
     * @param wallet The wallet which will be used to complete transactions.
     *               Unlike {@link PaymentChannelClient}, this does not have to already contain a StoredState manager
     * @param minAcceptedChannelSize The minimum value the client must lock into this channel. A value too large will be
     *                               rejected by clients, and a value too low will require excessive channel reopening
     *                               and may cause fees to be require to settle the channel. A reasonable value depends
     *                               entirely on the expected maximum for the channel, and should likely be somewhere
     *                               between a few bitcents and a bitcoin.
     * @param minTimeWindow The minimum allowed channel time window in seconds, must be larger than 7200.
     * @param maxTimeWindow The maximum allowed channel time window in seconds. Note that the server need to be online for the whole time the channel is open.
     *                              Failure to do this could cause loss of all payments received on the channel.
     * @param conn A callback listener which represents the connection to the client (forwards messages we generate to
     *              the client and will close the connection on request)
     */
    public PaymentChannelServer(TransactionBroadcaster broadcaster, Wallet wallet,
                                Coin minAcceptedChannelSize, long minTimeWindow, long maxTimeWindow, ServerConnection conn) {
        if (minTimeWindow > maxTimeWindow) throw new IllegalArgumentException("minTimeWindow must be less or equal to maxTimeWindow");
        if (minTimeWindow < HARD_MIN_TIME_WINDOW) throw new IllegalArgumentException("minTimeWindow must be larger than" + HARD_MIN_TIME_WINDOW  + " seconds");
        this.broadcaster = checkNotNull(broadcaster);
        this.wallet = checkNotNull(wallet);
        this.minAcceptedChannelSize = checkNotNull(minAcceptedChannelSize);
        this.conn = checkNotNull(conn);
        this.minTimeWindow = minTimeWindow;
        this.maxTimeWindow = maxTimeWindow;
    }

    /**
     * Returns the underlying {@link PaymentChannelServerState} object that is being manipulated. This object allows
     * you to learn how much money has been transferred, etc. May be null if the channel wasn't negotiated yet.
     */
    @Nullable
    public PaymentChannelServerState state() {
        return state;
    }

    @GuardedBy("lock")
    private void receiveVersionMessage(Protos.TwoWayChannelMessage msg) throws VerificationException {
        checkState(step == InitStep.WAITING_ON_CLIENT_VERSION && msg.hasClientVersion());
        final Protos.ClientVersion clientVersion = msg.getClientVersion();
        final int major = clientVersion.getMajor();
        if (major != SERVER_MAJOR_VERSION) {
            error("This server needs protocol version " + SERVER_MAJOR_VERSION + " , client offered " + major,
                    Protos.Error.ErrorCode.NO_ACCEPTABLE_VERSION, CloseReason.NO_ACCEPTABLE_VERSION);
            return;
        }

        Protos.ServerVersion.Builder versionNegotiationBuilder = Protos.ServerVersion.newBuilder()
                .setMajor(SERVER_MAJOR_VERSION).setMinor(SERVER_MINOR_VERSION);
        conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION)
                .setServerVersion(versionNegotiationBuilder)
                .build());
        ByteString reopenChannelContractHash = clientVersion.getPreviousChannelContractHash();
        if (reopenChannelContractHash != null && reopenChannelContractHash.size() == 32) {
            Sha256Hash contractHash = new Sha256Hash(reopenChannelContractHash.toByteArray());
            log.info("New client that wants to resume {}", contractHash);
            StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                    wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
            if (channels != null) {
                StoredServerChannel storedServerChannel = channels.getChannel(contractHash);
                if (storedServerChannel != null) {
                    final PaymentChannelServer existingHandler = storedServerChannel.setConnectedHandler(this, false);
                    if (existingHandler != this) {
                        log.warn("  ... and that channel is already in use, disconnecting other user.");
                        existingHandler.close();
                        storedServerChannel.setConnectedHandler(this, true);
                    }

                    log.info("Got resume version message, responding with VERSIONS and CHANNEL_OPEN");
                    state = storedServerChannel.getOrCreateState(wallet, broadcaster);
                    step = InitStep.CHANNEL_OPEN;
                    conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                            .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN)
                            .build());
                    conn.channelOpen(contractHash);
                    return;
                } else {
                    log.error(" ... but we do not have any record of that contract! Resume failed.");
                }
            } else {
                log.error(" ... but we do not have any stored channels! Resume failed.");
            }
        }
        log.info("Got initial version message, responding with VERSIONS and INITIATE: min value={}",
                minAcceptedChannelSize.value);

        myKey = new ECKey();
        wallet.freshReceiveKey();

        expireTime = Utils.currentTimeSeconds() + truncateTimeWindow(clientVersion.getTimeWindowSecs());
        step = InitStep.WAITING_ON_UNSIGNED_REFUND;

        Protos.Initiate.Builder initiateBuilder = Protos.Initiate.newBuilder()
                .setMultisigKey(ByteString.copyFrom(myKey.getPubKey()))
                .setExpireTimeSecs(expireTime)
                .setMinAcceptedChannelSize(minAcceptedChannelSize.value)
                .setMinPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.value);

        conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                .setInitiate(initiateBuilder)
                .setType(Protos.TwoWayChannelMessage.MessageType.INITIATE)
                .build());
    }

    private long truncateTimeWindow(long timeWindow) {
        if (timeWindow < minTimeWindow) {
            log.info("client requested time window {} s to short, offering {} s", timeWindow, minTimeWindow);
            return minTimeWindow;
        }
        if (timeWindow > maxTimeWindow) {
            log.info("client requested time window {} s to long, offering {} s", timeWindow, minTimeWindow);
            return maxTimeWindow;
        }
        return timeWindow;
    }

    @GuardedBy("lock")
    private void receiveRefundMessage(Protos.TwoWayChannelMessage msg) throws VerificationException {
        checkState(step == InitStep.WAITING_ON_UNSIGNED_REFUND && msg.hasProvideRefund());
        log.info("Got refund transaction, returning signature");

        Protos.ProvideRefund providedRefund = msg.getProvideRefund();
        state = new PaymentChannelServerState(broadcaster, wallet, myKey, expireTime);
        byte[] signature = state.provideRefundTransaction(new Transaction(wallet.getParams(), providedRefund.getTx().toByteArray()),
                providedRefund.getMultisigKey().toByteArray());

        step = InitStep.WAITING_ON_CONTRACT;

        Protos.ReturnRefund.Builder returnRefundBuilder = Protos.ReturnRefund.newBuilder()
                .setSignature(ByteString.copyFrom(signature));

        conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                .setReturnRefund(returnRefundBuilder)
                .setType(Protos.TwoWayChannelMessage.MessageType.RETURN_REFUND)
                .build());
    }

    private void multisigContractPropogated(Protos.ProvideContract providedContract, Sha256Hash contractHash) {
        lock.lock();
        try {
            if (!connectionOpen || channelSettling)
                return;
            state.storeChannelInWallet(PaymentChannelServer.this);
            try {
                receiveUpdatePaymentMessage(providedContract.getInitialPayment(), false /* no ack msg */);
            } catch (VerificationException e) {
                log.error("Initial payment failed to verify", e);
                error(e.getMessage(), Protos.Error.ErrorCode.BAD_TRANSACTION, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
                return;
            } catch (ValueOutOfRangeException e) {
                log.error("Initial payment value was out of range", e);
                error(e.getMessage(), Protos.Error.ErrorCode.BAD_TRANSACTION, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
                return;
            } catch (InsufficientMoneyException e) {
                // This shouldn't happen because the server shouldn't allow itself to get into this situation in the
                // first place, by specifying a min up front payment.
                log.error("Tried to settle channel and could not afford the fees whilst updating payment", e);
                error(e.getMessage(), Protos.Error.ErrorCode.BAD_TRANSACTION, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
                return;
            }
            conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                    .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN)
                    .build());
            step = InitStep.CHANNEL_OPEN;
            conn.channelOpen(contractHash);
        } finally {
            lock.unlock();
        }
    }

    @GuardedBy("lock")
    private void receiveContractMessage(Protos.TwoWayChannelMessage msg) throws VerificationException {
        checkState(step == InitStep.WAITING_ON_CONTRACT && msg.hasProvideContract());
        log.info("Got contract, broadcasting and responding with CHANNEL_OPEN");
        final Protos.ProvideContract providedContract = msg.getProvideContract();

        //TODO notify connection handler that timeout should be significantly extended as we wait for network propagation?
        final Transaction multisigContract = new Transaction(wallet.getParams(), providedContract.getTx().toByteArray());
        step = InitStep.WAITING_ON_MULTISIG_ACCEPTANCE;
        state.provideMultiSigContract(multisigContract)
                .addListener(new Runnable() {
                    @Override
                    public void run() {
                        multisigContractPropogated(providedContract, multisigContract.getHash());
                    }
                }, Threading.SAME_THREAD);
    }

    @GuardedBy("lock")
    private void receiveUpdatePaymentMessage(Protos.UpdatePayment msg, boolean sendAck) throws VerificationException, ValueOutOfRangeException, InsufficientMoneyException {
        log.info("Got a payment update");

        Coin lastBestPayment = state.getBestValueToMe();
        final Coin refundSize = Coin.valueOf(msg.getClientChangeValue());
        boolean stillUsable = state.incrementPayment(refundSize, msg.getSignature().toByteArray());
        Coin bestPaymentChange = state.getBestValueToMe().subtract(lastBestPayment);

        ListenableFuture<ByteString> ackInfoFuture = null;
        if (bestPaymentChange.signum() > 0) {
            ByteString info = (msg.hasInfo()) ? msg.getInfo() : null;
            ackInfoFuture = conn.paymentIncrease(bestPaymentChange, state.getBestValueToMe(), info);
        }

        if (sendAck) {
            final Protos.TwoWayChannelMessage.Builder ack = Protos.TwoWayChannelMessage.newBuilder();
            ack.setType(Protos.TwoWayChannelMessage.MessageType.PAYMENT_ACK);
            if (ackInfoFuture == null) {
                conn.sendToClient(ack.build());
            } else {
                Futures.addCallback(ackInfoFuture, new FutureCallback<ByteString>() {
                    @Override
                    public void onSuccess(@Nullable ByteString result) {
                        if (result != null) ack.setPaymentAck(ack.getPaymentAckBuilder().setInfo(result));
                        conn.sendToClient(ack.build());
                    }

                    @Override
                    public void onFailure(Throwable t) {
                        log.info("Failed retrieving paymentIncrease info future");
                        error("Failed processing payment update", Protos.Error.ErrorCode.OTHER, CloseReason.UPDATE_PAYMENT_FAILED);
                    }
                });
            }
        }

        if (!stillUsable) {
            log.info("Channel is now fully exhausted, closing/initiating settlement");
            settlePayment(CloseReason.CHANNEL_EXHAUSTED);
        }
    }

    /**
     * Called when a message is received from the client. Processes the given message and generates events based on its
     * content.
     */
    public void receiveMessage(Protos.TwoWayChannelMessage msg) {
        lock.lock();
        try {
            checkState(connectionOpen);
            if (channelSettling)
                return;
            // If we generate an error, we set errorBuilder and closeReason and break, otherwise we return
            Protos.Error.Builder errorBuilder;
            CloseReason closeReason;
            try {
                switch (msg.getType()) {
                    case CLIENT_VERSION:
                        receiveVersionMessage(msg);
                        return;
                    case PROVIDE_REFUND:
                        receiveRefundMessage(msg);
                        return;
                    case PROVIDE_CONTRACT:
                        receiveContractMessage(msg);
                        return;
                    case UPDATE_PAYMENT:
                        checkState(step == InitStep.CHANNEL_OPEN && msg.hasUpdatePayment());
                        receiveUpdatePaymentMessage(msg.getUpdatePayment(), true);
                        return;
                    case CLOSE:
                        receiveCloseMessage();
                        return;
                    case ERROR:
                        checkState(msg.hasError());
                        log.error("Client sent ERROR {} with explanation {}", msg.getError().getCode().name(),
                                msg.getError().hasExplanation() ? msg.getError().getExplanation() : "");
                        conn.destroyConnection(CloseReason.REMOTE_SENT_ERROR);
                        return;
                    default:
                        final String errorText = "Got unknown message type or type that doesn't apply to servers.";
                        error(errorText, Protos.Error.ErrorCode.SYNTAX_ERROR, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
                }
            } catch (VerificationException e) {
                log.error("Caught verification exception handling message from client", e);
                error(e.getMessage(), Protos.Error.ErrorCode.BAD_TRANSACTION, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
            } catch (ValueOutOfRangeException e) {
                log.error("Caught value out of range exception handling message from client", e);
                error(e.getMessage(), Protos.Error.ErrorCode.BAD_TRANSACTION, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
            } catch (InsufficientMoneyException e) {
                log.error("Caught insufficient money exception handling message from client", e);
                error(e.getMessage(), Protos.Error.ErrorCode.BAD_TRANSACTION, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
            } catch (IllegalStateException e) {
                log.error("Caught illegal state exception handling message from client", e);
                error(e.getMessage(), Protos.Error.ErrorCode.SYNTAX_ERROR, CloseReason.REMOTE_SENT_INVALID_MESSAGE);
            }
        } finally {
            lock.unlock();
        }
    }

    private void error(String message, Protos.Error.ErrorCode errorCode, CloseReason closeReason) {
        log.error(message);
        Protos.Error.Builder errorBuilder;
        errorBuilder = Protos.Error.newBuilder()
                .setCode(errorCode)
                .setExplanation(message);
        conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                .setError(errorBuilder)
                .setType(Protos.TwoWayChannelMessage.MessageType.ERROR)
                .build());
        conn.destroyConnection(closeReason);
    }

    @GuardedBy("lock")
    private void receiveCloseMessage() throws InsufficientMoneyException {
        log.info("Got CLOSE message, closing channel");
        if (state != null) {
            settlePayment(CloseReason.CLIENT_REQUESTED_CLOSE);
        } else {
            conn.destroyConnection(CloseReason.CLIENT_REQUESTED_CLOSE);
        }
    }

    @GuardedBy("lock")
    private void settlePayment(final CloseReason clientRequestedClose) throws InsufficientMoneyException {
        // Setting channelSettling here prevents us from sending another CLOSE when state.close() calls
        // close() on us here below via the stored channel state.
        // TODO: Strongly separate the lifecycle of the payment channel from the TCP connection in these classes.
        channelSettling = true;
        Futures.addCallback(state.close(), new FutureCallback<Transaction>() {
            @Override
            public void onSuccess(Transaction result) {
                // Send the successfully accepted transaction back to the client.
                final Protos.TwoWayChannelMessage.Builder msg = Protos.TwoWayChannelMessage.newBuilder();
                msg.setType(Protos.TwoWayChannelMessage.MessageType.CLOSE);
                if (result != null) {
                    // Result can be null on various error paths, like if we never actually opened
                    // properly and so on.
                    msg.getSettlementBuilder().setTx(ByteString.copyFrom(result.bitcoinSerialize()));
                    log.info("Sending CLOSE back with broadcast settlement tx.");
                } else {
                    log.info("Sending CLOSE back without broadcast settlement tx.");
                }
                conn.sendToClient(msg.build());
                conn.destroyConnection(clientRequestedClose);
            }

            @Override
            public void onFailure(Throwable t) {
                log.error("Failed to broadcast settlement tx", t);
                conn.destroyConnection(clientRequestedClose);
            }
        });
    }

    /**
     * <p>Called when the connection terminates. Notifies the {@link StoredServerChannel} object that we can attempt to
     * resume this channel in the future and stops generating messages for the client.</p>
     *
     * <p>Note that this <b>MUST</b> still be called even after either
     * {@link ServerConnection#destroyConnection(CloseReason)} or
     * {@link PaymentChannelServer#close()} is called to actually handle the connection close logic.</p>
     */
    public void connectionClosed() {
        lock.lock();
        try {
            log.info("Server channel closed.");
            connectionOpen = false;

            try {
                if (state != null && state.getMultisigContract() != null) {
                    StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                            wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
                    if (channels != null) {
                        StoredServerChannel storedServerChannel = channels.getChannel(state.getMultisigContract().getHash());
                        if (storedServerChannel != null) {
                            storedServerChannel.clearConnectedHandler();
                        }
                    }
                }
            } catch (IllegalStateException e) {
                // Expected when we call getMultisigContract() sometimes
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Called to indicate the connection has been opened and messages can now be generated for the client.
     */
    public void connectionOpen() {
        lock.lock();
        try {
            log.info("New server channel active.");
            connectionOpen = true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Closes the connection by generating a settle message for the client and calls
     * {@link ServerConnection#destroyConnection(CloseReason)}. Note that this does not broadcast
     * the payment transaction and the client may still resume the same channel if they reconnect</p>
     * <p>
     * <p>Note that {@link PaymentChannelServer#connectionClosed()} must still be called after the connection fully
     * closes.</p>
     */
    public void close() {
        lock.lock();
        try {
            if (connectionOpen && !channelSettling) {
                final Protos.TwoWayChannelMessage.Builder msg = Protos.TwoWayChannelMessage.newBuilder();
                msg.setType(Protos.TwoWayChannelMessage.MessageType.CLOSE);
                conn.sendToClient(msg.build());
                conn.destroyConnection(CloseReason.SERVER_REQUESTED_CLOSE);
            }
        } finally {
            lock.unlock();
        }
    }
}
