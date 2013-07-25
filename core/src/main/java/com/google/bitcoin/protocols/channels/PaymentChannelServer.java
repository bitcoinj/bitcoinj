package com.google.bitcoin.protocols.channels;

import com.google.bitcoin.core.*;
import com.google.bitcoin.protocols.channels.PaymentChannelCloseException.CloseReason;
import com.google.bitcoin.utils.Threading;
import com.google.protobuf.ByteString;
import net.jcip.annotations.GuardedBy;
import org.bitcoin.paymentchannel.Protos;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
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
         */
        public void paymentIncrease(BigInteger by, BigInteger to);
    }
    @GuardedBy("lock") private final ServerConnection conn;

    // Used to keep track of whether or not the "socket" ie connection is open and we can generate messages
    @GuardedBy("lock") private boolean connectionOpen = false;
    // Indicates that no further messages should be sent and we intend to close the connection
    @GuardedBy("lock") private boolean connectionClosing = false;

    // The wallet and peergroup which are used to complete/broadcast transactions
    private final Wallet wallet;
    private final TransactionBroadcaster broadcaster;

    // The key used for multisig in this channel
    @GuardedBy("lock") private ECKey myKey;

    // The minimum accepted channel value
    private final BigInteger minAcceptedChannelSize;

    // The state manager for this channel
    @GuardedBy("lock") private PaymentChannelServerState state;

    // The time this channel expires (ie the refund transaction's locktime)
    @GuardedBy("lock") private long expireTime;

    /**
     * <p>The amount of time we request the client lock in their funds.</p>
     *
     * <p>The value defaults to 24 hours - 60 seconds and should always be greater than 2 hours plus the amount of time
     * the channel is expected to be used and smaller than 24 hours minus the client <-> server latency minus some
     * factor to account for client clock inaccuracy.</p>
     */
    public long timeWindow = 24*60*60 - 60;

    /**
     * Creates a new server-side state manager which handles a single client connection.
     *
     * @param broadcaster The PeerGroup on which transactions will be broadcast - should have multiple connections.
     * @param wallet The wallet which will be used to complete transactions.
     *               Unlike {@link PaymentChannelClient}, this does not have to already contain a StoredState manager
     * @param minAcceptedChannelSize The minimum value the client must lock into this channel. A value too large will be
     *                               rejected by clients, and a value too low will require excessive channel reopening
     *                               and may cause fees to be require to close the channel. A reasonable value depends
     *                               entirely on the expected maximum for the channel, and should likely be somewhere
     *                               between a few bitcents and a bitcoin.
     * @param conn A callback listener which represents the connection to the client (forwards messages we generate to
     *             the client and will close the connection on request)
     */
    public PaymentChannelServer(TransactionBroadcaster broadcaster, Wallet wallet,
                                BigInteger minAcceptedChannelSize, ServerConnection conn) {
        this.broadcaster = checkNotNull(broadcaster);
        this.wallet = checkNotNull(wallet);
        this.minAcceptedChannelSize = checkNotNull(minAcceptedChannelSize);
        this.conn = checkNotNull(conn);
    }

    @GuardedBy("lock")
    private void receiveVersionMessage(Protos.TwoWayChannelMessage msg) throws VerificationException {
        Protos.ServerVersion.Builder versionNegotiationBuilder = Protos.ServerVersion.newBuilder()
                .setMajor(0).setMinor(1);
        conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION)
                .setServerVersion(versionNegotiationBuilder)
                .build());
        ByteString reopenChannelContractHash = msg.getClientVersion().getPreviousChannelContractHash();
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
        log.info("Got initial version message, responding with VERSIONS and INITIATE");

        myKey = new ECKey();
        wallet.addKey(myKey);

        expireTime = Utils.now().getTime() / 1000 + timeWindow;
        step = InitStep.WAITING_ON_UNSIGNED_REFUND;

        Protos.Initiate.Builder initiateBuilder = Protos.Initiate.newBuilder()
                .setMultisigKey(ByteString.copyFrom(myKey.getPubKey()))
                .setExpireTimeSecs(expireTime)
                .setMinAcceptedChannelSize(minAcceptedChannelSize.longValue());

        conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                .setInitiate(initiateBuilder)
                .setType(Protos.TwoWayChannelMessage.MessageType.INITIATE)
                .build());
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

    private void multisigContractPropogated(Sha256Hash contractHash) {
        lock.lock();
        try {
            if (!connectionOpen || connectionClosing)
                return;
            state.storeChannelInWallet(PaymentChannelServer.this);
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
        Protos.ProvideContract providedContract = msg.getProvideContract();

        //TODO notify connection handler that timeout should be significantly extended as we wait for network propagation?
        final Transaction multisigContract = new Transaction(wallet.getParams(), providedContract.getTx().toByteArray());
        step = InitStep.WAITING_ON_MULTISIG_ACCEPTANCE;
        state.provideMultiSigContract(multisigContract)
                .addListener(new Runnable() {
                    @Override
                    public void run() {
                        multisigContractPropogated(multisigContract.getHash());
                    }
                }, Threading.SAME_THREAD);
    }

    @GuardedBy("lock")
    private void receiveUpdatePaymentMessage(Protos.TwoWayChannelMessage msg) throws VerificationException, ValueOutOfRangeException {
        checkState(step == InitStep.CHANNEL_OPEN && msg.hasUpdatePayment());
        log.info("Got a payment update");

        Protos.UpdatePayment updatePayment = msg.getUpdatePayment();
        BigInteger lastBestPayment = state.getBestValueToMe();
        state.incrementPayment(BigInteger.valueOf(updatePayment.getClientChangeValue()), updatePayment.getSignature().toByteArray());
        BigInteger bestPaymentChange = state.getBestValueToMe().subtract(lastBestPayment);

        if (bestPaymentChange.compareTo(BigInteger.ZERO) > 0)
            conn.paymentIncrease(bestPaymentChange, state.getBestValueToMe());
    }

    /**
     * Called when a message is received from the client. Processes the given message and generates events based on its
     * content.
     */
    public void receiveMessage(Protos.TwoWayChannelMessage msg) {
        lock.lock();
        try {
            checkState(connectionOpen);
            if (connectionClosing)
                return;
            // If we generate an error, we set errorBuilder and closeReason and break, otherwise we return
            Protos.Error.Builder errorBuilder;
            CloseReason closeReason;
            try {
                switch (msg.getType()) {
                    case CLIENT_VERSION:
                        checkState(step == InitStep.WAITING_ON_CLIENT_VERSION && msg.hasClientVersion());
                        if (msg.getClientVersion().getMajor() != 0) {
                            errorBuilder = Protos.Error.newBuilder()
                                    .setCode(Protos.Error.ErrorCode.NO_ACCEPTABLE_VERSION);
                            closeReason = CloseReason.NO_ACCEPTABLE_VERSION;
                            break;
                        }

                        receiveVersionMessage(msg);
                        return;
                    case PROVIDE_REFUND:
                        receiveRefundMessage(msg);
                        return;
                    case PROVIDE_CONTRACT:
                        receiveContractMessage(msg);
                        return;
                    case UPDATE_PAYMENT:
                        receiveUpdatePaymentMessage(msg);
                        return;
                    case CLOSE:
                        log.info("Got CLOSE message, closing channel");
                        connectionClosing = true;
                        if (state != null)
                            state.close();
                        conn.destroyConnection(CloseReason.CLIENT_REQUESTED_CLOSE);
                        return;
                    case ERROR:
                        checkState(msg.hasError());
                        log.error("Client sent ERROR {} with explanation {}", msg.getError().getCode().name(),
                                msg.getError().hasExplanation() ? msg.getError().getExplanation() : "");
                        conn.destroyConnection(CloseReason.REMOTE_SENT_ERROR);
                        return;
                    default:
                        log.error("Got unknown message type or type that doesn't apply to servers.");
                        errorBuilder = Protos.Error.newBuilder()
                                .setCode(Protos.Error.ErrorCode.SYNTAX_ERROR);
                        closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
                        break;
                }
            } catch (VerificationException e) {
                log.error("Caught verification exception handling message from client {}", e);
                errorBuilder = Protos.Error.newBuilder()
                        .setCode(Protos.Error.ErrorCode.BAD_TRANSACTION)
                        .setExplanation(e.getMessage());
                closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
            } catch (ValueOutOfRangeException e) {
                log.error("Caught value out of range exception handling message from client {}", e);
                errorBuilder = Protos.Error.newBuilder()
                        .setCode(Protos.Error.ErrorCode.BAD_TRANSACTION)
                        .setExplanation(e.getMessage());
                closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
            } catch (IllegalStateException e) {
                log.error("Caught illegal state exception handling message from client {}", e);
                errorBuilder = Protos.Error.newBuilder()
                        .setCode(Protos.Error.ErrorCode.SYNTAX_ERROR);
                closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
            }
            conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                    .setError(errorBuilder)
                    .setType(Protos.TwoWayChannelMessage.MessageType.ERROR)
                    .build());
            conn.destroyConnection(closeReason);
        } finally {
            lock.unlock();
        }
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
     * <p>Closes the connection by generating a close message for the client and calls
     * {@link ServerConnection#destroyConnection(CloseReason)}. Note that this does not broadcast
     * the payment transaction and the client may still resume the same channel if they reconnect</p>
     *
     * <p>Note that {@link PaymentChannelServer#connectionClosed()} must still be called after the connection fully
     * closes.</p>
     */
    public void close() {
        lock.lock();
        try {
            if (connectionOpen && !connectionClosing) {
                conn.sendToClient(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.CLOSE)
                        .build());
                conn.destroyConnection(CloseReason.SERVER_REQUESTED_CLOSE);
            }
        } finally {
            lock.unlock();
        }
    }
}
