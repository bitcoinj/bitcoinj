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

package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.*;
import org.bitcoinj.protocols.channels.PaymentChannelCloseException.CloseReason;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import net.jcip.annotations.GuardedBy;
import org.bitcoin.paymentchannel.Protos;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
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
public class PaymentChannelClient implements IPaymentChannelClient {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(PaymentChannelClient.class);

    protected final ReentrantLock lock = Threading.lock("channelclient");
    protected final ClientChannelProperties clientChannelProperties;

    // Used to track the negotiated version number
    @GuardedBy("lock") private int majorVersion;

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
        CHANNEL_OPEN,
        WAITING_FOR_CHANNEL_CLOSE,
        CHANNEL_CLOSED,
    }
    @GuardedBy("lock") private InitStep step = InitStep.WAITING_FOR_CONNECTION_OPEN;

    public enum VersionSelector {
        VERSION_1,
        VERSION_2_ALLOW_1,
        VERSION_2;

        public int getRequestedMajorVersion() {
            switch (this) {
                case VERSION_1:
                    return 1;
                case VERSION_2_ALLOW_1:
                case VERSION_2:
                default:
                    return 2;
            }
        }

        public int getRequestedMinorVersion() {
            return 0;
        }

        public boolean isServerVersionAccepted(int major, int minor) {
            switch (this) {
                case VERSION_1:
                    return major == 1;
                case VERSION_2_ALLOW_1:
                    return major == 1 || major == 2;
                case VERSION_2:
                    return major == 2;
                default:
                    return false;
            }
        }
    }

    private final VersionSelector versionSelector;

    // Will either hold the StoredClientChannel of this channel or null after connectionOpen
    private StoredClientChannel storedChannel;
    // An arbitrary hash which identifies this channel (specified by the API user)
    private final Sha256Hash serverId;

    // The wallet associated with this channel
    private final Wallet wallet;

    // Information used during channel initialization to send to the server or check what the server sends to us
    private final ECKey myKey;
    private final Coin maxValue;

    private Coin missing;

    // key to decrypt myKey, if it is encrypted, during setup.
    private KeyParameter userKeySetup;

    private final long timeWindow;

    @GuardedBy("lock") private long minPayment;

    @GuardedBy("lock") SettableFuture<PaymentIncrementAck> increasePaymentFuture;
    @GuardedBy("lock") Coin lastPaymentActualAmount;

    /**
     * <p>The default maximum amount of time for which we will accept the server locking up our funds for the multisig
     * contract.</p>
     *
     * <p>24 hours less a minute  is the default as it is expected that clients limit risk exposure by limiting channel size instead of
     * limiting lock time when dealing with potentially malicious servers.</p>
     */
    public static final long DEFAULT_TIME_WINDOW = 24*60*60-60;

    /**
     * Constructs a new channel manager which waits for {@link PaymentChannelClient#connectionOpen()} before acting.
     * A default time window of {@link #DEFAULT_TIME_WINDOW} will be used.
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
    public PaymentChannelClient(Wallet wallet, ECKey myKey, Coin maxValue, Sha256Hash serverId, ClientConnection conn) {
        this(wallet,myKey,maxValue,serverId, null, conn);
    }

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
     * @param userKeySetup Key derived from a user password, used to decrypt myKey, if it is encrypted, during setup.
     * @param conn A callback listener which represents the connection to the server (forwards messages we generate to
     *             the server)
     */
    public PaymentChannelClient(Wallet wallet, ECKey myKey, Coin maxValue, Sha256Hash serverId,
                                @Nullable KeyParameter userKeySetup, ClientConnection conn) {
        this(wallet, myKey, maxValue, serverId, userKeySetup, defaultChannelProperties, conn);
    }

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
     * @param userKeySetup Key derived from a user password, used to decrypt myKey, if it is encrypted, during setup.
     * @param clientChannelProperties Modify the channel's properties. You may extend {@link DefaultClientChannelProperties}
     * @param conn A callback listener which represents the connection to the server (forwards messages we generate to
     *             the server)
     */
    public PaymentChannelClient(Wallet wallet, ECKey myKey, Coin maxValue, Sha256Hash serverId,
                                @Nullable KeyParameter userKeySetup, @Nullable ClientChannelProperties clientChannelProperties,
                                ClientConnection conn) {
        this.wallet = checkNotNull(wallet);
        this.myKey = checkNotNull(myKey);
        this.maxValue = checkNotNull(maxValue);
        this.serverId = checkNotNull(serverId);
        this.conn = checkNotNull(conn);
        this.userKeySetup = userKeySetup;
        if (clientChannelProperties == null) {
            this.clientChannelProperties = defaultChannelProperties;
        } else {
            this.clientChannelProperties = clientChannelProperties;
        }
        this.timeWindow = clientChannelProperties.timeWindow();
        checkState(timeWindow >= 0);
        this.versionSelector = clientChannelProperties.versionSelector();
    }

    /** 
     * <p>Returns the amount of satoshis missing when a server requests too much value.</p>
     *
     * <p>When InsufficientMoneyException is thrown due to the server requesting too much value, an instance of 
     * PaymentChannelClient needs access to how many satoshis are missing.</p>
     */
    public Coin getMissing() {
        return missing;
    }

    @Nullable
    @GuardedBy("lock")
    private CloseReason receiveInitiate(Protos.Initiate initiate, Coin contractValue, Protos.Error.Builder errorBuilder)
            throws VerificationException, InsufficientMoneyException, ECKey.KeyIsEncryptedException {
        log.info("Got INITIATE message:\n{}", initiate.toString());

        if (wallet.isEncrypted() && this.userKeySetup == null)
            throw new ECKey.KeyIsEncryptedException();

        final long expireTime = initiate.getExpireTimeSecs();
        checkState( expireTime >= 0 && initiate.getMinAcceptedChannelSize() >= 0);

        if (! conn.acceptExpireTime(expireTime)) {
            log.error("Server suggested expire time was out of our allowed bounds: {} ({} s)", Utils.dateTimeFormat(expireTime * 1000), expireTime);
            errorBuilder.setCode(Protos.Error.ErrorCode.TIME_WINDOW_UNACCEPTABLE);
            return CloseReason.TIME_WINDOW_UNACCEPTABLE;
        }

        Coin minChannelSize = Coin.valueOf(initiate.getMinAcceptedChannelSize());
        if (contractValue.compareTo(minChannelSize) < 0) {
            log.error("Server requested too much value");
            errorBuilder.setCode(Protos.Error.ErrorCode.CHANNEL_VALUE_TOO_LARGE);
            missing = minChannelSize.subtract(contractValue);
            return CloseReason.SERVER_REQUESTED_TOO_MUCH_VALUE;
        }

        // For now we require a hard-coded value. In future this will have to get more complex and dynamic as the fees
        // start to float.
        final long maxMin = clientChannelProperties.acceptableMinPayment().value;
        if (initiate.getMinPayment() > maxMin) {
            log.error("Server requested a min payment of {} but we only accept up to {}", initiate.getMinPayment(), maxMin);
            errorBuilder.setCode(Protos.Error.ErrorCode.MIN_PAYMENT_TOO_LARGE);
            errorBuilder.setExpectedValue(maxMin);
            missing = Coin.valueOf(initiate.getMinPayment() - maxMin);
            return CloseReason.SERVER_REQUESTED_TOO_MUCH_VALUE;
        }

        final byte[] pubKeyBytes = initiate.getMultisigKey().toByteArray();
        if (!ECKey.isPubKeyCanonical(pubKeyBytes))
            throw new VerificationException("Server gave us a non-canonical public key, protocol error.");
        switch (majorVersion) {
            case 1:
                state = new PaymentChannelV1ClientState(wallet, myKey, ECKey.fromPublicOnly(pubKeyBytes), contractValue, expireTime);
                break;
            case 2:
                state = new PaymentChannelV2ClientState(wallet, myKey, ECKey.fromPublicOnly(pubKeyBytes), contractValue, expireTime);
                break;
            default:
                return CloseReason.NO_ACCEPTABLE_VERSION;
        }
        try {
            state.initiate(userKeySetup, clientChannelProperties);
        } catch (ValueOutOfRangeException e) {
            log.error("Value out of range when trying to initiate", e);
            errorBuilder.setCode(Protos.Error.ErrorCode.CHANNEL_VALUE_TOO_LARGE);
            return CloseReason.SERVER_REQUESTED_TOO_MUCH_VALUE;
        }
        minPayment = initiate.getMinPayment();
        switch (majorVersion) {
            case 1:
                step = InitStep.WAITING_FOR_REFUND_RETURN;

                Protos.ProvideRefund.Builder provideRefundBuilder = Protos.ProvideRefund.newBuilder()
                        .setMultisigKey(ByteString.copyFrom(myKey.getPubKey()))
                        .setTx(ByteString.copyFrom(((PaymentChannelV1ClientState)state).getIncompleteRefundTransaction().unsafeBitcoinSerialize()));

                conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                        .setProvideRefund(provideRefundBuilder)
                        .setType(Protos.TwoWayChannelMessage.MessageType.PROVIDE_REFUND)
                        .build());
                break;
            case 2:
                step = InitStep.WAITING_FOR_CHANNEL_OPEN;

                // Before we can send the server the contract (ie send it to the network), we must ensure that our refund
                // transaction is safely in the wallet - thus we store it (this also keeps it up-to-date when we pay)
                state.storeChannelInWallet(serverId);

                Protos.ProvideContract.Builder provideContractBuilder = Protos.ProvideContract.newBuilder()
                        .setTx(ByteString.copyFrom(state.getContract().unsafeBitcoinSerialize()))
                        .setClientKey(ByteString.copyFrom(myKey.getPubKey()));
                try {
                    // Make an initial payment of the dust limit, and put it into the message as well. The size of the
                    // server-requested dust limit was already sanity checked by this point.
                    PaymentChannelClientState.IncrementedPayment payment = state().incrementPaymentBy(Coin.valueOf(minPayment), userKeySetup);
                    Protos.UpdatePayment.Builder initialMsg = provideContractBuilder.getInitialPaymentBuilder();
                    initialMsg.setSignature(ByteString.copyFrom(payment.signature.encodeToBitcoin()));
                    initialMsg.setClientChangeValue(state.getValueRefunded().value);
                } catch (ValueOutOfRangeException e) {
                    throw new IllegalStateException(e);  // This cannot happen.
                }

                // Not used any more
                userKeySetup = null;

                final Protos.TwoWayChannelMessage.Builder msg = Protos.TwoWayChannelMessage.newBuilder();
                msg.setProvideContract(provideContractBuilder);
                msg.setType(Protos.TwoWayChannelMessage.MessageType.PROVIDE_CONTRACT);
                conn.sendToServer(msg.build());
                break;
            default:
                return CloseReason.NO_ACCEPTABLE_VERSION;
        }
        return null;
    }

    @GuardedBy("lock")
    private void receiveRefund(Protos.TwoWayChannelMessage refundMsg, @Nullable KeyParameter userKey) throws VerificationException {
        checkState(majorVersion == 1);
        checkState(step == InitStep.WAITING_FOR_REFUND_RETURN && refundMsg.hasReturnRefund());
        log.info("Got RETURN_REFUND message, providing signed contract");
        Protos.ReturnRefund returnedRefund = refundMsg.getReturnRefund();
        // Cast is safe since we've checked the version number
        ((PaymentChannelV1ClientState)state).provideRefundSignature(returnedRefund.getSignature().toByteArray(), userKey);
        step = InitStep.WAITING_FOR_CHANNEL_OPEN;

        // Before we can send the server the contract (ie send it to the network), we must ensure that our refund
        // transaction is safely in the wallet - thus we store it (this also keeps it up-to-date when we pay)
        state.storeChannelInWallet(serverId);

        Protos.ProvideContract.Builder contractMsg = Protos.ProvideContract.newBuilder()
                .setTx(ByteString.copyFrom(state.getContract().unsafeBitcoinSerialize()));
        try {
            // Make an initial payment of the dust limit, and put it into the message as well. The size of the
            // server-requested dust limit was already sanity checked by this point.
            PaymentChannelClientState.IncrementedPayment payment = state().incrementPaymentBy(Coin.valueOf(minPayment), userKey);
            Protos.UpdatePayment.Builder initialMsg = contractMsg.getInitialPaymentBuilder();
            initialMsg.setSignature(ByteString.copyFrom(payment.signature.encodeToBitcoin()));
            initialMsg.setClientChangeValue(state.getValueRefunded().value);
        } catch (ValueOutOfRangeException e) {
            throw new IllegalStateException(e);  // This cannot happen.
        }

        final Protos.TwoWayChannelMessage.Builder msg = Protos.TwoWayChannelMessage.newBuilder();
        msg.setProvideContract(contractMsg);
        msg.setType(Protos.TwoWayChannelMessage.MessageType.PROVIDE_CONTRACT);
        conn.sendToServer(msg.build());
    }

    @GuardedBy("lock")
    private void receiveChannelOpen() throws VerificationException {
        checkState(step == InitStep.WAITING_FOR_CHANNEL_OPEN || (step == InitStep.WAITING_FOR_INITIATE && storedChannel != null), step);
        log.info("Got CHANNEL_OPEN message, ready to pay");

        boolean wasInitiated = true;
        if (step == InitStep.WAITING_FOR_INITIATE) {
            // We skipped the initiate step, because a previous channel that's still valid was resumed.
            wasInitiated  = false;
            switch (majorVersion) {
                case 1:
                    state = new PaymentChannelV1ClientState(storedChannel, wallet);
                    break;
                case 2:
                    state = new PaymentChannelV2ClientState(storedChannel, wallet);
                    break;
                default:
                    throw new IllegalStateException("Invalid version number " + majorVersion);
            }
        }
        step = InitStep.CHANNEL_OPEN;
        // channelOpen should disable timeouts, but
        // TODO accomodate high latency between PROVIDE_CONTRACT and here
        conn.channelOpen(wasInitiated);
    }

    @Override
    public void receiveMessage(Protos.TwoWayChannelMessage msg) throws InsufficientMoneyException {
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
                        // Server might send back a major version lower than our own if they want to fallback to a
                        // lower version. We can't handle that, so we just close the channel.
                        majorVersion = msg.getServerVersion().getMajor();
                        if (!versionSelector.isServerVersionAccepted(majorVersion, msg.getServerVersion().getMinor())) {
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
                        errorBuilder = Protos.Error.newBuilder();
                        closeReason = receiveInitiate(initiate, maxValue, errorBuilder);
                        if (closeReason == null)
                            return;
                        log.error("Initiate failed with error: {}", errorBuilder.build().toString());
                        break;
                    case RETURN_REFUND:
                        receiveRefund(msg, userKeySetup);
                        // Key not used anymore
                        userKeySetup = null;
                        return;
                    case CHANNEL_OPEN:
                        receiveChannelOpen();
                        return;
                    case PAYMENT_ACK:
                        receivePaymentAck(msg.getPaymentAck());
                        return;
                    case CLOSE:
                        receiveClose(msg);
                        return;
                    case ERROR:
                        checkState(msg.hasError());
                        log.error("Server sent ERROR {} with explanation {}", msg.getError().getCode().name(),
                                msg.getError().hasExplanation() ? msg.getError().getExplanation() : "");
                        setIncreasePaymentFutureIfNeeded(CloseReason.REMOTE_SENT_ERROR, msg.getError().getCode().name());
                        conn.destroyConnection(CloseReason.REMOTE_SENT_ERROR);
                        return;
                    default:
                        log.error("Got unknown message type or type that doesn't apply to clients.");
                        errorBuilder = Protos.Error.newBuilder()
                                .setCode(Protos.Error.ErrorCode.SYNTAX_ERROR);
                        setIncreasePaymentFutureIfNeeded(CloseReason.REMOTE_SENT_INVALID_MESSAGE, "");
                        closeReason = CloseReason.REMOTE_SENT_INVALID_MESSAGE;
                        break;
                }
            } catch (VerificationException e) {
                log.error("Caught verification exception handling message from server", e);
                errorBuilder = Protos.Error.newBuilder()
                        .setCode(Protos.Error.ErrorCode.BAD_TRANSACTION);
                final String message = e.getMessage();
                if (message != null)
                    errorBuilder.setExplanation(message);
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

    /*
     * If this is an ongoing payment channel increase we need to call setException() on its future.
     *
     * @param reason is the reason for aborting
     * @param message is the detailed message
     */
    private void setIncreasePaymentFutureIfNeeded(PaymentChannelCloseException.CloseReason reason, String message) {
        if (increasePaymentFuture != null && !increasePaymentFuture.isDone()) {
            increasePaymentFuture.setException(new PaymentChannelCloseException(message, reason));
        }
    }

    @GuardedBy("lock")
    private void receiveClose(Protos.TwoWayChannelMessage msg) throws VerificationException {
        checkState(lock.isHeldByCurrentThread());
        if (msg.hasSettlement()) {
            Transaction settleTx = wallet.getParams().getDefaultSerializer().makeTransaction(msg.getSettlement().getTx().toByteArray());
            log.info("CLOSE message received with settlement tx {}", settleTx.getHash());
            // TODO: set source
            if (state != null && state().isSettlementTransaction(settleTx)) {
                // The wallet has a listener on it that the state object will use to do the right thing at this
                // point (like watching it for confirmations). The tx has been checked by now for syntactical validity
                // and that it correctly spends the multisig contract.
                wallet.receivePending(settleTx, null);
            }
        } else {
            log.info("CLOSE message received without settlement tx");
        }
        if (step == InitStep.WAITING_FOR_CHANNEL_CLOSE)
            conn.destroyConnection(CloseReason.CLIENT_REQUESTED_CLOSE);
        else
            conn.destroyConnection(CloseReason.SERVER_REQUESTED_CLOSE);
        step = InitStep.CHANNEL_CLOSED;
    }

    /**
     * <p>Called when the connection terminates. Notifies the {@link StoredClientChannel} object that we can attempt to
     * resume this channel in the future and stops generating messages for the server.</p>
     *
     * <p>For stateless protocols, this translates to a client not using the channel for the immediate future, but
     * intending to reopen the channel later. There is likely little reason to use this in a stateless protocol.</p>
     *
     * <p>Note that this <b>MUST</b> still be called even after either
     * {@link IPaymentChannelClient.ClientConnection#destroyConnection(PaymentChannelCloseException.CloseReason)} or
     * {@link PaymentChannelClient#settle()} is called, to actually handle the connection close logic.</p>
     */
    @Override
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
     * <p>Closes the connection, notifying the server it should settle the channel by broadcasting the most recent
     * payment transaction.</p>
     *
     * <p>Note that this only generates a CLOSE message for the server and calls
     * {@link IPaymentChannelClient.ClientConnection#destroyConnection(PaymentChannelCloseException.CloseReason)} to settle the connection, it does not
     * actually handle connection close logic, and {@link PaymentChannelClient#connectionClosed()} must still be called
     * after the connection fully closes.</p>
     *
     * @throws IllegalStateException If the connection is not currently open (ie the CLOSE message cannot be sent)
     */
    @Override
    public void settle() throws IllegalStateException {
        lock.lock();
        try {
            checkState(connectionOpen);
            step = InitStep.WAITING_FOR_CHANNEL_CLOSE;
            log.info("Sending a CLOSE message to the server and waiting for response indicating successful settlement.");
            conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                    .setType(Protos.TwoWayChannelMessage.MessageType.CLOSE)
                    .build());
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
    @Override
    public void connectionOpen() {
        lock.lock();
        try {
            connectionOpen = true;

            StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates) wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
            if (channels != null)
                storedChannel = channels.getUsableChannelForServerID(serverId);

            step = InitStep.WAITING_FOR_VERSION_NEGOTIATION;

            Protos.ClientVersion.Builder versionNegotiationBuilder = Protos.ClientVersion.newBuilder()
                    .setMajor(versionSelector.getRequestedMajorVersion())
                    .setMinor(versionSelector.getRequestedMinorVersion())
                    .setTimeWindowSecs(timeWindow);

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
     * Increments the total value which we pay the server. Note that the amount of money sent may not be the same as the
     * amount of money actually requested. It can be larger if the amount left over in the channel would be too small to
     * be accepted by the Bitcoin network. ValueOutOfRangeException will be thrown, however, if there's not enough money
     * left in the channel to make the payment at all. Only one payment can be in-flight at once. You have to ensure
     * you wait for the previous increase payment future to complete before incrementing the payment again.
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @return a future that completes when the server acknowledges receipt and acceptance of the payment.
     * @throws ValueOutOfRangeException If the size is negative or would pay more than this channel's total value
     *                                  ({@link PaymentChannelClientConnection#state()}.getTotalValue())
     * @throws IllegalStateException If the channel has been closed or is not yet open
     *                               (see {@link PaymentChannelClientConnection#getChannelOpenFuture()} for the second)
     */
    public ListenableFuture<PaymentIncrementAck> incrementPayment(Coin size) throws ValueOutOfRangeException, IllegalStateException {
        return incrementPayment(size, null, null);
    }

    /**
     * Increments the total value which we pay the server. Note that the amount of money sent may not be the same as the
     * amount of money actually requested. It can be larger if the amount left over in the channel would be too small to
     * be accepted by the Bitcoin network. ValueOutOfRangeException will be thrown, however, if there's not enough money
     * left in the channel to make the payment at all. Only one payment can be in-flight at once. You have to ensure
     * you wait for the previous increase payment future to complete before incrementing the payment again.
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @param info Information about this update, used to extend this protocol.
     * @param userKey Key derived from a user password, needed for any signing when the wallet is encrypted.
     *                The wallet KeyCrypter is assumed.
     * @return a future that completes when the server acknowledges receipt and acceptance of the payment.
     * @throws ValueOutOfRangeException If the size is negative or would pay more than this channel's total value
     *                                  ({@link PaymentChannelClientConnection#state()}.getTotalValue())
     * @throws IllegalStateException If the channel has been closed or is not yet open
     *                               (see {@link PaymentChannelClientConnection#getChannelOpenFuture()} for the second)
     * @throws ECKey.KeyIsEncryptedException If the keys are encrypted and no AES key has been provided,
     */
    @Override
    public ListenableFuture<PaymentIncrementAck> incrementPayment(Coin size, @Nullable ByteString info, @Nullable KeyParameter userKey)
            throws ValueOutOfRangeException, IllegalStateException, ECKey.KeyIsEncryptedException {
        lock.lock();
        try {
            if (state() == null || !connectionOpen || step != InitStep.CHANNEL_OPEN)
                throw new IllegalStateException("Channel is not fully initialized/has already been closed");
            if (increasePaymentFuture != null)
                throw new IllegalStateException("Already incrementing paying, wait for previous payment to complete.");
            if (wallet.isEncrypted() && userKey == null)
                throw new ECKey.KeyIsEncryptedException();

            PaymentChannelV1ClientState.IncrementedPayment payment = state().incrementPaymentBy(size, userKey);
            Protos.UpdatePayment.Builder updatePaymentBuilder = Protos.UpdatePayment.newBuilder()
                    .setSignature(ByteString.copyFrom(payment.signature.encodeToBitcoin()))
                    .setClientChangeValue(state.getValueRefunded().value);
            if (info != null) updatePaymentBuilder.setInfo(info);

            increasePaymentFuture = SettableFuture.create();
            increasePaymentFuture.addListener(new Runnable() {
                @Override
                public void run() {
                    lock.lock();
                    increasePaymentFuture = null;
                    lock.unlock();
                }
            }, MoreExecutors.directExecutor());

            conn.sendToServer(Protos.TwoWayChannelMessage.newBuilder()
                    .setUpdatePayment(updatePaymentBuilder)
                    .setType(Protos.TwoWayChannelMessage.MessageType.UPDATE_PAYMENT)
                    .build());
            lastPaymentActualAmount = payment.amount;
            return increasePaymentFuture;
        } finally {
            lock.unlock();
        }
    }

    private void receivePaymentAck(Protos.PaymentAck paymentAck) {
        SettableFuture<PaymentIncrementAck> future;
        Coin value;

        lock.lock();
        try {
            if (increasePaymentFuture == null) return;
            checkNotNull(increasePaymentFuture, "Server sent a PAYMENT_ACK with no outstanding payment");
            log.info("Received a PAYMENT_ACK from the server");
            future = increasePaymentFuture;
            value = lastPaymentActualAmount;
        } finally {
            lock.unlock();
        }

        // Ensure the future runs without the client lock held.
        future.set(new PaymentIncrementAck(value, paymentAck.getInfo()));
    }

    public static class DefaultClientChannelProperties implements ClientChannelProperties {

        @Override
        public SendRequest modifyContractSendRequest(SendRequest sendRequest) {
            return sendRequest;
        }

        @Override
        public Coin acceptableMinPayment() { return Transaction.REFERENCE_DEFAULT_MIN_TX_FEE; }

        @Override
        public long timeWindow() {
            return DEFAULT_TIME_WINDOW;
        }

        @Override
        public VersionSelector versionSelector() {
            return VersionSelector.VERSION_2_ALLOW_1;
        }

    }

    public static DefaultClientChannelProperties defaultChannelProperties = new DefaultClientChannelProperties();
}
