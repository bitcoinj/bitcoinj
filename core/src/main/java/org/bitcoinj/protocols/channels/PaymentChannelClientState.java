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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Throwables;
import com.google.common.collect.Multimap;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.protocols.channels.IPaymentChannelClient.ClientChannelProperties;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A payment channel is a method of sending money to someone such that the amount of money you send can be adjusted
 * after the fact, in an efficient manner that does not require broadcasting to the network. This can be used to
 * implement micropayments or other payment schemes in which immediate settlement is not required, but zero trust
 * negotiation is. Note that this class only allows the amount of money sent to be incremented, not decremented.</p>
 *
 * <p>This class has two subclasses, {@link PaymentChannelV1ClientState} and {@link PaymentChannelV2ClientState} for
 * protocols version 1 and 2.</p>
 *
 * <p>This class implements the core state machine for the client side of the protocol. The server side is implemented
 * by {@link PaymentChannelServerState} and {@link PaymentChannelClientConnection} implements a network protocol
 * suitable for TCP/IP connections which moves this class through each state. We say that the party who is sending funds
 * is the <i>client</i> or <i>initiating party</i>. The party that is receiving the funds is the <i>server</i> or
 * <i>receiving party</i>. Although the underlying Bitcoin protocol is capable of more complex relationships than that,
 * this class implements only the simplest case.</p>
 *
 * <p>A channel has an expiry parameter. If the server halts after the multi-signature contract which locks
 * up the given value is broadcast you could get stuck in a state where you've lost all the money put into the
 * contract. To avoid this, a refund transaction is agreed ahead of time but it may only be used/broadcast after
 * the expiry time. This is specified in terms of block timestamps and once the timestamp of the chain chain approaches
 * the given time (within a few hours), the channel must be closed or else the client will broadcast the refund
 * transaction and take back all the money once the expiry time is reached.</p>
 *
 * <p>To begin, the client calls {@link PaymentChannelClientState#initiate(KeyParameter, IPaymentChannelClient.ClientChannelProperties)}, which moves the channel into state
 * INITIATED and creates the initial multi-sig contract and refund transaction. If the wallet has insufficient funds an
 * exception will be thrown at this point. Once this is done, call
 * {@link PaymentChannelV1ClientState#getIncompleteRefundTransaction()} and pass the resultant transaction through to the
 * server. Once you have retrieved the signature, use {@link PaymentChannelV1ClientState#provideRefundSignature(byte[], KeyParameter)}.
 * You must then call {@link PaymentChannelClientState#storeChannelInWallet(Sha256Hash)} to store the refund transaction
 * in the wallet, protecting you against a malicious server attempting to destroy all your coins. At this point, you can
 * provide the server with the multi-sig contract (via {@link PaymentChannelClientState#getContract()}) safely.
 * </p>
 */
public abstract class PaymentChannelClientState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelClientState.class);
    // How much value is currently allocated to us. Starts as being same as totalValue.
    protected Coin valueToMe;

    /**
     * The different logical states the channel can be in. The channel starts out as NEW, and then steps through the
     * states until it becomes finalized. The server should have already been contacted and asked for a public key
     * by the time the NEW state is reached.
     */
    public enum State {
        UNINITIALISED,
        NEW,
        INITIATED,
        WAITING_FOR_SIGNED_REFUND,
        SAVE_STATE_IN_WALLET,
        PROVIDE_MULTISIG_CONTRACT_TO_SERVER,
        READY,
        EXPIRED,
        CLOSED
    }
    protected final StateMachine<State> stateMachine;

    final Wallet wallet;

    // Both sides need a key (private in our case, public for the server) in order to manage the multisig contract
    // and transactions that spend it.
    final ECKey myKey, serverKey;

    // The id of this channel in the StoredPaymentChannelClientStates, or null if it is not stored
    protected StoredClientChannel storedChannel;

    PaymentChannelClientState(StoredClientChannel storedClientChannel, Wallet wallet) throws VerificationException {
        this.stateMachine = new StateMachine<>(State.UNINITIALISED, getStateTransitions());
        this.wallet = checkNotNull(wallet);
        this.myKey = checkNotNull(storedClientChannel.myKey);
        this.serverKey = checkNotNull(storedClientChannel.serverKey);
        this.storedChannel = storedClientChannel;
        this.valueToMe = checkNotNull(storedClientChannel.valueToMe);
    }

    /**
     * Returns true if the tx is a valid settlement transaction.
     */
    public synchronized boolean isSettlementTransaction(Transaction tx) {
        try {
            tx.verify();
            tx.getInput(0).verify(getContractInternal().getOutput(0));
            return true;
        } catch (VerificationException e) {
            return false;
        }
    }

    /**
     * Creates a state object for a payment channel client. It is expected that you be ready to
     * {@link PaymentChannelClientState#initiate(KeyParameter, IPaymentChannelClient.ClientChannelProperties)} after construction (to avoid creating objects for channels which are
     * not going to finish opening) and thus some parameters provided here are only used in
     * {@link PaymentChannelClientState#initiate(KeyParameter, IPaymentChannelClient.ClientChannelProperties)} to create the Multisig contract and refund transaction.
     *
     * @param wallet a wallet that contains at least the specified amount of value.
     * @param myKey a freshly generated private key for this channel.
     * @param serverKey a public key retrieved from the server used for the initial multisig contract
     * @param value how many satoshis to put into this contract. If the channel reaches this limit, it must be closed.
     * @param expiryTimeInSeconds At what point (UNIX timestamp +/- a few hours) the channel will expire
     *
     * @throws VerificationException If either myKey's pubkey or serverKey's pubkey are non-canonical (ie invalid)
     */
    public PaymentChannelClientState(Wallet wallet, ECKey myKey, ECKey serverKey,
                                     Coin value, long expiryTimeInSeconds) throws VerificationException {
        this.stateMachine = new StateMachine<>(State.UNINITIALISED, getStateTransitions());
        this.wallet = checkNotNull(wallet);
        this.serverKey = checkNotNull(serverKey);
        this.myKey = checkNotNull(myKey);
        this.valueToMe = checkNotNull(value);
    }

    protected synchronized void initWalletListeners() {
        // Register a listener that watches out for the server closing the channel.
        if (storedChannel != null && storedChannel.close != null) {
            watchCloseConfirmations();
        }
        wallet.addCoinsReceivedEventListener(Threading.SAME_THREAD, new WalletCoinsReceivedEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                synchronized (PaymentChannelClientState.this) {
                    if (getContractInternal() == null) return;
                    if (isSettlementTransaction(tx)) {
                        log.info("Close: transaction {} closed contract {}", tx.getHash(), getContractInternal().getHash());
                        // Record the fact that it was closed along with the transaction that closed it.
                        stateMachine.transition(State.CLOSED);
                        if (storedChannel == null) return;
                        storedChannel.close = tx;
                        updateChannelInWallet();
                        watchCloseConfirmations();
                    }
                }
            }
        });
    }

    protected void watchCloseConfirmations() {
        // When we see the close transaction get enough confirmations, we can just delete the record
        // of this channel along with the refund tx from the wallet, because we're not going to need
        // any of that any more.
        final TransactionConfidence confidence = storedChannel.close.getConfidence();
        int numConfirms = Context.get().getEventHorizon();
        ListenableFuture<TransactionConfidence> future = confidence.getDepthFuture(numConfirms, Threading.SAME_THREAD);
        Futures.addCallback(future, new FutureCallback<TransactionConfidence>() {
            @Override
            public void onSuccess(TransactionConfidence result) {
                deleteChannelFromWallet();
            }

            @Override
            public void onFailure(Throwable t) {
                Throwables.propagate(t);
            }
        });
    }

    private synchronized void deleteChannelFromWallet() {
        log.info("Close tx has confirmed, deleting channel from wallet: {}", storedChannel);
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        channels.removeChannel(storedChannel);
        storedChannel = null;
    }

    public synchronized State getState() {
        return stateMachine.getState();
    }

    protected abstract Multimap<State, State> getStateTransitions();

    public abstract int getMajorVersion();

    /**
     * Creates the initial multisig contract and incomplete refund transaction which can be requested at the appropriate
     * time using {@link PaymentChannelV1ClientState#getIncompleteRefundTransaction} and
     * {@link PaymentChannelV1ClientState#getContract()}. The way the contract is crafted can be adjusted by
     * By default unconfirmed coins are allowed to be used, as for micropayments the risk should be relatively low.
     *
     * @throws ValueOutOfRangeException if the value being used is too small to be accepted by the network
     * @throws InsufficientMoneyException if the wallet doesn't contain enough balance to initiate
     */
    public void initiate() throws ValueOutOfRangeException, InsufficientMoneyException {
        initiate(null, PaymentChannelClient.defaultChannelProperties);
    }

    /**
     * Creates the initial multisig contract and incomplete refund transaction which can be requested at the appropriate
     * time using {@link PaymentChannelV1ClientState#getIncompleteRefundTransaction} and
     * {@link PaymentChannelClientState#getContract()}.
     * By default unconfirmed coins are allowed to be used, as for micropayments the risk should be relatively low.
     * @param userKey Key derived from a user password, needed for any signing when the wallet is encrypted.
     *                The wallet KeyCrypter is assumed.
     * @param clientChannelProperties Modify the channel's configuration.
     *
     * @throws ValueOutOfRangeException   if the value being used is too small to be accepted by the network
     * @throws InsufficientMoneyException if the wallet doesn't contain enough balance to initiate
     */
    public abstract void initiate(@Nullable KeyParameter userKey, ClientChannelProperties clientChannelProperties) throws ValueOutOfRangeException, InsufficientMoneyException;

    /**
     * Gets the contract which was used to initialize this channel
     */
    public abstract Transaction getContract();

    private synchronized Transaction makeUnsignedChannelContract(Coin valueToMe) throws ValueOutOfRangeException {
        Transaction tx = new Transaction(wallet.getParams());
        tx.addInput(getContractInternal().getOutput(0));
        // Our output always comes first.
        // TODO: We should drop myKey in favor of output key + multisig key separation
        // (as its always obvious who the client is based on T2 output order)
        tx.addOutput(valueToMe, LegacyAddress.fromKey(wallet.getParams(), myKey));
        return tx;
    }

    /**
     * Checks if the channel is expired, setting state to {@link State#EXPIRED}, removing this channel from wallet
     * storage and throwing an {@link IllegalStateException} if it is.
     */
    public synchronized void checkNotExpired() {
        if (Utils.currentTimeSeconds() > getExpiryTime()) {
            stateMachine.transition(State.EXPIRED);
            disconnectFromChannel();
            throw new IllegalStateException("Channel expired");
        }
    }

    /** Container for a signature and an amount that was sent. */
    public static class IncrementedPayment {
        public TransactionSignature signature;
        public Coin amount;
    }

    /**
     * <p>Updates the outputs on the payment contract transaction and re-signs it. The state must be READY in order to
     * call this method. The signature that is returned should be sent to the server so it has the ability to broadcast
     * the best seen payment when the channel closes or times out.</p>
     *
     * <p>The returned signature is over the payment transaction, which we never have a valid copy of and thus there
     * is no accessor for it on this object.</p>
     *
     * <p>To spend the whole channel increment by {@link PaymentChannelV1ClientState#getTotalValue()} -
     * {@link PaymentChannelV1ClientState#getValueRefunded()}</p>
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @throws ValueOutOfRangeException If size is negative or the channel does not have sufficient money in it to
     *                                  complete this payment.
     */
    public synchronized IncrementedPayment incrementPaymentBy(Coin size, @Nullable KeyParameter userKey)
            throws ValueOutOfRangeException {
        stateMachine.checkState(State.READY);
        checkNotExpired();
        checkNotNull(size);  // Validity of size will be checked by makeUnsignedChannelContract.
        if (size.signum() < 0)
            throw new ValueOutOfRangeException("Tried to decrement payment");
        Coin newValueToMe = getValueToMe().subtract(size);
        if (newValueToMe.compareTo(Transaction.MIN_NONDUST_OUTPUT) < 0 && newValueToMe.signum() > 0) {
            log.info("New value being sent back as change was smaller than minimum nondust output, sending all");
            size = getValueToMe();
            newValueToMe = Coin.ZERO;
        }
        if (newValueToMe.signum() < 0)
            throw new ValueOutOfRangeException("Channel has too little money to pay " + size + " satoshis");
        Transaction tx = makeUnsignedChannelContract(newValueToMe);
        log.info("Signing new payment tx {}", tx);
        Transaction.SigHash mode;
        // If we spent all the money we put into this channel, we (by definition) don't care what the outputs are, so
        // we sign with SIGHASH_NONE to let the server do what it wants.
        if (newValueToMe.equals(Coin.ZERO))
            mode = Transaction.SigHash.NONE;
        else
            mode = Transaction.SigHash.SINGLE;
        TransactionSignature sig = tx.calculateSignature(0, myKey.maybeDecrypt(userKey), getSignedScript(), mode, true);
        valueToMe = newValueToMe;
        updateChannelInWallet();
        IncrementedPayment payment = new IncrementedPayment();
        payment.signature = sig;
        payment.amount = size;
        return payment;
    }

    protected synchronized void updateChannelInWallet() {
        if (storedChannel == null)
            return;
        storedChannel.valueToMe = getValueToMe();
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        channels.updatedChannel(storedChannel);
    }

    /**
     * Sets this channel's state in {@link StoredPaymentChannelClientStates} to unopened so this channel can be reopened
     * later.
     *
     * @see PaymentChannelV1ClientState#storeChannelInWallet(Sha256Hash)
     */
    public synchronized void disconnectFromChannel() {
        if (storedChannel == null)
            return;
        synchronized (storedChannel) {
            storedChannel.active = false;
        }
    }

    /**
     * Skips saving state in the wallet for testing
     */
    @VisibleForTesting synchronized void fakeSave() {
        try {
            wallet.commitTx(getContractInternal());
        } catch (VerificationException e) {
            throw new RuntimeException(e); // We created it
        }
        stateMachine.transition(State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER);
    }

    @VisibleForTesting abstract void doStoreChannelInWallet(Sha256Hash id);

    /**
     * <p>Stores this channel's state in the wallet as a part of a {@link StoredPaymentChannelClientStates} wallet
     * extension and keeps it up-to-date each time payment is incremented. This allows the
     * {@link StoredPaymentChannelClientStates} object to keep track of timeouts and broadcast the refund transaction
     * when the channel expires.</p>
     *
     * <p>A channel may only be stored after it has fully opened (ie state == State.READY). The wallet provided in the
     * constructor must already have a {@link StoredPaymentChannelClientStates} object in its extensions set.</p>
     *
     * @param id A hash providing this channel with an id which uniquely identifies this server. It does not have to be
     *           unique.
     */
    public synchronized void storeChannelInWallet(Sha256Hash id) {
        stateMachine.checkState(State.SAVE_STATE_IN_WALLET);
        checkState(id != null);
        if (storedChannel != null) {
            checkState(storedChannel.id.equals(id));
            return;
        }
        doStoreChannelInWallet(id);

        try {
            wallet.commitTx(getContractInternal());
        } catch (VerificationException e) {
            throw new RuntimeException(e); // We created it
        }
        stateMachine.transition(State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER);
    }

    /**
     * Returns the fees that will be paid if the refund transaction has to be claimed because the server failed to settle
     * the channel properly. May only be called after {@link PaymentChannelClientState#initiate(KeyParameter, IPaymentChannelClient.ClientChannelProperties)}
     */
    public abstract Coin getRefundTxFees();

    @VisibleForTesting abstract Transaction getRefundTransaction();

    /**
     * Gets the total value of this channel (ie the maximum payment possible)
     */
    public abstract Coin getTotalValue();

    /**
     * Gets the current amount refunded to us from the multisig contract (ie totalValue-valueSentToServer)
     */
    public synchronized Coin getValueRefunded() {
        stateMachine.checkState(State.READY);
        return valueToMe;
    }

    /**
     * Returns the amount of money sent on this channel so far.
     */
    public synchronized Coin getValueSpent() {
        return getTotalValue().subtract(getValueRefunded());
    }

    protected abstract Coin getValueToMe();

    protected abstract long getExpiryTime();

    /**
     * Gets the contract without changing the state machine
     * @return the contract.
     */
    protected abstract Transaction getContractInternal();

    protected abstract Script getContractScript();

    /**
     * Gets the script that is signed. In the case of a P2SH contract this is the
     * script inside the P2SH script.
     * @return the signed script.
     */
    protected abstract Script getSignedScript();
}
