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

package com.google.bitcoin.protocols.channels;

import com.google.bitcoin.core.*;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.utils.Threading;
import com.google.bitcoin.wallet.AllowUnconfirmedCoinSelector;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Throwables;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.List;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A payment channel is a method of sending money to someone such that the amount of money you send can be adjusted
 * after the fact, in an efficient manner that does not require broadcasting to the network. This can be used to
 * implement micropayments or other payment schemes in which immediate settlement is not required, but zero trust
 * negotiation is. Note that this class only allows the amount of money sent to be incremented, not decremented.</p>
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
 * <p>To begin, the client calls {@link PaymentChannelClientState#initiate()}, which moves the channel into state
 * INITIATED and creates the initial multi-sig contract and refund transaction. If the wallet has insufficient funds an
 * exception will be thrown at this point. Once this is done, call
 * {@link PaymentChannelClientState#getIncompleteRefundTransaction()} and pass the resultant transaction through to the
 * server. Once you have retrieved the signature, use {@link PaymentChannelClientState#provideRefundSignature(byte[])}.
 * You must then call {@link PaymentChannelClientState#storeChannelInWallet(Sha256Hash)} to store the refund transaction
 * in the wallet, protecting you against a malicious server attempting to destroy all your coins. At this point, you can
 * provide the server with the multi-sig contract (via {@link PaymentChannelClientState#getMultisigContract()}) safely.
 * </p>
 */
public class PaymentChannelClientState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelClientState.class);
    private static final int CONFIRMATIONS_FOR_DELETE = 3;

    private final Wallet wallet;
    // Both sides need a key (private in our case, public for the server) in order to manage the multisig contract
    // and transactions that spend it.
    private final ECKey myKey, serverMultisigKey;
    // How much value (in satoshis) is locked up into the channel.
    private final BigInteger totalValue;
    // When the channel will automatically settle in favor of the client, if the server halts before protocol termination
    // specified in terms of block timestamps (so it can off real time by a few hours).
    private final long expiryTime;

    // The refund is a time locked transaction that spends all the money of the channel back to the client.
    private Transaction refundTx;
    private BigInteger refundFees;
    // The multi-sig contract locks the value of the channel up such that the agreement of both parties is required
    // to spend it.
    private Transaction multisigContract;
    private Script multisigScript;
    // How much value is currently allocated to us. Starts as being same as totalValue.
    private BigInteger valueToMe;

    /**
     * The different logical states the channel can be in. The channel starts out as NEW, and then steps through the
     * states until it becomes finalized. The server should have already been contacted and asked for a public key
     * by the time the NEW state is reached.
     */
    public enum State {
        NEW,
        INITIATED,
        WAITING_FOR_SIGNED_REFUND,
        SAVE_STATE_IN_WALLET,
        PROVIDE_MULTISIG_CONTRACT_TO_SERVER,
        READY,
        EXPIRED,
        CLOSED
    }
    private State state;

    // The id of this channel in the StoredPaymentChannelClientStates, or null if it is not stored
    private StoredClientChannel storedChannel;

    PaymentChannelClientState(StoredClientChannel storedClientChannel, Wallet wallet) throws VerificationException {
        // The PaymentChannelClientConnection handles storedClientChannel.active and ensures we aren't resuming channels
        this.wallet = checkNotNull(wallet);
        this.multisigContract = checkNotNull(storedClientChannel.contract);
        this.multisigScript = multisigContract.getOutput(0).getScriptPubKey();
        this.refundTx = checkNotNull(storedClientChannel.refund);
        this.refundFees = checkNotNull(storedClientChannel.refundFees);
        this.expiryTime = refundTx.getLockTime();
        this.myKey = checkNotNull(storedClientChannel.myKey);
        this.serverMultisigKey = null;
        this.totalValue = multisigContract.getOutput(0).getValue();
        this.valueToMe = checkNotNull(storedClientChannel.valueToMe);
        this.storedChannel = storedClientChannel;
        this.state = State.READY;
        initWalletListeners();
    }

    /**
     * Returns true if the tx is a valid settlement transaction.
     */
    public synchronized boolean isSettlementTransaction(Transaction tx) {
        try {
            tx.verify();
            tx.getInput(0).verify(multisigContract.getOutput(0));
            return true;
        } catch (VerificationException e) {
            return false;
        }
    }

    /**
     * Creates a state object for a payment channel client. It is expected that you be ready to
     * {@link PaymentChannelClientState#initiate()} after construction (to avoid creating objects for channels which are
     * not going to finish opening) and thus some parameters provided here are only used in
     * {@link PaymentChannelClientState#initiate()} to create the Multisig contract and refund transaction.
     *
     * @param wallet a wallet that contains at least the specified amount of value.
     * @param myKey a freshly generated private key for this channel.
     * @param serverMultisigKey a public key retrieved from the server used for the initial multisig contract
     * @param value how many satoshis to put into this contract. If the channel reaches this limit, it must be closed.
     *              It is suggested you use at least {@link Utils#CENT} to avoid paying fees if you need to spend the refund transaction
     * @param expiryTimeInSeconds At what point (UNIX timestamp +/- a few hours) the channel will expire
     *
     * @throws VerificationException If either myKey's pubkey or serverMultisigKey's pubkey are non-canonical (ie invalid)
     */
    public PaymentChannelClientState(Wallet wallet, ECKey myKey, ECKey serverMultisigKey,
                                     BigInteger value, long expiryTimeInSeconds) throws VerificationException {
        checkArgument(value.compareTo(BigInteger.ZERO) > 0);
        this.wallet = checkNotNull(wallet);
        initWalletListeners();
        this.serverMultisigKey = checkNotNull(serverMultisigKey);
        if (!myKey.isPubKeyCanonical() || !serverMultisigKey.isPubKeyCanonical())
            throw new VerificationException("Pubkey was not canonical (ie non-standard)");
        this.myKey = checkNotNull(myKey);
        this.valueToMe = this.totalValue = checkNotNull(value);
        this.expiryTime = expiryTimeInSeconds;
        this.state = State.NEW;
    }

    private synchronized void initWalletListeners() {
        // Register a listener that watches out for the server closing the channel.
        if (storedChannel != null && storedChannel.close != null) {
            watchCloseConfirmations();
        }
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                synchronized (PaymentChannelClientState.this) {
                    if (multisigContract == null) return;
                    if (isSettlementTransaction(tx)) {
                        log.info("Close: transaction {} closed contract {}", tx.getHash(), multisigContract.getHash());
                        // Record the fact that it was closed along with the transaction that closed it.
                        state = State.CLOSED;
                        if (storedChannel == null) return;
                        storedChannel.close = tx;
                        updateChannelInWallet();
                        watchCloseConfirmations();
                    }
                }
            }
        }, Threading.SAME_THREAD);
    }

    private void watchCloseConfirmations() {
        // When we see the close transaction get a few confirmations, we can just delete the record
        // of this channel along with the refund tx from the wallet, because we're not going to need
        // any of that any more.
        final TransactionConfidence confidence = storedChannel.close.getConfidence();
        ListenableFuture<Transaction> future = confidence.getDepthFuture(CONFIRMATIONS_FOR_DELETE, Threading.SAME_THREAD);
        Futures.addCallback(future, new FutureCallback<Transaction>() {
            @Override
            public void onSuccess(Transaction result) {
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
        wallet.addOrUpdateExtension(channels);
        storedChannel = null;
    }

    /**
     * This object implements a state machine, and this accessor returns which state it's currently in.
     */
    public synchronized State getState() {
        return state;
    }

    /**
     * Creates the initial multisig contract and incomplete refund transaction which can be requested at the appropriate
     * time using {@link PaymentChannelClientState#getIncompleteRefundTransaction} and
     * {@link PaymentChannelClientState#getMultisigContract()}. The way the contract is crafted can be adjusted by
     * overriding {@link PaymentChannelClientState#editContractSendRequest(com.google.bitcoin.core.Wallet.SendRequest)}.
     * By default unconfirmed coins are allowed to be used, as for micropayments the risk should be relatively low.
     *
     * @throws ValueOutOfRangeException if the value being used is too small to be accepted by the network
     * @throws InsufficientMoneyException if the wallet doesn't contain enough balance to initiate
     */
    public synchronized void initiate() throws ValueOutOfRangeException, InsufficientMoneyException {
        final NetworkParameters params = wallet.getParams();
        Transaction template = new Transaction(params);
        // We always place the client key before the server key because, if either side wants some privacy, they can
        // use a fresh key for the the multisig contract and nowhere else
        List<ECKey> keys = Lists.newArrayList(myKey, serverMultisigKey);
        // There is also probably a change output, but we don't bother shuffling them as it's obvious from the
        // format which one is the change. If we start obfuscating the change output better in future this may
        // be worth revisiting.
        TransactionOutput multisigOutput = template.addOutput(totalValue, ScriptBuilder.createMultiSigOutputScript(2, keys));
        if (multisigOutput.getMinNonDustValue().compareTo(totalValue) > 0)
            throw new ValueOutOfRangeException("totalValue too small to use");
        Wallet.SendRequest req = Wallet.SendRequest.forTx(template);
        req.coinSelector = AllowUnconfirmedCoinSelector.get();
        editContractSendRequest(req);
        wallet.completeTx(req);
        BigInteger multisigFee = req.fee;
        multisigContract = req.tx;
        // Build a refund transaction that protects us in the case of a bad server that's just trying to cause havoc
        // by locking up peoples money (perhaps as a precursor to a ransom attempt). We time lock it so the server
        // has an assurance that we cannot take back our money by claiming a refund before the channel closes - this
        // relies on the fact that since Bitcoin 0.8 time locked transactions are non-final. This will need to change
        // in future as it breaks the intended design of timelocking/tx replacement, but for now it simplifies this
        // specific protocol somewhat.
        refundTx = new Transaction(params);
        refundTx.addInput(multisigOutput).setSequenceNumber(0);   // Allow replacement when it's eventually reactivated.
        refundTx.setLockTime(expiryTime);
        if (totalValue.compareTo(Utils.CENT) < 0) {
            // Must pay min fee.
            final BigInteger valueAfterFee = totalValue.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
            if (Transaction.MIN_NONDUST_OUTPUT.compareTo(valueAfterFee) > 0)
                throw new ValueOutOfRangeException("totalValue too small to use");
            refundTx.addOutput(valueAfterFee, myKey.toAddress(params));
            refundFees = multisigFee.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
        } else {
            refundTx.addOutput(totalValue, myKey.toAddress(params));
            refundFees = multisigFee;
        }
        refundTx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        log.info("initiated channel with multi-sig contract {}, refund {}", multisigContract.getHashAsString(),
                refundTx.getHashAsString());
        state = State.INITIATED;
        // Client should now call getIncompleteRefundTransaction() and send it to the server.
    }

    /**
     * You can override this method in order to control the construction of the initial contract that creates the
     * channel. For example if you want it to only use specific coins, you can adjust the coin selector here.
     * The default implementation does nothing.
     */
    protected void editContractSendRequest(Wallet.SendRequest req) {
    }

    /**
     * Returns the transaction that locks the money to the agreement of both parties. Do not mutate the result.
     * Once this step is done, you can use {@link PaymentChannelClientState#incrementPaymentBy(java.math.BigInteger)} to
     * start paying the server.
     */
    public synchronized Transaction getMultisigContract() {
        checkState(multisigContract != null);
        if (state == State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER)
            state = State.READY;
        return multisigContract;
    }

    /**
     * Returns a partially signed (invalid) refund transaction that should be passed to the server. Once the server
     * has checked it out and provided its own signature, call
     * {@link PaymentChannelClientState#provideRefundSignature(byte[])} with the result.
     */
    public synchronized Transaction getIncompleteRefundTransaction() {
        checkState(refundTx != null);
        if (state == State.INITIATED)
            state = State.WAITING_FOR_SIGNED_REFUND;
        return refundTx;
    }

    /**
     * <p>When the servers signature for the refund transaction is received, call this to verify it and sign the
     * complete refund ourselves.</p>
     *
     * <p>If this does not throw an exception, we are secure against the loss of funds and can safely provide the server
     * with the multi-sig contract to lock in the agreement. In this case, both the multisig contract and the refund
     * transaction are automatically committed to wallet so that it can handle broadcasting the refund transaction at
     * the appropriate time if necessary.</p>
     */
    public synchronized void provideRefundSignature(byte[] theirSignature) throws VerificationException {
        checkNotNull(theirSignature);
        checkState(state == State.WAITING_FOR_SIGNED_REFUND);
        TransactionSignature theirSig = TransactionSignature.decodeFromBitcoin(theirSignature, true);
        if (theirSig.sigHashMode() != Transaction.SigHash.NONE || !theirSig.anyoneCanPay())
            throw new VerificationException("Refund signature was not SIGHASH_NONE|SIGHASH_ANYONECANPAY");
        // Sign the refund transaction ourselves.
        final TransactionOutput multisigContractOutput = multisigContract.getOutput(0);
        try {
            multisigScript = multisigContractOutput.getScriptPubKey();
        } catch (ScriptException e) {
            throw new RuntimeException(e);  // Cannot happen: we built this ourselves.
        }
        TransactionSignature ourSignature =
                refundTx.calculateSignature(0, myKey, multisigScript, Transaction.SigHash.ALL, false);
        // Insert the signatures.
        Script scriptSig = ScriptBuilder.createMultiSigInputScript(ourSignature, theirSig);
        log.info("Refund scriptSig: {}", scriptSig);
        log.info("Multi-sig contract scriptPubKey: {}", multisigScript);
        TransactionInput refundInput = refundTx.getInput(0);
        refundInput.setScriptSig(scriptSig);
        refundInput.verify(multisigContractOutput);
        state = State.SAVE_STATE_IN_WALLET;
    }

    private synchronized Transaction makeUnsignedChannelContract(BigInteger valueToMe) throws ValueOutOfRangeException {
        Transaction tx = new Transaction(wallet.getParams());
        tx.addInput(multisigContract.getOutput(0));
        // Our output always comes first.
        // TODO: We should drop myKey in favor of output key + multisig key separation
        // (as its always obvious who the client is based on T2 output order)
        tx.addOutput(valueToMe, myKey.toAddress(wallet.getParams()));
        return tx;
    }

    /**
     * Checks if the channel is expired, setting state to {@link State#EXPIRED}, removing this channel from wallet
     * storage and throwing an {@link IllegalStateException} if it is.
     */
    public synchronized void checkNotExpired() {
        if (Utils.currentTimeMillis()/1000 > expiryTime) {
            state = State.EXPIRED;
            disconnectFromChannel();
            throw new IllegalStateException("Channel expired");
        }
    }

    /** Container for a signature and an amount that was sent. */
    public static class IncrementedPayment {
        public TransactionSignature signature;
        public BigInteger amount;
    }

    /**
     * <p>Updates the outputs on the payment contract transaction and re-signs it. The state must be READY in order to
     * call this method. The signature that is returned should be sent to the server so it has the ability to broadcast
     * the best seen payment when the channel closes or times out.</p>
     *
     * <p>The returned signature is over the payment transaction, which we never have a valid copy of and thus there
     * is no accessor for it on this object.</p>
     *
     * <p>To spend the whole channel increment by {@link PaymentChannelClientState#getTotalValue()} -
     * {@link PaymentChannelClientState#getValueRefunded()}</p>
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @throws ValueOutOfRangeException If size is negative or the channel does not have sufficient money in it to
     *                                  complete this payment.
     */
    public synchronized IncrementedPayment incrementPaymentBy(BigInteger size) throws ValueOutOfRangeException {
        checkState(state == State.READY);
        checkNotExpired();
        checkNotNull(size);  // Validity of size will be checked by makeUnsignedChannelContract.
        if (size.compareTo(BigInteger.ZERO) < 0)
            throw new ValueOutOfRangeException("Tried to decrement payment");
        BigInteger newValueToMe = valueToMe.subtract(size);
        if (newValueToMe.compareTo(Transaction.MIN_NONDUST_OUTPUT) < 0 && newValueToMe.compareTo(BigInteger.ZERO) > 0) {
            log.info("New value being sent back as change was smaller than minimum nondust output, sending all");
            size = valueToMe;
            newValueToMe = BigInteger.ZERO;
        }
        if (newValueToMe.compareTo(BigInteger.ZERO) < 0)
            throw new ValueOutOfRangeException("Channel has too little money to pay " + size + " satoshis");
        Transaction tx = makeUnsignedChannelContract(newValueToMe);
        log.info("Signing new payment tx {}", tx);
        Transaction.SigHash mode;
        // If we spent all the money we put into this channel, we (by definition) don't care what the outputs are, so
        // we sign with SIGHASH_NONE to let the server do what it wants.
        if (newValueToMe.equals(BigInteger.ZERO))
            mode = Transaction.SigHash.NONE;
        else
            mode = Transaction.SigHash.SINGLE;
        TransactionSignature sig = tx.calculateSignature(0, myKey, multisigScript, mode, true);
        valueToMe = newValueToMe;
        updateChannelInWallet();
        IncrementedPayment payment = new IncrementedPayment();
        payment.signature = sig;
        payment.amount = size;
        return payment;
    }

    private synchronized void updateChannelInWallet() {
        if (storedChannel == null)
            return;
        storedChannel.valueToMe = valueToMe;
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        wallet.addOrUpdateExtension(channels);
    }

    /**
     * Sets this channel's state in {@link StoredPaymentChannelClientStates} to unopened so this channel can be reopened
     * later.
     *
     * @see PaymentChannelClientState#storeChannelInWallet(Sha256Hash)
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
            wallet.commitTx(multisigContract);
        } catch (VerificationException e) {
            throw new RuntimeException(e); // We created it
        }
        state = State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER;
    }

    @VisibleForTesting synchronized void doStoreChannelInWallet(Sha256Hash id) {
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        checkNotNull(channels, "You have not added the StoredPaymentChannelClientStates extension to the wallet.");
        checkState(channels.getChannel(id, multisigContract.getHash()) == null);
        storedChannel = new StoredClientChannel(id, multisigContract, refundTx, myKey, valueToMe, refundFees, true);
        channels.putChannel(storedChannel);
        wallet.addOrUpdateExtension(channels);
    }

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
        checkState(state == State.SAVE_STATE_IN_WALLET && id != null);
        if (storedChannel != null) {
            checkState(storedChannel.id.equals(id));
            return;
        }
        doStoreChannelInWallet(id);

        try {
            wallet.commitTx(multisigContract);
        } catch (VerificationException e) {
            throw new RuntimeException(e); // We created it
        }
        state = State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER;
    }

    /**
     * Returns the fees that will be paid if the refund transaction has to be claimed because the server failed to settle
     * the channel properly. May only be called after {@link PaymentChannelClientState#initiate()}
     */
    public synchronized BigInteger getRefundTxFees() {
        checkState(state.compareTo(State.NEW) > 0);
        return refundFees;
    }

    /**
     * Once the servers signature over the refund transaction has been received and provided using
     * {@link PaymentChannelClientState#provideRefundSignature(byte[])} then this
     * method can be called to receive the now valid and broadcastable refund transaction.
     */
    public synchronized Transaction getCompletedRefundTransaction() {
        checkState(state.compareTo(State.WAITING_FOR_SIGNED_REFUND) > 0);
        return refundTx;
    }

    /**
     * Gets the total value of this channel (ie the maximum payment possible)
     */
    public BigInteger getTotalValue() {
        return totalValue;
    }

    /**
     * Gets the current amount refunded to us from the multisig contract (ie totalValue-valueSentToServer)
     */
    public synchronized BigInteger getValueRefunded() {
        checkState(state == State.READY);
        return valueToMe;
    }

    /**
     * Returns the amount of money sent on this channel so far.
     */
    public synchronized BigInteger getValueSpent() {
        return getTotalValue().subtract(getValueRefunded());
    }
}
