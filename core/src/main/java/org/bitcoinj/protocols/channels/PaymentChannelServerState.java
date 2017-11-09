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

import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Multimap;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A payment channel is a method of sending money to someone such that the amount of money you send can be adjusted
 * after the fact, in an efficient manner that does not require broadcasting to the network. This can be used to
 * implement micropayments or other payment schemes in which immediate settlement is not required, but zero trust
 * negotiation is. Note that this class only allows the amount of money received to be incremented, not decremented.</p>
 *
 * <p>There are two subclasses that implement this one, for versions 1 and 2 of the protocol -
 * {@link PaymentChannelV1ServerState} and {@link PaymentChannelV2ServerState}.</p>
 *
 * <p>This class implements the core state machine for the server side of the protocol. The client side is implemented
 * by {@link PaymentChannelV1ClientState} and {@link PaymentChannelServerListener} implements the server-side network
 * protocol listening for TCP/IP connections and moving this class through each state. We say that the party who is
 * sending funds is the <i>client</i> or <i>initiating party</i>. The party that is receiving the funds is the
 * <i>server</i> or <i>receiving party</i>. Although the underlying Bitcoin protocol is capable of more complex
 * relationships than that, this class implements only the simplest case.</p>
 *
 * <p>To protect clients from malicious servers, a channel has an expiry parameter. When this expiration is reached, the
 * client will broadcast the created refund  transaction and take back all the money in this channel. Because this is
 * specified in terms of block timestamps, it is fairly fuzzy and it is possible to spend the refund transaction up to a
 * few hours before the actual timestamp. Thus, it is very important that the channel be closed with plenty of time left
 * to get the highest value payment transaction confirmed before the expire time (minimum 3-4 hours is suggested if the
 * payment transaction has enough fee to be confirmed in the next block or two).</p>
 *
 * <p>To begin, we must provide the client with a pubkey which we wish to use for the multi-sig contract which locks in
 * the channel. The client will then provide us with an incomplete refund transaction and the pubkey which they used in
 * the multi-sig contract. We use this pubkey to recreate the multi-sig output and then sign that to the refund
 * transaction. We provide that signature to the client and they then have the ability to spend the refund transaction
 * at the specified expire time. The client then provides us with the full, signed multi-sig contract which we verify
 * and broadcast, locking in their funds until we spend a payment transaction or the expire time is reached. The client
 * can then begin paying by providing us with signatures for the multi-sig contract which pay some amount back to the
 * client, and the rest is ours to do with as we wish.</p>
 */
public abstract class PaymentChannelServerState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelServerState.class);

    /**
     * The different logical states the channel can be in. Because the first action we need to track is the client
     * providing the refund transaction, we begin in WAITING_FOR_REFUND_TRANSACTION. We then step through the states
     * until READY, at which time the client can increase payment incrementally.
     */
    public enum State {
        UNINITIALISED,
        WAITING_FOR_REFUND_TRANSACTION,
        WAITING_FOR_MULTISIG_CONTRACT,
        WAITING_FOR_MULTISIG_ACCEPTANCE,
        READY,
        CLOSING,
        CLOSED,
        ERROR,
    }

    protected StateMachine<State> stateMachine;

    // Package-local for checkArguments in StoredServerChannel
    final Wallet wallet;

    // The object that will broadcast transactions for us - usually a peer group.
    protected final TransactionBroadcaster broadcaster;

    // The last signature the client provided for a payment transaction.
    protected byte[] bestValueSignature;

    protected Coin bestValueToMe = Coin.ZERO;

    // The server key for the multi-sig contract
    // We currently also use the serverKey for payouts, but this is not required
    protected ECKey serverKey;

    protected long minExpireTime;

    protected StoredServerChannel storedServerChannel = null;

    // The contract and the output script from it
    protected Transaction contract = null;

    PaymentChannelServerState(StoredServerChannel storedServerChannel, Wallet wallet, TransactionBroadcaster broadcaster) throws VerificationException {
        synchronized (storedServerChannel) {
            this.stateMachine = new StateMachine<>(State.UNINITIALISED, getStateTransitions());
            this.wallet = checkNotNull(wallet);
            this.broadcaster = checkNotNull(broadcaster);
            this.contract = checkNotNull(storedServerChannel.contract);
            this.serverKey = checkNotNull(storedServerChannel.myKey);
            this.storedServerChannel = storedServerChannel;
            this.bestValueToMe = checkNotNull(storedServerChannel.bestValueToMe);
            this.minExpireTime = storedServerChannel.refundTransactionUnlockTimeSecs;
            this.bestValueSignature = storedServerChannel.bestValueSignature;
            checkArgument(bestValueToMe.equals(Coin.ZERO) || bestValueSignature != null);
            storedServerChannel.state = this;
        }
    }

    /**
     * Creates a new state object to track the server side of a payment channel.
     *
     * @param broadcaster The peer group which we will broadcast transactions to, this should have multiple peers
     * @param wallet The wallet which will be used to complete transactions
     * @param serverKey The private key which we use for our part of the multi-sig contract
     *                  (this MUST be fresh and CANNOT be used elsewhere)
     * @param minExpireTime The earliest time at which the client can claim the refund transaction (UNIX timestamp of block)
     */
    public PaymentChannelServerState(TransactionBroadcaster broadcaster, Wallet wallet, ECKey serverKey, long minExpireTime) {
        this.stateMachine = new StateMachine<>(State.UNINITIALISED, getStateTransitions());
        this.serverKey = checkNotNull(serverKey);
        this.wallet = checkNotNull(wallet);
        this.broadcaster = checkNotNull(broadcaster);
        this.minExpireTime = minExpireTime;
    }

    public abstract int getMajorVersion();

    public synchronized State getState() {
        return stateMachine.getState();
    }

    protected abstract Multimap<State, State> getStateTransitions();

    /**
     * Called when the client provides the multi-sig contract.  Checks that the previously-provided refund transaction
     * spends this transaction (because we will use it as a base to create payment transactions) as well as output value
     * and form (ie it is a 2-of-2 multisig to the correct keys).
     *
     * @param contract The provided multisig contract. Do not mutate this object after this call.
     * @return A future which completes when the provided multisig contract successfully broadcasts, or throws if the broadcast fails for some reason
     *         Note that if the network simply rejects the transaction, this future will never complete, a timeout should be used.
     * @throws VerificationException If the provided multisig contract is not well-formed or does not meet previously-specified parameters
     */
    public synchronized ListenableFuture<PaymentChannelServerState> provideContract(final Transaction contract) throws VerificationException {
        checkNotNull(contract);
        stateMachine.checkState(State.WAITING_FOR_MULTISIG_CONTRACT);
        try {
            contract.verify();
            this.contract = contract;
            verifyContract(contract);

            // Check that contract's first output is a 2-of-2 multisig to the correct pubkeys in the correct order
            final Script expectedScript = createOutputScript();
            if (!Arrays.equals(getContractScript().getProgram(), expectedScript.getProgram()))
                throw new VerificationException(getMajorVersion() == 1 ?
                        "Contract's first output was not a standard 2-of-2 multisig to client and server in that order." :
                        "Contract was not a P2SH script of a CLTV redeem script to client and server");

            if (getTotalValue().signum() <= 0)
                throw new VerificationException("Not accepting an attempt to open a contract with zero value.");
        } catch (VerificationException e) {
            // We couldn't parse the multisig transaction or its output.
            log.error("Provided multisig contract did not verify: {}", contract.toString());
            throw e;
        }
        log.info("Broadcasting multisig contract: {}", contract);
        wallet.addWatchedScripts(ImmutableList.of(contract.getOutput(0).getScriptPubKey()));
        stateMachine.transition(State.WAITING_FOR_MULTISIG_ACCEPTANCE);
        final SettableFuture<PaymentChannelServerState> future = SettableFuture.create();
        Futures.addCallback(broadcaster.broadcastTransaction(contract).future(), new FutureCallback<Transaction>() {
            @Override public void onSuccess(Transaction transaction) {
                log.info("Successfully broadcast multisig contract {}. Channel now open.", transaction.getHashAsString());
                try {
                    // Manually add the contract to the wallet, overriding the isRelevant checks so we can track
                    // it and check for double-spends later
                    wallet.receivePending(contract, null, true);
                } catch (VerificationException e) {
                    throw new RuntimeException(e); // Cannot happen, we already called contract.verify()
                }
                stateMachine.transition(State.READY);
                future.set(PaymentChannelServerState.this);
            }

            @Override public void onFailure(Throwable throwable) {
                // Couldn't broadcast the transaction for some reason.
                log.error("Failed to broadcast contract", throwable);
                stateMachine.transition(State.ERROR);
                future.setException(throwable);
            }
        });
        return future;
    }

    // Create a payment transaction with valueToMe going back to us
    protected synchronized SendRequest makeUnsignedChannelContract(Coin valueToMe) {
        Transaction tx = new Transaction(wallet.getParams());
        if (!getTotalValue().subtract(valueToMe).equals(Coin.ZERO)) {
            tx.addOutput(getTotalValue().subtract(valueToMe), getClientKey().toAddress(wallet.getParams()));
        }
        tx.addInput(contract.getOutput(0));
        return SendRequest.forTx(tx);
    }

    /**
     * Called when the client provides us with a new signature and wishes to increment total payment by size.		+
     * Verifies the provided signature and only updates values if everything checks out.
     * If the new refundSize is not the lowest we have seen, it is simply ignored.
     *
     * @param refundSize How many satoshis of the original contract are refunded to the client (the rest are ours)
     * @param signatureBytes The new signature spending the multi-sig contract to a new payment transaction
     * @throws VerificationException If the signature does not verify or size is out of range (incl being rejected by the network as dust).
     * @return true if there is more value left on the channel, false if it is now fully used up.
     */
    public synchronized boolean incrementPayment(Coin refundSize, byte[] signatureBytes) throws VerificationException, ValueOutOfRangeException, InsufficientMoneyException {
        stateMachine.checkState(State.READY);
        checkNotNull(refundSize);
        checkNotNull(signatureBytes);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(signatureBytes, true);
        // We allow snapping to zero for the payment amount because it's treated specially later, but not less than
        // the dust level because that would prevent the transaction from being relayed/mined.
        final boolean fullyUsedUp = refundSize.equals(Coin.ZERO);
        Coin newValueToMe = getTotalValue().subtract(refundSize);
        if (newValueToMe.signum() < 0)
            throw new ValueOutOfRangeException("Attempt to refund more than the contract allows.");
        if (newValueToMe.compareTo(bestValueToMe) < 0)
            throw new ValueOutOfRangeException("Attempt to roll back payment on the channel.");

        SendRequest req = makeUnsignedChannelContract(newValueToMe);

        if (!fullyUsedUp && refundSize.isLessThan(req.tx.getOutput(0).getMinNonDustValue()))
            throw new ValueOutOfRangeException("Attempt to refund negative value or value too small to be accepted by the network");

        // Get the wallet's copy of the contract (ie with confidence information), if this is null, the wallet
        // was not connected to the peergroup when the contract was broadcast (which may cause issues down the road, and
        // disables our double-spend check next)
        Transaction walletContract = wallet.getTransaction(contract.getHash());
        checkNotNull(walletContract, "Wallet did not contain multisig contract {} after state was marked READY", contract.getHash());

        // Note that we check for DEAD state here, but this test is essentially useless in production because we will
        // miss most double-spends due to bloom filtering right now anyway. This will eventually fixed by network-wide
        // double-spend notifications, so we just wait instead of attempting to add all dependant outpoints to our bloom
        // filters (and probably missing lots of edge-cases).
        if (walletContract.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.DEAD) {
            close();
            throw new VerificationException("Multisig contract was double-spent");
        }

        Transaction.SigHash mode;
        // If the client doesn't want anything back, they shouldn't sign any outputs at all.
        if (fullyUsedUp)
            mode = Transaction.SigHash.NONE;
        else
            mode = Transaction.SigHash.SINGLE;

        if (signature.sigHashMode() != mode || !signature.anyoneCanPay())
            throw new VerificationException("New payment signature was not signed with the right SIGHASH flags.");

        // Now check the signature is correct.
        // Note that the client must sign with SIGHASH_{SINGLE/NONE} | SIGHASH_ANYONECANPAY to allow us to add additional
        // inputs (in case we need to add significant fee, or something...) and any outputs we want to pay to.
        Sha256Hash sighash = req.tx.hashForSignature(0, getSignedScript(), mode, true);

        if (!getClientKey().verify(sighash, signature))
            throw new VerificationException("Signature does not verify on tx\n" + req.tx);
        bestValueToMe = newValueToMe;
        bestValueSignature = signatureBytes;
        updateChannelInWallet();
        return !fullyUsedUp;
    }

    /**
     * <p>Closes this channel and broadcasts the highest value payment transaction on the network.</p>
     *
     * @return a future which completes when the provided multisig contract successfully broadcasts, or throws if the
     *         broadcast fails for some reason. Note that if the network simply rejects the transaction, this future
     *         will never complete, a timeout should be used.
     * @throws InsufficientMoneyException If the payment tx would have cost more in fees to spend than it is worth.
     */
    public ListenableFuture<Transaction> close() throws InsufficientMoneyException {
        return close(null);
    }

    /**
     * <p>Closes this channel and broadcasts the highest value payment transaction on the network.</p>
     *
     * @param userKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @return a future which completes when the provided multisig contract successfully broadcasts, or throws if the
     *         broadcast fails for some reason. Note that if the network simply rejects the transaction, this future
     *         will never complete, a timeout should be used.
     * @throws InsufficientMoneyException If the payment tx would have cost more in fees to spend than it is worth.
     */
    public abstract ListenableFuture<Transaction> close(@Nullable KeyParameter userKey) throws InsufficientMoneyException;

    /**
     * Gets the highest payment to ourselves (which we will receive on settle(), not including fees)
     */
    public synchronized Coin getBestValueToMe() {
        return bestValueToMe;
    }

    /**
     * Gets the fee paid in the final payment transaction (only available if settle() did not throw an exception)
     */
    public abstract Coin getFeePaid();

    /**
     * Gets the multisig contract which was used to initialize this channel
     */
    public synchronized Transaction getContract() {
        checkState(contract != null);
        return contract;
    }

    public long getExpiryTime() {
        return minExpireTime;
    }

    protected synchronized void updateChannelInWallet() {
        if (storedServerChannel != null) {
            storedServerChannel.updateValueToMe(bestValueToMe, bestValueSignature);
            StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                    wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
            channels.updatedChannel(storedServerChannel);
        }
    }

    /**
     * Stores this channel's state in the wallet as a part of a {@link StoredPaymentChannelServerStates} wallet
     * extension and keeps it up-to-date each time payment is incremented. This will be automatically removed when
     * a call to {@link PaymentChannelV1ServerState#close()} completes successfully. A channel may only be stored after it
     * has fully opened (ie state == State.READY).
     *
     * @param connectedHandler Optional {@link PaymentChannelServer} object that manages this object. This will
     *                         set the appropriate pointer in the newly created {@link StoredServerChannel} before it is
     *                         committed to wallet. If set, closing the state object will propagate the close to the
     *                         handler which can then do a TCP disconnect.
     */
    public synchronized void storeChannelInWallet(@Nullable PaymentChannelServer connectedHandler) {
        stateMachine.checkState(State.READY);
        if (storedServerChannel != null)
            return;

        log.info("Storing state with contract hash {}.", getContract().getHash());
        StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                wallet.addOrGetExistingExtension(new StoredPaymentChannelServerStates(wallet, broadcaster));
        storedServerChannel = new StoredServerChannel(this, getMajorVersion(), getContract(), getClientOutput(), getExpiryTime(), serverKey, getClientKey(), bestValueToMe, bestValueSignature);
        if (connectedHandler != null)
            checkState(storedServerChannel.setConnectedHandler(connectedHandler, false) == connectedHandler);
        channels.putChannel(storedServerChannel);
    }

    public abstract TransactionOutput getClientOutput();

    public Script getContractScript() {
        if (contract == null) {
            return null;
        }
        return contract.getOutput(0).getScriptPubKey();
    }

    /**
     * Gets the script that signatures should sign against. This is never a P2SH
     * script, rather the script that would be inside a P2SH script.
     * @return the script that signatures should sign against.
     */
    protected abstract Script getSignedScript();

    /**
     * Verifies that the given contract meets a set of extra requirements
     * @param contract
     */
    protected void verifyContract(final Transaction contract) {
    }

    protected abstract Script createOutputScript();

    protected Coin getTotalValue() {
        return contract.getOutput(0).getValue();
    }

    protected abstract ECKey getClientKey();
}
