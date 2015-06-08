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
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.Arrays;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A payment channel is a method of sending money to someone such that the amount of money you send can be adjusted
 * after the fact, in an efficient manner that does not require broadcasting to the network. This can be used to
 * implement micropayments or other payment schemes in which immediate settlement is not required, but zero trust
 * negotiation is. Note that this class only allows the amount of money received to be incremented, not decremented.</p>
 *
 * <p>This class implements the core state machine for the server side of the protocol. The client side is implemented
 * by {@link PaymentChannelClientState} and {@link PaymentChannelServerListener} implements the server-side network
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
public class PaymentChannelServerState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelServerState.class);

    /**
     * The different logical states the channel can be in. Because the first action we need to track is the client
     * providing the refund transaction, we begin in WAITING_FOR_REFUND_TRANSACTION. We then step through the states
     * until READY, at which time the client can increase payment incrementally.
     */
    public enum State {
        WAITING_FOR_REFUND_TRANSACTION,
        WAITING_FOR_MULTISIG_CONTRACT,
        WAITING_FOR_MULTISIG_ACCEPTANCE,
        READY,
        CLOSING,
        CLOSED,
        ERROR,
    }
    private State state;

    // The client and server keys for the multi-sig contract
    // We currently also use the serverKey for payouts, but this is not required
    private ECKey clientKey, serverKey;

    // Package-local for checkArguments in StoredServerChannel
    final Wallet wallet;

    // The object that will broadcast transactions for us - usually a peer group.
    private final TransactionBroadcaster broadcaster;

    // The multi-sig contract and the output script from it
    private Transaction multisigContract = null;
    private Script multisigScript;

    // The last signature the client provided for a payment transaction.
    private byte[] bestValueSignature;

    // The total value locked into the multi-sig output and the value to us in the last signature the client provided
    private Coin totalValue;
    private Coin bestValueToMe = Coin.ZERO;
    private Coin feePaidForPayment;

    // The refund/change transaction output that goes back to the client
    private TransactionOutput clientOutput;
    private long refundTransactionUnlockTimeSecs;

    private long minExpireTime;

    private StoredServerChannel storedServerChannel = null;

    PaymentChannelServerState(StoredServerChannel storedServerChannel, Wallet wallet, TransactionBroadcaster broadcaster) throws VerificationException {
        synchronized (storedServerChannel) {
            this.wallet = checkNotNull(wallet);
            this.broadcaster = checkNotNull(broadcaster);
            this.multisigContract = checkNotNull(storedServerChannel.contract);
            this.multisigScript = multisigContract.getOutput(0).getScriptPubKey();
            this.clientKey = ECKey.fromPublicOnly(multisigScript.getChunks().get(1).data);
            this.clientOutput = checkNotNull(storedServerChannel.clientOutput);
            this.refundTransactionUnlockTimeSecs = storedServerChannel.refundTransactionUnlockTimeSecs;
            this.serverKey = checkNotNull(storedServerChannel.myKey);
            this.totalValue = multisigContract.getOutput(0).getValue();
            this.bestValueToMe = checkNotNull(storedServerChannel.bestValueToMe);
            this.bestValueSignature = storedServerChannel.bestValueSignature;
            checkArgument(bestValueToMe.equals(Coin.ZERO) || bestValueSignature != null);
            this.storedServerChannel = storedServerChannel;
            storedServerChannel.state = this;
            this.state = State.READY;
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
        this.state = State.WAITING_FOR_REFUND_TRANSACTION;
        this.serverKey = checkNotNull(serverKey);
        this.wallet = checkNotNull(wallet);
        this.broadcaster = checkNotNull(broadcaster);
        this.minExpireTime = minExpireTime;
    }

    /**
     * This object implements a state machine, and this accessor returns which state it's currently in.
     */
    public synchronized State getState() {
        return state;
    }

    /**
     * Called when the client provides the refund transaction.
     * The refund transaction must have one input from the multisig contract (that we don't have yet) and one output
     * that the client creates to themselves. This object will later be modified when we start getting paid.
     *
     * @param refundTx The refund transaction, this object will be mutated when payment is incremented.
     * @param clientMultiSigPubKey The client's pubkey which is required for the multisig output
     * @return Our signature that makes the refund transaction valid
     * @throws VerificationException If the transaction isnt valid or did not meet the requirements of a refund transaction.
     */
    public synchronized byte[] provideRefundTransaction(Transaction refundTx, byte[] clientMultiSigPubKey) throws VerificationException {
        checkNotNull(refundTx);
        checkNotNull(clientMultiSigPubKey);
        checkState(state == State.WAITING_FOR_REFUND_TRANSACTION);
        log.info("Provided with refund transaction: {}", refundTx);
        // Do a few very basic syntax sanity checks.
        refundTx.verify();
        // Verify that the refund transaction has a single input (that we can fill to sign the multisig output).
        if (refundTx.getInputs().size() != 1)
            throw new VerificationException("Refund transaction does not have exactly one input");
        // Verify that the refund transaction has a time lock on it and a sequence number of zero.
        if (refundTx.getInput(0).getSequenceNumber() != 0)
            throw new VerificationException("Refund transaction's input's sequence number is non-0");
        if (refundTx.getLockTime() < minExpireTime)
            throw new VerificationException("Refund transaction has a lock time too soon");
        // Verify the transaction has one output (we don't care about its contents, its up to the client)
        // Note that because we sign with SIGHASH_NONE|SIGHASH_ANYOENCANPAY the client can later add more outputs and
        // inputs, but we will need only one output later to create the paying transactions
        if (refundTx.getOutputs().size() != 1)
            throw new VerificationException("Refund transaction does not have exactly one output");

        refundTransactionUnlockTimeSecs = refundTx.getLockTime();

        // Sign the refund tx with the scriptPubKey and return the signature. We don't have the spending transaction
        // so do the steps individually.
        clientKey = ECKey.fromPublicOnly(clientMultiSigPubKey);
        Script multisigPubKey = ScriptBuilder.createMultiSigOutputScript(2, ImmutableList.of(clientKey, serverKey));
        // We are really only signing the fact that the transaction has a proper lock time and don't care about anything
        // else, so we sign SIGHASH_NONE and SIGHASH_ANYONECANPAY.
        TransactionSignature sig = refundTx.calculateSignature(0, serverKey, multisigPubKey, Transaction.SigHash.NONE, true);
        log.info("Signed refund transaction.");
        this.clientOutput = refundTx.getOutput(0);
        state = State.WAITING_FOR_MULTISIG_CONTRACT;
        return sig.encodeToBitcoin();
    }

    /**
     * Called when the client provides the multi-sig contract.  Checks that the previously-provided refund transaction
     * spends this transaction (because we will use it as a base to create payment transactions) as well as output value
     * and form (ie it is a 2-of-2 multisig to the correct keys).
     *
     * @param multisigContract The provided multisig contract. Do not mutate this object after this call.
     * @return A future which completes when the provided multisig contract successfully broadcasts, or throws if the broadcast fails for some reason
     *         Note that if the network simply rejects the transaction, this future will never complete, a timeout should be used.
     * @throws VerificationException If the provided multisig contract is not well-formed or does not meet previously-specified parameters
     */
    public synchronized ListenableFuture<PaymentChannelServerState> provideMultiSigContract(final Transaction multisigContract) throws VerificationException {
        checkNotNull(multisigContract);
        checkState(state == State.WAITING_FOR_MULTISIG_CONTRACT);
        try {
            multisigContract.verify();
            this.multisigContract = multisigContract;
            this.multisigScript = multisigContract.getOutput(0).getScriptPubKey();

            // Check that multisigContract's first output is a 2-of-2 multisig to the correct pubkeys in the correct order
            final Script expectedScript = ScriptBuilder.createMultiSigOutputScript(2, Lists.newArrayList(clientKey, serverKey));
            if (!Arrays.equals(multisigScript.getProgram(), expectedScript.getProgram()))
                throw new VerificationException("Multisig contract's first output was not a standard 2-of-2 multisig to client and server in that order.");

            this.totalValue = multisigContract.getOutput(0).getValue();
            if (this.totalValue.signum() <= 0)
                throw new VerificationException("Not accepting an attempt to open a contract with zero value.");
        } catch (VerificationException e) {
            // We couldn't parse the multisig transaction or its output.
            log.error("Provided multisig contract did not verify: {}", multisigContract.toString());
            throw e;
        }
        log.info("Broadcasting multisig contract: {}", multisigContract);
        state = State.WAITING_FOR_MULTISIG_ACCEPTANCE;
        final SettableFuture<PaymentChannelServerState> future = SettableFuture.create();
        Futures.addCallback(broadcaster.broadcastTransaction(multisigContract).future(), new FutureCallback<Transaction>() {
            @Override public void onSuccess(Transaction transaction) {
                log.info("Successfully broadcast multisig contract {}. Channel now open.", transaction.getHashAsString());
                try {
                    // Manually add the multisigContract to the wallet, overriding the isRelevant checks so we can track
                    // it and check for double-spends later
                    wallet.receivePending(multisigContract, null, true);
                } catch (VerificationException e) {
                    throw new RuntimeException(e); // Cannot happen, we already called multisigContract.verify()
                }
                state = State.READY;
                future.set(PaymentChannelServerState.this);
            }

            @Override public void onFailure(Throwable throwable) {
                // Couldn't broadcast the transaction for some reason.
                log.error(throwable.toString());
                throwable.printStackTrace();
                state = State.ERROR;
                future.setException(throwable);
            }
        });
        return future;
    }

    // Create a payment transaction with valueToMe going back to us
    private synchronized Wallet.SendRequest makeUnsignedChannelContract(Coin valueToMe) {
        Transaction tx = new Transaction(wallet.getParams());
        if (!totalValue.subtract(valueToMe).equals(Coin.ZERO)) {
            clientOutput.setValue(totalValue.subtract(valueToMe));
            tx.addOutput(clientOutput);
        }
        tx.addInput(multisigContract.getOutput(0));
        return Wallet.SendRequest.forTx(tx);
    }

    /**
     * Called when the client provides us with a new signature and wishes to increment total payment by size.
     * Verifies the provided signature and only updates values if everything checks out.
     * If the new refundSize is not the lowest we have seen, it is simply ignored.
     *
     * @param refundSize How many satoshis of the original contract are refunded to the client (the rest are ours)
     * @param signatureBytes The new signature spending the multi-sig contract to a new payment transaction
     * @throws VerificationException If the signature does not verify or size is out of range (incl being rejected by the network as dust).
     * @return true if there is more value left on the channel, false if it is now fully used up.
     */
    public synchronized boolean incrementPayment(Coin refundSize, byte[] signatureBytes) throws VerificationException, ValueOutOfRangeException, InsufficientMoneyException {
        checkState(state == State.READY);
        checkNotNull(refundSize);
        checkNotNull(signatureBytes);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(signatureBytes, true);
        // We allow snapping to zero for the payment amount because it's treated specially later, but not less than
        // the dust level because that would prevent the transaction from being relayed/mined.
        final boolean fullyUsedUp = refundSize.equals(Coin.ZERO);
        if (refundSize.compareTo(clientOutput.getMinNonDustValue()) < 0 && !fullyUsedUp)
            throw new ValueOutOfRangeException("Attempt to refund negative value or value too small to be accepted by the network");
        Coin newValueToMe = totalValue.subtract(refundSize);
        if (newValueToMe.signum() < 0)
            throw new ValueOutOfRangeException("Attempt to refund more than the contract allows.");
        if (newValueToMe.compareTo(bestValueToMe) < 0)
            throw new ValueOutOfRangeException("Attempt to roll back payment on the channel.");

        // Get the wallet's copy of the multisigContract (ie with confidence information), if this is null, the wallet
        // was not connected to the peergroup when the contract was broadcast (which may cause issues down the road, and
        // disables our double-spend check next)
        Transaction walletContract = wallet.getTransaction(multisigContract.getHash());
        checkNotNull(walletContract, "Wallet did not contain multisig contract {} after state was marked READY", multisigContract.getHash());

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

        Wallet.SendRequest req = makeUnsignedChannelContract(newValueToMe);
        // Now check the signature is correct.
        // Note that the client must sign with SIGHASH_{SINGLE/NONE} | SIGHASH_ANYONECANPAY to allow us to add additional
        // inputs (in case we need to add significant fee, or something...) and any outputs we want to pay to.
        Sha256Hash sighash = req.tx.hashForSignature(0, multisigScript, mode, true);

        if (!clientKey.verify(sighash, signature))
            throw new VerificationException("Signature does not verify on tx\n" + req.tx);
        bestValueToMe = newValueToMe;
        bestValueSignature = signatureBytes;
        updateChannelInWallet();
        return !fullyUsedUp;
    }

    // Signs the first input of the transaction which must spend the multisig contract.
    private void signMultisigInput(Transaction tx, Transaction.SigHash hashType, boolean anyoneCanPay) {
        TransactionSignature signature = tx.calculateSignature(0, serverKey, multisigScript, hashType, anyoneCanPay);
        byte[] mySig = signature.encodeToBitcoin();
        Script scriptSig = ScriptBuilder.createMultiSigInputScriptBytes(ImmutableList.of(bestValueSignature, mySig));
        tx.getInput(0).setScriptSig(scriptSig);
    }

    final SettableFuture<Transaction> closedFuture = SettableFuture.create();
    /**
     * <p>Closes this channel and broadcasts the highest value payment transaction on the network.</p>
     *
     * <p>This will set the state to {@link State#CLOSED} if the transaction is successfully broadcast on the network.
     * If we fail to broadcast for some reason, the state is set to {@link State#ERROR}.</p>
     *
     * <p>If the current state is before {@link State#READY} (ie we have not finished initializing the channel), we
     * simply set the state to {@link State#CLOSED} and let the client handle getting its refund transaction confirmed.
     * </p>
     *
     * @return a future which completes when the provided multisig contract successfully broadcasts, or throws if the
     *         broadcast fails for some reason. Note that if the network simply rejects the transaction, this future
     *         will never complete, a timeout should be used.
     * @throws InsufficientMoneyException If the payment tx would have cost more in fees to spend than it is worth.
     */
    public synchronized ListenableFuture<Transaction> close() throws InsufficientMoneyException {
        if (storedServerChannel != null) {
            StoredServerChannel temp = storedServerChannel;
            storedServerChannel = null;
            StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                    wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
            channels.closeChannel(temp); // May call this method again for us (if it wasn't the original caller)
            if (state.compareTo(State.CLOSING) >= 0)
                return closedFuture;
        }

        if (state.ordinal() < State.READY.ordinal()) {
            log.error("Attempt to settle channel in state " + state);
            state = State.CLOSED;
            closedFuture.set(null);
            return closedFuture;
        }
        if (state != State.READY) {
            // TODO: What is this codepath for?
            log.warn("Failed attempt to settle a channel in state " + state);
            return closedFuture;
        }
        Transaction tx = null;
        try {
            Wallet.SendRequest req = makeUnsignedChannelContract(bestValueToMe);
            tx = req.tx;
            // Provide a throwaway signature so that completeTx won't complain out about unsigned inputs it doesn't
            // know how to sign. Note that this signature does actually have to be valid, so we can't use a dummy
            // signature to save time, because otherwise completeTx will try to re-sign it to make it valid and then
            // die. We could probably add features to the SendRequest API to make this a bit more efficient.
            signMultisigInput(tx, Transaction.SigHash.NONE, true);
            // Let wallet handle adding additional inputs/fee as necessary.
            req.shuffleOutputs = false;
            req.missingSigsMode = Wallet.MissingSigsMode.USE_DUMMY_SIG;
            wallet.completeTx(req);  // TODO: Fix things so shuffling is usable.
            feePaidForPayment = req.tx.getFee();
            log.info("Calculated fee is {}", feePaidForPayment);
            if (feePaidForPayment.compareTo(bestValueToMe) >= 0) {
                final String msg = String.format("Had to pay more in fees (%s) than the channel was worth (%s)",
                        feePaidForPayment, bestValueToMe);
                throw new InsufficientMoneyException(feePaidForPayment.subtract(bestValueToMe), msg);
            }
            // Now really sign the multisig input.
            signMultisigInput(tx, Transaction.SigHash.ALL, false);
            // Some checks that shouldn't be necessary but it can't hurt to check.
            tx.verify();  // Sanity check syntax.
            for (TransactionInput input : tx.getInputs())
                input.verify();  // Run scripts and ensure it is valid.
        } catch (InsufficientMoneyException e) {
            throw e;  // Don't fall through.
        } catch (Exception e) {
            log.error("Could not verify self-built tx\nMULTISIG {}\nCLOSE {}", multisigContract, tx != null ? tx : "");
            throw new RuntimeException(e);  // Should never happen.
        }
        state = State.CLOSING;
        log.info("Closing channel, broadcasting tx {}", tx);
        // The act of broadcasting the transaction will add it to the wallet.
        ListenableFuture<Transaction> future = broadcaster.broadcastTransaction(tx).future();
        Futures.addCallback(future, new FutureCallback<Transaction>() {
            @Override public void onSuccess(Transaction transaction) {
                log.info("TX {} propagated, channel successfully closed.", transaction.getHash());
                state = State.CLOSED;
                closedFuture.set(transaction);
            }

            @Override public void onFailure(Throwable throwable) {
                log.error("Failed to settle channel, could not broadcast: {}", throwable.toString());
                throwable.printStackTrace();
                state = State.ERROR;
                closedFuture.setException(throwable);
            }
        });
        return closedFuture;
    }

    /**
     * Gets the highest payment to ourselves (which we will receive on settle(), not including fees)
     */
    public synchronized Coin getBestValueToMe() {
        return bestValueToMe;
    }

    /**
     * Gets the fee paid in the final payment transaction (only available if settle() did not throw an exception)
     */
    public synchronized Coin getFeePaid() {
        checkState(state == State.CLOSED || state == State.CLOSING);
        return feePaidForPayment;
    }

    /**
     * Gets the multisig contract which was used to initialize this channel
     */
    public synchronized Transaction getMultisigContract() {
        checkState(multisigContract != null);
        return multisigContract;
    }

    /**
     * Gets the client's refund transaction which they can spend to get the entire channel value back if it reaches its
     * lock time.
     */
    public synchronized long getRefundTransactionUnlockTime() {
        checkState(state.compareTo(State.WAITING_FOR_MULTISIG_CONTRACT) > 0 && state != State.ERROR);
        return refundTransactionUnlockTimeSecs;
    }

    private synchronized void updateChannelInWallet() {
        if (storedServerChannel != null) {
            storedServerChannel.updateValueToMe(bestValueToMe, bestValueSignature);
            StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                    wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
            wallet.addOrUpdateExtension(channels);
        }
    }

    /**
     * Stores this channel's state in the wallet as a part of a {@link StoredPaymentChannelServerStates} wallet
     * extension and keeps it up-to-date each time payment is incremented. This will be automatically removed when
     * a call to {@link PaymentChannelServerState#close()} completes successfully. A channel may only be stored after it
     * has fully opened (ie state == State.READY).
     *
     * @param connectedHandler Optional {@link PaymentChannelServer} object that manages this object. This will
     *                         set the appropriate pointer in the newly created {@link StoredServerChannel} before it is
     *                         committed to wallet. If set, closing the state object will propagate the close to the
     *                         handler which can then do a TCP disconnect.
     */
    public synchronized void storeChannelInWallet(@Nullable PaymentChannelServer connectedHandler) {
        checkState(state == State.READY);
        if (storedServerChannel != null)
            return;

        log.info("Storing state with contract hash {}.", multisigContract.getHash());
        StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                wallet.addOrGetExistingExtension(new StoredPaymentChannelServerStates(wallet, broadcaster));
        storedServerChannel = new StoredServerChannel(this, multisigContract, clientOutput, refundTransactionUnlockTimeSecs, serverKey, bestValueToMe, bestValueSignature);
        if (connectedHandler != null)
            checkState(storedServerChannel.setConnectedHandler(connectedHandler, false) == connectedHandler);
        channels.putChannel(storedServerChannel);
        wallet.addOrUpdateExtension(channels);
    }
}
