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

import com.google.common.collect.*;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;

import static com.google.common.base.Preconditions.*;

/**
 * Version 1 of the payment channel server state object. Common functionality is
 * present in the parent class.
 */
public class PaymentChannelV1ServerState extends PaymentChannelServerState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelV1ServerState.class);

    // The total value locked into the multi-sig output and the value to us in the last signature the client provided
    private Coin feePaidForPayment;

    // The client key for the multi-sig contract
    // We currently also use the serverKey for payouts, but this is not required
    protected ECKey clientKey;

    // The refund/change transaction output that goes back to the client
    private TransactionOutput clientOutput;
    private long refundTransactionUnlockTimeSecs;

    PaymentChannelV1ServerState(StoredServerChannel storedServerChannel, Wallet wallet, TransactionBroadcaster broadcaster) throws VerificationException {
        super(storedServerChannel, wallet, broadcaster);
        synchronized (storedServerChannel) {
            this.clientKey = ECKey.fromPublicOnly(getContractScript().getChunks().get(1).data);
            this.clientOutput = checkNotNull(storedServerChannel.clientOutput);
            this.refundTransactionUnlockTimeSecs = storedServerChannel.refundTransactionUnlockTimeSecs;
            stateMachine.transition(State.READY);
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
    public PaymentChannelV1ServerState(TransactionBroadcaster broadcaster, Wallet wallet, ECKey serverKey, long minExpireTime) {
        super(broadcaster, wallet, serverKey, minExpireTime);
        stateMachine.transition(State.WAITING_FOR_REFUND_TRANSACTION);
    }

    @Override
    public Multimap<State, State> getStateTransitions() {
        Multimap<State, State> result = MultimapBuilder.enumKeys(State.class).arrayListValues().build();
        result.put(State.UNINITIALISED, State.READY);
        result.put(State.UNINITIALISED, State.WAITING_FOR_REFUND_TRANSACTION);
        result.put(State.WAITING_FOR_REFUND_TRANSACTION, State.WAITING_FOR_MULTISIG_CONTRACT);
        result.put(State.WAITING_FOR_MULTISIG_CONTRACT, State.WAITING_FOR_MULTISIG_ACCEPTANCE);
        result.put(State.WAITING_FOR_MULTISIG_ACCEPTANCE, State.READY);
        result.put(State.READY, State.CLOSING);
        result.put(State.CLOSING, State.CLOSED);
        for (State state : State.values()) {
            result.put(state, State.ERROR);
        }
        return result;
    }

    @Override
    public int getMajorVersion() {
        return 1;
    }

    @Override
    public TransactionOutput getClientOutput() {
        return clientOutput;
    }

    @Override
    protected Script getSignedScript() {
        return getContractScript();
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
        stateMachine.checkState(State.WAITING_FOR_REFUND_TRANSACTION);
        log.info("Provided with refund transaction: {}", refundTx);
        // Do a few very basic syntax sanity checks.
        refundTx.verify();
        // Verify that the refund transaction has a single input (that we can fill to sign the multisig output).
        if (refundTx.getInputs().size() != 1)
            throw new VerificationException("Refund transaction does not have exactly one input");
        // Verify that the refund transaction has a time lock on it and a sequence number that does not disable lock time.
        if (refundTx.getInput(0).getSequenceNumber() == TransactionInput.NO_SEQUENCE)
            throw new VerificationException("Refund transaction's input's sequence number disables lock time");
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
        stateMachine.transition(State.WAITING_FOR_MULTISIG_CONTRACT);
        return sig.encodeToBitcoin();
    }

    protected Script createOutputScript() {
        return ScriptBuilder.createMultiSigOutputScript(2, ImmutableList.<ECKey>of(clientKey, serverKey));
    }

    protected ECKey getClientKey() {
        return clientKey;
    }

    // Signs the first input of the transaction which must spend the multisig contract.
    private void signMultisigInput(Transaction tx, Transaction.SigHash hashType, boolean anyoneCanPay) {
        TransactionSignature signature = tx.calculateSignature(0, serverKey, getContractScript(), hashType, anyoneCanPay);
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
    @Override
    public synchronized ListenableFuture<Transaction> close() throws InsufficientMoneyException {
        if (storedServerChannel != null) {
            StoredServerChannel temp = storedServerChannel;
            storedServerChannel = null;
            StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)
                    wallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
            channels.closeChannel(temp); // May call this method again for us (if it wasn't the original caller)
            if (getState().compareTo(State.CLOSING) >= 0)
                return closedFuture;
        }

        if (getState().ordinal() < State.READY.ordinal()) {
            log.error("Attempt to settle channel in state " + getState());
            stateMachine.transition(State.CLOSED);
            closedFuture.set(null);
            return closedFuture;
        }
        if (getState() != State.READY) {
            // TODO: What is this codepath for?
            log.warn("Failed attempt to settle a channel in state " + getState());
            return closedFuture;
        }
        Transaction tx = null;
        try {
            SendRequest req = makeUnsignedChannelContract(bestValueToMe);
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
            if (feePaidForPayment.compareTo(bestValueToMe) > 0) {
                final String msg = String.format(Locale.US, "Had to pay more in fees (%s) than the channel was worth (%s)",
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
            log.error("Could not verify self-built tx\nMULTISIG {}\nCLOSE {}", contract, tx != null ? tx : "");
            throw new RuntimeException(e);  // Should never happen.
        }
        stateMachine.transition(State.CLOSING);
        log.info("Closing channel, broadcasting tx {}", tx);
        // The act of broadcasting the transaction will add it to the wallet.
        ListenableFuture<Transaction> future = broadcaster.broadcastTransaction(tx).future();
        Futures.addCallback(future, new FutureCallback<Transaction>() {
            @Override public void onSuccess(Transaction transaction) {
                log.info("TX {} propagated, channel successfully closed.", transaction.getHash());
                stateMachine.transition(State.CLOSED);
                closedFuture.set(transaction);
            }

            @Override public void onFailure(Throwable throwable) {
                log.error("Failed to settle channel, could not broadcast: {}", throwable);
                stateMachine.transition(State.ERROR);
                closedFuture.setException(throwable);
            }
        });
        return closedFuture;
    }

    /**
     * Gets the fee paid in the final payment transaction (only available if settle() did not throw an exception)
     */
    @Override
    public synchronized Coin getFeePaid() {
        stateMachine.checkState(State.CLOSED, State.CLOSING);
        return feePaidForPayment;
    }

    /**
     * Gets the client's refund transaction which they can spend to get the entire channel value back if it reaches its
     * lock time.
     */
    public synchronized long getRefundTransactionUnlockTime() {
        checkState(getState().compareTo(State.WAITING_FOR_MULTISIG_CONTRACT) > 0 && getState() != State.ERROR);
        return refundTransactionUnlockTimeSecs;
    }
}
