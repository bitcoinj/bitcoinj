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

import com.google.common.collect.Multimap;
import com.google.common.collect.MultimapBuilder;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

/**
 * Version 2 of the payment channel state machine - uses CLTV opcode transactions
 * instead of multisig transactions.
 */
public class PaymentChannelV2ServerState extends PaymentChannelServerState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelV1ServerState.class);

    // The total value locked into the CLTV output and the value to us in the last signature the client provided
    private Coin feePaidForPayment;

    // The client key for the multi-sig contract
    // We currently also use the serverKey for payouts, but this is not required
    protected ECKey clientKey;

    PaymentChannelV2ServerState(StoredServerChannel storedServerChannel, Wallet wallet, TransactionBroadcaster broadcaster) throws VerificationException {
        super(storedServerChannel, wallet, broadcaster);
        synchronized (storedServerChannel) {
            this.clientKey = storedServerChannel.clientKey;
            stateMachine.transition(State.READY);
        }
    }

    public PaymentChannelV2ServerState(TransactionBroadcaster broadcaster, Wallet wallet, ECKey serverKey, long minExpireTime) {
        super(broadcaster, wallet, serverKey, minExpireTime);
        stateMachine.transition(State.WAITING_FOR_MULTISIG_CONTRACT);
    }

    @Override
    public Multimap<State, State> getStateTransitions() {
        Multimap<State, State> result = MultimapBuilder.enumKeys(State.class).arrayListValues().build();
        result.put(State.UNINITIALISED, State.READY);
        result.put(State.UNINITIALISED, State.WAITING_FOR_MULTISIG_CONTRACT);
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
        return 2;
    }

    @Override
    public TransactionOutput getClientOutput() {
        return null;
    }

    public void provideClientKey(byte[] clientKey) {
        this.clientKey = ECKey.fromPublicOnly(clientKey);
    }

    @Override
    public synchronized Coin getFeePaid() {
        stateMachine.checkState(State.CLOSED, State.CLOSING);
        return feePaidForPayment;
    }

    @Override
    protected Script getSignedScript() {
        return createP2SHRedeemScript();
    }

    @Override
    protected void verifyContract(final Transaction contract) {
        super.verifyContract(contract);
        // Check contract matches P2SH hash
        byte[] expected = getContractScript().getPubKeyHash();
        byte[] actual = Utils.sha256hash160(createP2SHRedeemScript().getProgram());
        if (!Arrays.equals(actual, expected)) {
            throw new VerificationException(
                    "P2SH hash didn't match required contract - contract should be a CLTV micropayment channel to client and server in that order.");
        }
    }

    /**
     * Creates a P2SH script outputting to the client and server pubkeys
     * @return
     */
    @Override
    protected Script createOutputScript() {
        return ScriptBuilder.createP2SHOutputScript(createP2SHRedeemScript());
    }

    private Script createP2SHRedeemScript() {
        return ScriptBuilder.createCLTVPaymentChannelOutput(BigInteger.valueOf(getExpiryTime()), clientKey, serverKey);
    }

    protected ECKey getClientKey() {
        return clientKey;
    }

    // Signs the first input of the transaction which must spend the multisig contract.
    private void signP2SHInput(Transaction tx, Transaction.SigHash hashType, boolean anyoneCanPay) {
        TransactionSignature signature = tx.calculateSignature(0, serverKey, createP2SHRedeemScript(), hashType, anyoneCanPay);
        byte[] mySig = signature.encodeToBitcoin();
        Script scriptSig = ScriptBuilder.createCLTVPaymentChannelP2SHInput(bestValueSignature, mySig, createP2SHRedeemScript());
        tx.getInput(0).setScriptSig(scriptSig);
    }

    final SettableFuture<Transaction> closedFuture = SettableFuture.create();

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
            signP2SHInput(tx, Transaction.SigHash.NONE, true);
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
            signP2SHInput(tx, Transaction.SigHash.ALL, false);
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
}
