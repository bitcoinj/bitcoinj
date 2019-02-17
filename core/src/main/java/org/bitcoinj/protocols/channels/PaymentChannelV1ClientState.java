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
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.protocols.channels.IPaymentChannelClient.ClientChannelProperties;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.wallet.AllowUnconfirmedCoinSelector;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bouncycastle.crypto.params.KeyParameter;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.List;

import static com.google.common.base.Preconditions.*;

/**
 * Version 1 of the payment channel state machine - uses time locked multisig
 * contracts.
 */
public class PaymentChannelV1ClientState extends PaymentChannelClientState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelV1ClientState.class);
    // How much value (in satoshis) is locked up into the channel.
    private final Coin totalValue;
    // When the channel will automatically settle in favor of the client, if the server halts before protocol termination
    // specified in terms of block timestamps (so it can off real time by a few hours).
    private final long expiryTime;

    // The refund is a time locked transaction that spends all the money of the channel back to the client.
    private Transaction refundTx;
    private Coin refundFees;
    // The multi-sig contract locks the value of the channel up such that the agreement of both parties is required
    // to spend it.
    private Transaction multisigContract;
    private Script multisigScript;

    PaymentChannelV1ClientState(StoredClientChannel storedClientChannel, Wallet wallet) throws VerificationException {
        super(storedClientChannel, wallet);
        // The PaymentChannelClientConnection handles storedClientChannel.active and ensures we aren't resuming channels
        this.multisigContract = checkNotNull(storedClientChannel.contract);
        this.multisigScript = multisigContract.getOutput(0).getScriptPubKey();
        this.refundTx = checkNotNull(storedClientChannel.refund);
        this.refundFees = checkNotNull(storedClientChannel.refundFees);
        this.expiryTime = refundTx.getLockTime();
        this.totalValue = multisigContract.getOutput(0).getValue();
        stateMachine.transition(State.READY);
        initWalletListeners();
    }

    /**
     * Creates a state object for a payment channel client. It is expected that you be ready to
     * {@link PaymentChannelClientState#initiate(KeyParameter, IPaymentChannelClient.ClientChannelProperties)} after construction (to avoid creating objects for channels which are
     * not going to finish opening) and thus some parameters provided here are only used in
     * {@link PaymentChannelClientState#initiate(KeyParameter, IPaymentChannelClient.ClientChannelProperties)} to create the Multisig contract and refund transaction.
     *
     * @param wallet a wallet that contains at least the specified amount of value.
     * @param myKey a freshly generated private key for this channel.
     * @param serverMultisigKey a public key retrieved from the server used for the initial multisig contract
     * @param value how many satoshis to put into this contract. If the channel reaches this limit, it must be closed.
     * @param expiryTimeInSeconds At what point (UNIX timestamp +/- a few hours) the channel will expire
     *
     * @throws VerificationException If either myKey's pubkey or serverKey's pubkey are non-canonical (ie invalid)
     */
    public PaymentChannelV1ClientState(Wallet wallet, ECKey myKey, ECKey serverMultisigKey,
                                       Coin value, long expiryTimeInSeconds) throws VerificationException {
        super(wallet, myKey, serverMultisigKey, value, expiryTimeInSeconds);
        checkArgument(value.signum() > 0);
        initWalletListeners();
        this.totalValue = checkNotNull(value);
        this.expiryTime = expiryTimeInSeconds;
        stateMachine.transition(State.NEW);
    }

    @Override
    protected Multimap<State, State> getStateTransitions() {
        Multimap<State, State> result = MultimapBuilder.enumKeys(State.class).arrayListValues().build();
        result.put(State.UNINITIALISED, State.NEW);
        result.put(State.UNINITIALISED, State.READY);
        result.put(State.NEW, State.INITIATED);
        result.put(State.INITIATED, State.WAITING_FOR_SIGNED_REFUND);
        result.put(State.WAITING_FOR_SIGNED_REFUND, State.SAVE_STATE_IN_WALLET);
        result.put(State.SAVE_STATE_IN_WALLET, State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER);
        result.put(State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, State.READY);
        result.put(State.READY, State.EXPIRED);
        result.put(State.READY, State.CLOSED);
        return result;
    }

    public int getMajorVersion() {
        return 1;
    }

    /**
     * Creates the initial multisig contract and incomplete refund transaction which can be requested at the appropriate
     * time using {@link PaymentChannelV1ClientState#getIncompleteRefundTransaction} and
     * {@link PaymentChannelV1ClientState#getContract()}.
     * By default unconfirmed coins are allowed to be used, as for micropayments the risk should be relatively low.
     * @param userKey Key derived from a user password, needed for any signing when the wallet is encrypted.
     *                The wallet KeyCrypter is assumed.
     * @param clientChannelProperties Modify the channel's configuration.
     *
     * @throws ValueOutOfRangeException   if the value being used is too small to be accepted by the network
     * @throws InsufficientMoneyException if the wallet doesn't contain enough balance to initiate
     */
    @Override
    public synchronized void initiate(@Nullable KeyParameter userKey, ClientChannelProperties clientChannelProperties) throws ValueOutOfRangeException, InsufficientMoneyException {
        final NetworkParameters params = wallet.getParams();
        Transaction template = new Transaction(params);
        // We always place the client key before the server key because, if either side wants some privacy, they can
        // use a fresh key for the the multisig contract and nowhere else
        List<ECKey> keys = Lists.newArrayList(myKey, serverKey);
        // There is also probably a change output, but we don't bother shuffling them as it's obvious from the
        // format which one is the change. If we start obfuscating the change output better in future this may
        // be worth revisiting.
        TransactionOutput multisigOutput = template.addOutput(totalValue, ScriptBuilder.createMultiSigOutputScript(2, keys));
        if (multisigOutput.isDust())
            throw new ValueOutOfRangeException("totalValue too small to use");
        SendRequest req = SendRequest.forTx(template);
        req.coinSelector = AllowUnconfirmedCoinSelector.get();
        req.shuffleOutputs = false;   // TODO: Fix things so shuffling is usable.
        req = clientChannelProperties.modifyContractSendRequest(req);
        if (userKey != null) req.aesKey = userKey;
        wallet.completeTx(req);
        Coin multisigFee = req.tx.getFee();
        multisigContract = req.tx;
        // Build a refund transaction that protects us in the case of a bad server that's just trying to cause havoc
        // by locking up peoples money (perhaps as a precursor to a ransom attempt). We time lock it so the server
        // has an assurance that we cannot take back our money by claiming a refund before the channel closes - this
        // relies on the fact that since Bitcoin 0.8 time locked transactions are non-final. This will need to change
        // in future as it breaks the intended design of timelocking/tx replacement, but for now it simplifies this
        // specific protocol somewhat.
        refundTx = new Transaction(params);
        // don't disable lock time. the sequence will be included in the server's signature and thus won't be changeable.
        // by using this sequence value, we avoid extra full replace-by-fee and relative lock time processing.
        refundTx.addInput(multisigOutput).setSequenceNumber(TransactionInput.NO_SEQUENCE - 1L);
        refundTx.setLockTime(expiryTime);
        if (Context.get().isEnsureMinRequiredFee()) {
            // Must pay min fee.
            final Coin valueAfterFee = totalValue.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
            if (Transaction.MIN_NONDUST_OUTPUT.compareTo(valueAfterFee) > 0)
                throw new ValueOutOfRangeException("totalValue too small to use");
            refundTx.addOutput(valueAfterFee, LegacyAddress.fromKey(params, myKey));
            refundFees = multisigFee.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
        } else {
            refundTx.addOutput(totalValue, LegacyAddress.fromKey(params, myKey));
            refundFees = multisigFee;
        }
        refundTx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        log.info("initiated channel with multi-sig contract {}, refund {}", multisigContract.getTxId(),
                refundTx.getTxId());
        stateMachine.transition(State.INITIATED);
        // Client should now call getIncompleteRefundTransaction() and send it to the server.
    }

    /**
     * Returns the transaction that locks the money to the agreement of both parties. Do not mutate the result.
     * Once this step is done, you can use {@link PaymentChannelClientState#incrementPaymentBy(Coin, KeyParameter)} to
     * start paying the server.
     */
    @Override
    public synchronized Transaction getContract() {
        checkState(multisigContract != null);
        if (stateMachine.getState() == State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER) {
            stateMachine.transition(State.READY);
        }
        return multisigContract;
    }

    @Override
    protected synchronized Transaction getContractInternal() {
        return multisigContract;
    }

    protected synchronized Script getContractScript() {
        return multisigScript;
    }

    @Override
    protected Script getSignedScript() {
        return getContractScript();
    }

    /**
     * Returns a partially signed (invalid) refund transaction that should be passed to the server. Once the server
     * has checked it out and provided its own signature, call
     * {@link PaymentChannelV1ClientState#provideRefundSignature(byte[], KeyParameter)} with the result.
     */
    public synchronized Transaction getIncompleteRefundTransaction() {
        checkState(refundTx != null);
        if (stateMachine.getState() == State.INITIATED) {
            stateMachine.transition(State.WAITING_FOR_SIGNED_REFUND);
        }
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
    public synchronized void provideRefundSignature(byte[] theirSignature, @Nullable KeyParameter userKey)
            throws SignatureDecodeException, VerificationException {
        checkNotNull(theirSignature);
        stateMachine.checkState(State.WAITING_FOR_SIGNED_REFUND);
        TransactionSignature theirSig = TransactionSignature.decodeFromBitcoin(theirSignature, true, false);
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
                refundTx.calculateSignature(0, myKey.maybeDecrypt(userKey),
                        multisigScript, Transaction.SigHash.ALL, false);
        // Insert the signatures.
        Script scriptSig = ScriptBuilder.createMultiSigInputScript(ourSignature, theirSig);
        log.info("Refund scriptSig: {}", scriptSig);
        log.info("Multi-sig contract scriptPubKey: {}", multisigScript);
        TransactionInput refundInput = refundTx.getInput(0);
        refundInput.setScriptSig(scriptSig);
        refundInput.verify(multisigContractOutput);
        stateMachine.transition(State.SAVE_STATE_IN_WALLET);
    }

    @Override
    protected synchronized Coin getValueToMe() {
        return valueToMe;
    }

    protected long getExpiryTime() {
        return expiryTime;
    }

    @Override
    @VisibleForTesting synchronized void doStoreChannelInWallet(Sha256Hash id) {
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        checkNotNull(channels, "You have not added the StoredPaymentChannelClientStates extension to the wallet.");
        checkState(channels.getChannel(id, multisigContract.getTxId()) == null);
        storedChannel = new StoredClientChannel(getMajorVersion(), id, multisigContract, refundTx, myKey, serverKey, valueToMe, refundFees, 0, true);
        channels.putChannel(storedChannel);
    }

    @Override
    public synchronized Coin getRefundTxFees() {
        checkState(getState().compareTo(State.NEW) > 0);
        return refundFees;
    }

    @VisibleForTesting Transaction getRefundTransaction() {
        return refundTx;
    }

    /**
     * Once the servers signature over the refund transaction has been received and provided using
     * {@link PaymentChannelV1ClientState#provideRefundSignature(byte[], KeyParameter)} then this
     * method can be called to receive the now valid and broadcastable refund transaction.
     */
    public synchronized Transaction getCompletedRefundTransaction() {
        checkState(getState().compareTo(State.WAITING_FOR_SIGNED_REFUND) > 0);
        return refundTx;
    }

    /**
     * Gets the total value of this channel (ie the maximum payment possible)
     */
    @Override
    public Coin getTotalValue() {
        return totalValue;
    }
}
