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
import com.google.common.collect.Multimap;
import com.google.common.collect.MultimapBuilder;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.protocols.channels.IPaymentChannelClient.ClientChannelProperties;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.AllowUnconfirmedCoinSelector;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.math.BigInteger;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Version 2 of the payment channel state machine - uses CLTV opcode transactions
 * instead of multisig transactions.
 */
public class PaymentChannelV2ClientState extends PaymentChannelClientState {
    private static final Logger log = LoggerFactory.getLogger(PaymentChannelV1ClientState.class);

    // How much value (in satoshis) is locked up into the channel.
    private final Coin totalValue;
    // When the channel will automatically settle in favor of the client, if the server halts before protocol termination
    // specified in terms of block timestamps (so it can off real time by a few hours).
    private final long expiryTime;

    // The refund is a time locked transaction that spends all the money of the channel back to the client.
    // Unlike in V1 this refund isn't signed by the server - we only have to sign it ourselves.
    @VisibleForTesting Transaction refundTx;
    private Coin refundFees;

    // The multi-sig contract locks the value of the channel up such that the agreement of both parties is required
    // to spend it.
    private Transaction contract;

    PaymentChannelV2ClientState(StoredClientChannel storedClientChannel, Wallet wallet) throws VerificationException {
        super(storedClientChannel, wallet);
        // The PaymentChannelClientConnection handles storedClientChannel.active and ensures we aren't resuming channels
        this.contract = checkNotNull(storedClientChannel.contract);
        this.expiryTime = storedClientChannel.expiryTime;
        this.totalValue = contract.getOutput(0).getValue();
        this.valueToMe = checkNotNull(storedClientChannel.valueToMe);
        this.refundTx = checkNotNull(storedClientChannel.refund);
        this.refundFees = checkNotNull(storedClientChannel.refundFees);
        stateMachine.transition(State.READY);
        initWalletListeners();
    }

    public PaymentChannelV2ClientState(Wallet wallet, ECKey myKey, ECKey serverMultisigKey, Coin value, long expiryTimeInSeconds) throws VerificationException {
        super(wallet, myKey, serverMultisigKey, value, expiryTimeInSeconds);
        checkArgument(value.signum() > 0);
        initWalletListeners();
        this.valueToMe = this.totalValue = checkNotNull(value);
        this.expiryTime = expiryTimeInSeconds;
        stateMachine.transition(State.NEW);
    }

    @Override
    protected Multimap<State, State> getStateTransitions() {
        Multimap<State, State> result = MultimapBuilder.enumKeys(State.class).arrayListValues().build();
        result.put(State.UNINITIALISED, State.NEW);
        result.put(State.UNINITIALISED, State.READY);
        result.put(State.NEW, State.SAVE_STATE_IN_WALLET);
        result.put(State.SAVE_STATE_IN_WALLET, State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER);
        result.put(State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, State.READY);
        result.put(State.READY, State.EXPIRED);
        result.put(State.READY, State.CLOSED);
        return result;
    }

    @Override
    public int getMajorVersion() {
        return 2;
    }

    @Override
    public synchronized void initiate(@Nullable KeyParameter userKey, ClientChannelProperties clientChannelProperties) throws ValueOutOfRangeException, InsufficientMoneyException {
        final NetworkParameters params = wallet.getParams();
        Transaction template = new Transaction(params);
        // There is also probably a change output, but we don't bother shuffling them as it's obvious from the
        // format which one is the change. If we start obfuscating the change output better in future this may
        // be worth revisiting.
        Script redeemScript =
                ScriptBuilder.createCLTVPaymentChannelOutput(BigInteger.valueOf(expiryTime), myKey, serverKey);
        TransactionOutput transactionOutput = template.addOutput(totalValue,
                ScriptBuilder.createP2SHOutputScript(redeemScript));
        if (transactionOutput.isDust())
            throw new ValueOutOfRangeException("totalValue too small to use");
        SendRequest req = SendRequest.forTx(template);
        req.coinSelector = AllowUnconfirmedCoinSelector.get();
        req.shuffleOutputs = false;   // TODO: Fix things so shuffling is usable.
        req = clientChannelProperties.modifyContractSendRequest(req);
        if (userKey != null) req.aesKey = userKey;
        wallet.completeTx(req);
        Coin multisigFee = req.tx.getFee();
        contract = req.tx;

        // Build a refund transaction that protects us in the case of a bad server that's just trying to cause havoc
        // by locking up peoples money (perhaps as a precursor to a ransom attempt). We time lock it because the
        // CheckLockTimeVerify opcode requires a lock time to be specified and the input to have a non-final sequence
        // number (so that the lock time is not disabled).
        refundTx = new Transaction(params);
        // by using this sequence value, we avoid extra full replace-by-fee and relative lock time processing.
        refundTx.addInput(contract.getOutput(0)).setSequenceNumber(TransactionInput.NO_SEQUENCE - 1L);
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

        TransactionSignature refundSignature =
                refundTx.calculateSignature(0, myKey.maybeDecrypt(userKey),
                        getSignedScript(), Transaction.SigHash.ALL, false);
        refundTx.getInput(0).setScriptSig(ScriptBuilder.createCLTVPaymentChannelP2SHRefund(refundSignature, redeemScript));

        refundTx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        log.info("initiated channel with contract {}", contract.getHashAsString());
        stateMachine.transition(State.SAVE_STATE_IN_WALLET);
        // Client should now call getIncompleteRefundTransaction() and send it to the server.
    }

    @Override
    protected synchronized Coin getValueToMe() {
        return valueToMe;
    }

    protected long getExpiryTime() {
        return expiryTime;
    }

    @Override
    public synchronized Transaction getContract() {
        checkState(contract != null);
        if (stateMachine.getState() == State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER) {
            stateMachine.transition(State.READY);
        }
        return contract;
    }

    @Override
    protected synchronized Transaction getContractInternal() {
        return contract;
    }

    protected synchronized Script getContractScript() {
        return contract.getOutput(0).getScriptPubKey();
    }

    @Override
    protected Script getSignedScript() {
        return ScriptBuilder.createCLTVPaymentChannelOutput(BigInteger.valueOf(expiryTime), myKey, serverKey);
    }

    @Override
    public synchronized Coin getRefundTxFees() {
        checkState(getState().compareTo(State.NEW) > 0);
        return refundFees;
    }

    @VisibleForTesting Transaction getRefundTransaction() {
        return refundTx;
    }

    @Override
    @VisibleForTesting synchronized void doStoreChannelInWallet(Sha256Hash id) {
        StoredPaymentChannelClientStates channels = (StoredPaymentChannelClientStates)
                wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        checkNotNull(channels, "You have not added the StoredPaymentChannelClientStates extension to the wallet.");
        checkState(channels.getChannel(id, contract.getHash()) == null);
        storedChannel = new StoredClientChannel(getMajorVersion(), id, contract, refundTx, myKey, serverKey, valueToMe, refundFees, expiryTime, true);
        channels.putChannel(storedChannel);
    }

    @Override
    public Coin getTotalValue() {
        return totalValue;
    }
}
