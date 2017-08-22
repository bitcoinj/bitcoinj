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

package org.bitcoinj.wallet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Date;

import org.bitcoin.protocols.payments.Protos.PaymentDetails;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.utils.ExchangeRate;
import org.bitcoinj.wallet.KeyChain.KeyPurpose;
import org.bitcoinj.wallet.Wallet.MissingSigsMode;
import org.bouncycastle.crypto.params.KeyParameter;

import com.google.common.base.MoreObjects;

/**
 * A SendRequest gives the wallet information about precisely how to send money to a recipient or set of recipients.
 * Static methods are provided to help you create SendRequests and there are a few helper methods on the wallet that
 * just simplify the most common use cases. You may wish to customize a SendRequest if you want to attach a fee or
 * modify the change address.
 */
public class SendRequest {
    /**
     * <p>A transaction, probably incomplete, that describes the outline of what you want to do. This typically will
     * mean it has some outputs to the intended destinations, but no inputs or change address (and therefore no
     * fees) - the wallet will calculate all that for you and update tx later.</p>
     *
     * <p>Be careful when adding outputs that you check the min output value
     * ({@link TransactionOutput#getMinNonDustValue(Coin)}) to avoid the whole transaction being rejected
     * because one output is dust.</p>
     *
     * <p>If there are already inputs to the transaction, make sure their out point has a connected output,
     * otherwise their value will be added to fee.  Also ensure they are either signed or are spendable by a wallet
     * key, otherwise the behavior of {@link Wallet#completeTx(SendRequest)} is undefined (likely
     * RuntimeException).</p>
     */
    public Transaction tx;

    /**
     * When emptyWallet is set, all coins selected by the coin selector are sent to the first output in tx
     * (its value is ignored and set to {@link Wallet#getBalance()} - the fees required
     * for the transaction). Any additional outputs are removed.
     */
    public boolean emptyWallet = false;

    /**
     * "Change" means the difference between the value gathered by a transactions inputs (the size of which you
     * don't really control as it depends on who sent you money), and the value being sent somewhere else. The
     * change address should be selected from this wallet, normally. <b>If null this will be chosen for you.</b>
     */
    public Address changeAddress = null;

    /**
     * <p>A transaction can have a fee attached, which is defined as the difference between the input values
     * and output values. Any value taken in that is not provided to an output can be claimed by a miner. This
     * is how mining is incentivized in later years of the Bitcoin system when inflation drops. It also provides
     * a way for people to prioritize their transactions over others and is used as a way to make denial of service
     * attacks expensive.</p>
     *
     * <p>This is a dynamic fee (in satoshis) which will be added to the transaction for each kilobyte in size
     * including the first. This is useful as as miners usually sort pending transactions by their fee per unit size
     * when choosing which transactions to add to a block. Note that, to keep this equivalent to Bitcoin Core
     * definition, a kilobyte is defined as 1000 bytes, not 1024.</p>
     */
    public Coin feePerKb = Context.get().getFeePerKb();

    /**
     * <p>Requires that there be enough fee for a default Bitcoin Core to at least relay the transaction.
     * (ie ensure the transaction will not be outright rejected by the network). Defaults to true, you should
     * only set this to false if you know what you're doing.</p>
     *
     * <p>Note that this does not enforce certain fee rules that only apply to transactions which are larger than
     * 26,000 bytes. If you get a transaction which is that large, you should set a feePerKb of at least
     * {@link Transaction#REFERENCE_DEFAULT_MIN_TX_FEE}.</p>
     */
    public boolean ensureMinRequiredFee = Context.get().isEnsureMinRequiredFee();

    /**
     * If true (the default), the inputs will be signed.
     */
    public boolean signInputs = true;

    /**
     * The AES key to use to decrypt the private keys before signing.
     * If null then no decryption will be performed and if decryption is required an exception will be thrown.
     * You can get this from a password by doing wallet.getKeyCrypter().deriveKey(password).
     */
    public KeyParameter aesKey = null;

    /**
     * If not null, the {@link CoinSelector} to use instead of the wallets default. Coin selectors are
     * responsible for choosing which transaction outputs (coins) in a wallet to use given the desired send value
     * amount.
     */
    public CoinSelector coinSelector = null;

    /**
     * If true (the default), the outputs will be shuffled during completion to randomize the location of the change
     * output, if any. This is normally what you want for privacy reasons but in unit tests it can be annoying
     * so it can be disabled here.
     */
    public boolean shuffleOutputs = true;

    /**
     * Specifies what to do with missing signatures left after completing this request. Default strategy is to
     * throw an exception on missing signature ({@link MissingSigsMode#THROW}).
     * @see MissingSigsMode
     */
    public MissingSigsMode missingSigsMode = MissingSigsMode.THROW;

    /**
     * If not null, this exchange rate is recorded with the transaction during completion.
     */
    public ExchangeRate exchangeRate = null;

    /**
     * If not null, this memo is recorded with the transaction during completion. It can be used to record the memo
     * of the payment request that initiated the transaction.
     */
    public String memo = null;

    /**
     * If false (default value), tx fee is paid by the sender If true, tx fee is paid by the recipient/s. If there is
     * more than one recipient, the tx fee is split equally between them regardless of output value and size.
     */
    public boolean recipientsPayFees = false;

    // Tracks if this has been passed to wallet.completeTx already: just a safety check.
    boolean completed;

    private SendRequest() {}

    /**
     * <p>Creates a new SendRequest to the given address for the given value.</p>
     *
     * <p>Be very careful when value is smaller than {@link Transaction#MIN_NONDUST_OUTPUT} as the transaction will
     * likely be rejected by the network in this case.</p>
     */
    public static SendRequest to(Address destination, Coin value) {
        SendRequest req = new SendRequest();
        final NetworkParameters parameters = destination.getParameters();
        checkNotNull(parameters, "Address is for an unknown network");
        req.tx = new Transaction(parameters);
        req.tx.addOutput(value, destination);
        return req;
    }

    /**
     * <p>Creates a new SendRequest to the given pubkey for the given value.</p>
     *
     * <p>Be careful to check the output's value is reasonable using
     * {@link TransactionOutput#getMinNonDustValue(Coin)} afterwards or you risk having the transaction
     * rejected by the network. Note that using {@link SendRequest#to(Address, Coin)} will result
     * in a smaller output, and thus the ability to use a smaller output value without rejection.</p>
     */
    public static SendRequest to(NetworkParameters params, ECKey destination, Coin value) {
        SendRequest req = new SendRequest();
        req.tx = new Transaction(params);
        req.tx.addOutput(value, destination);
        return req;
    }

    /** Simply wraps a pre-built incomplete transaction provided by you. */
    public static SendRequest forTx(Transaction tx) {
        SendRequest req = new SendRequest();
        req.tx = tx;
        return req;
    }

    public static SendRequest emptyWallet(Address destination) {
        SendRequest req = new SendRequest();
        final NetworkParameters parameters = destination.getParameters();
        checkNotNull(parameters, "Address is for an unknown network");
        req.tx = new Transaction(parameters);
        req.tx.addOutput(Coin.ZERO, destination);
        req.emptyWallet = true;
        return req;
    }

    /**
     * Construct a SendRequest for a CPFP (child-pays-for-parent) transaction. The resulting transaction is already
     * completed, so you should directly proceed to signing and broadcasting/committing the transaction. CPFP is
     * currently only supported by a few miners, so use with care.
     */
    public static SendRequest childPaysForParent(Wallet wallet, Transaction parentTransaction, Coin feeRaise) {
        TransactionOutput outputToSpend = null;
        for (final TransactionOutput output : parentTransaction.getOutputs()) {
            if (output.isMine(wallet) && output.isAvailableForSpending()
                    && output.getValue().isGreaterThan(feeRaise)) {
                outputToSpend = output;
                break;
            }
        }
        // TODO spend another confirmed output of own wallet if needed
        checkNotNull(outputToSpend, "Can't find adequately sized output that spends to us");

        final Transaction tx = new Transaction(parentTransaction.getParams());
        tx.addInput(outputToSpend);
        tx.addOutput(outputToSpend.getValue().subtract(feeRaise), wallet.freshAddress(KeyPurpose.CHANGE));
        tx.setPurpose(Transaction.Purpose.RAISE_FEE);
        final SendRequest req = forTx(tx);
        req.completed = true;
        return req;
    }

    public static SendRequest toCLTVPaymentChannel(NetworkParameters params, Date releaseTime, ECKey from, ECKey to, Coin value) {
        long time = releaseTime.getTime() / 1000L;
        checkArgument(time >= Transaction.LOCKTIME_THRESHOLD, "Release time was too small");
        return toCLTVPaymentChannel(params, BigInteger.valueOf(time), from, to, value);
    }

    public static SendRequest toCLTVPaymentChannel(NetworkParameters params, int releaseBlock, ECKey from, ECKey to, Coin value) {
        checkArgument(0 <= releaseBlock && releaseBlock < Transaction.LOCKTIME_THRESHOLD, "Block number was too large");
        return toCLTVPaymentChannel(params, BigInteger.valueOf(releaseBlock), from, to, value);
    }

    public static SendRequest toCLTVPaymentChannel(NetworkParameters params, BigInteger time, ECKey from, ECKey to, Coin value) {
        SendRequest req = new SendRequest();
        Script output = ScriptBuilder.createCLTVPaymentChannelOutput(time, from, to);
        req.tx = new Transaction(params);
        req.tx.addOutput(value, output);
        return req;
    }

    /** Copy data from payment request. */
    public SendRequest fromPaymentDetails(PaymentDetails paymentDetails) {
        if (paymentDetails.hasMemo())
            this.memo = paymentDetails.getMemo();
        return this;
    }

    @Override
    public String toString() {
        // print only the user-settable fields
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this).omitNullValues();
        helper.add("emptyWallet", emptyWallet);
        helper.add("changeAddress", changeAddress);
        helper.add("feePerKb", feePerKb);
        helper.add("ensureMinRequiredFee", ensureMinRequiredFee);
        helper.add("signInputs", signInputs);
        helper.add("aesKey", aesKey != null ? "set" : null); // careful to not leak the key
        helper.add("coinSelector", coinSelector);
        helper.add("shuffleOutputs", shuffleOutputs);
        helper.add("recipientsPayFees", recipientsPayFees);
        return helper.toString();
    }
}