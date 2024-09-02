/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.core;

import com.google.common.base.MoreObjects;
import com.google.common.math.IntMath;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.LockTime.HeightLock;
import org.bitcoinj.core.LockTime.TimeLock;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptError;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.utils.ExchangeRate;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletTransaction.Pool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

import static org.bitcoinj.base.internal.Preconditions.check;
import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;
import static org.bitcoinj.core.ProtocolVersion.WITNESS_VERSION;
import static org.bitcoinj.base.internal.ByteUtils.writeInt32LE;
import static org.bitcoinj.base.internal.ByteUtils.writeInt64LE;

/**
 * <p>A transaction represents the movement of coins from some addresses to some other addresses. It can also represent
 * the minting of new coins. A Transaction object corresponds to the equivalent in the Bitcoin C++ implementation.</p>
 *
 * <p>Transactions are the fundamental atoms of Bitcoin and have many powerful features. Read
 * <a href="https://bitcoinj.github.io/working-with-transactions">"Working with transactions"</a> in the
 * documentation to learn more about how to use this class.</p>
 *
 * <p>All Bitcoin transactions are at risk of being reversed, though the risk is much less than with traditional payment
 * systems. Transactions have <i>confidence levels</i>, which help you decide whether to trust a transaction or not.
 * Whether to trust a transaction is something that needs to be decided on a case by case basis - a rule that makes
 * sense for selling MP3s might not make sense for selling cars, or accepting payments from a family member. If you
 * are building a wallet, how to present confidence to your users is something to consider carefully.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class Transaction extends BaseMessage {
    private static final Comparator<Transaction> SORT_TX_BY_ID = Comparator.comparing(Transaction::getTxId);

    /**
     * A comparator that can be used to sort transactions by their updateTime field. The ordering goes from most recent
     * into the past. Transactions with an unknown update time will go to the end.
     */
    public static final Comparator<Transaction> SORT_TX_BY_UPDATE_TIME = Comparator.comparing(
                    Transaction::sortableUpdateTime,
                    Comparator.reverseOrder())
            .thenComparing(SORT_TX_BY_ID);

    // helps the above comparator by handling transactions with unknown update time
    private static Instant sortableUpdateTime(Transaction tx) {
        return tx.updateTime().orElse(Instant.EPOCH);
    }

    /**
     * A comparator that can be used to sort transactions by their chain height. Unconfirmed transactions will go to
     * the end.
     */
    public static final Comparator<Transaction> SORT_TX_BY_HEIGHT = Comparator.comparing(
                    Transaction::sortableBlockHeight,
                    Comparator.reverseOrder())
            .thenComparing(SORT_TX_BY_ID);

    // helps the above comparator by handling unconfirmed transactions
    private static int sortableBlockHeight(Transaction tx) {
        TransactionConfidence confidence = tx.getConfidence();
        return confidence.getConfidenceType() == ConfidenceType.BUILDING ?
                confidence.getAppearedAtChainHeight() :
                Block.BLOCK_HEIGHT_UNKNOWN;
    }

    private static final Logger log = LoggerFactory.getLogger(Transaction.class);

    /**
     * When this bit is set in protocolVersion, do not include witness. The actual value is the same as in Bitcoin Core
     * for consistency.
     */
    public static final int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;

    /**
     * @deprecated use {@link LockTime#THRESHOLD} or
     *                 {@code lockTime instanceof HeightLock} or
     *                 {@code lockTime instanceof TimeLock}
     **/
    @Deprecated
    public static final int LOCKTIME_THRESHOLD = (int) LockTime.THRESHOLD;

    /** How many bytes a transaction can be before it won't be relayed anymore. Currently 100kb. */
    public static final int MAX_STANDARD_TX_SIZE = 100_000;

    /**
     * If feePerKb is lower than this, Bitcoin Core will treat it as if there were no fee.
     */
    public static final Coin REFERENCE_DEFAULT_MIN_TX_FEE = Coin.valueOf(1_000); // 0.01 mBTC

    /**
     * If using this feePerKb, transactions will get confirmed within the next couple of blocks.
     * This should be adjusted from time to time. Last adjustment: February 2017.
     */
    public static final Coin DEFAULT_TX_FEE = Coin.valueOf(100_000); // 1 mBTC

    private final int protocolVersion;

    // These are bitcoin serialized.
    private long version;
    private List<TransactionInput> inputs;
    private List<TransactionOutput> outputs;

    private volatile LockTime vLockTime;

    // This is either the time the transaction was broadcast as measured from the local clock, or the time from the
    // block in which it was included. Note that this can be changed by re-orgs so the wallet may update this field.
    // Old serialized transactions don't have this field, thus null is valid. It is used for returning an ordered
    // list of transactions from a wallet, which is helpful for presenting to users.
    @Nullable private Instant updateTime = null;

    // Data about how confirmed this tx is. Serialized, may be null.
    @Nullable private TransactionConfidence confidence;

    // Records a map of which blocks the transaction has appeared in (keys) to an index within that block (values).
    // The "index" is not a real index, instead the values are only meaningful relative to each other. For example,
    // consider two transactions that appear in the same block, t1 and t2, where t2 spends an output of t1. Both
    // will have the same block hash as a key in their appearsInHashes, but the counter would be 1 and 2 respectively
    // regardless of where they actually appeared in the block.
    //
    // If this transaction is not stored in the wallet, appearsInHashes is null.
    private Map<Sha256Hash, Integer> appearsInHashes;

    /**
     * This enum describes the underlying reason the transaction was created. It's useful for rendering wallet GUIs
     * more appropriately.
     */
    public enum Purpose {
        /** Used when the purpose of a transaction is genuinely unknown. */
        UNKNOWN,
        /** Transaction created to satisfy a user payment request. */
        USER_PAYMENT,
        /** Transaction automatically created and broadcast in order to reallocate money from old to new keys. */
        KEY_ROTATION,
        /** Transaction that uses up pledges to an assurance contract */
        ASSURANCE_CONTRACT_CLAIM,
        /** Transaction that makes a pledge to an assurance contract. */
        ASSURANCE_CONTRACT_PLEDGE,
        /** Send-to-self transaction that exists just to create an output of the right size we can pledge. */
        ASSURANCE_CONTRACT_STUB,
        /** Raise fee, e.g. child-pays-for-parent. */
        RAISE_FEE,
        // In future: de/refragmentation, privacy boosting/mixing, etc.
        // When adding a value, it also needs to be added to wallet.proto, WalletProtobufSerialize.makeTxProto()
        // and WalletProtobufSerializer.readTransaction()!
    }

    private Purpose purpose = Purpose.UNKNOWN;

    /**
     * This field can be used by applications to record the exchange rate that was valid when the transaction happened.
     * It's optional.
     */
    @Nullable
    private ExchangeRate exchangeRate;

    /**
     * This field can be used to record the memo of the payment request that initiated the transaction. It's optional.
     */
    @Nullable
    private String memo;

    /**
     * Constructs an incomplete coinbase transaction with a minimal input script and no outputs.
     *
     * @return coinbase transaction
     */
    public static Transaction coinbase() {
        Transaction tx = new Transaction();
        tx.addInput(TransactionInput.coinbaseInput(tx, new byte[2])); // 2 is minimum
        return tx;
    }

    /**
     * Constructs an incomplete coinbase transaction with given bytes for the input script and no outputs.
     *
     * @param inputScriptBytes  arbitrary bytes for the coinbase input
     * @return coinbase transaction
     */
    public static Transaction coinbase(byte[] inputScriptBytes) {
        Transaction tx = new Transaction();
        tx.addInput(TransactionInput.coinbaseInput(tx, inputScriptBytes));
        return tx;
    }

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static Transaction read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        return Transaction.read(payload, ProtocolVersion.CURRENT.intValue());
    }

    /**
     * Deserialize this message from a given payload, according to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki">BIP144</a> or the
     * <a href="https://en.bitcoin.it/wiki/Protocol_documentation#tx">classic format</a>, depending on if the
     * transaction is segwit or not.
     *
     * @param payload         payload to deserialize from
     * @param protocolVersion protocol version to use for deserialization
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static Transaction read(ByteBuffer payload, int protocolVersion) throws BufferUnderflowException, ProtocolException {
        Transaction tx = new Transaction(protocolVersion);
        boolean allowWitness = allowWitness(protocolVersion);

        // version
        tx.version = ByteUtils.readUint32(payload);
        byte flags = 0;
        // Try to parse the inputs. In case the dummy is there, this will be read as an empty array list.
        tx.readInputs(payload);
        if (tx.inputs.size() == 0 && allowWitness) {
            // We read a dummy or an empty input
            flags = payload.get();

            if (flags != 0) {
                tx.readInputs(payload);
                tx.readOutputs(payload);
            } else {
                tx.outputs = new ArrayList<>(0);
            }
        } else {
            // We read non-empty inputs. Assume normal outputs follows.
            tx.readOutputs(payload);
        }

        if (((flags & 1) != 0) && allowWitness) {
            // The witness flag is present, and we support witnesses.
            flags ^= 1;
            // script_witnesses
            tx.readWitnesses(payload);
            if (!tx.hasWitnesses()) {
                // It's illegal to encode witnesses when all witness stacks are empty.
                throw new ProtocolException("Superfluous witness record");
            }
        }
        if (flags != 0) {
            // Unknown flag in the serialization
            throw new ProtocolException("Unknown transaction optional data");
        }
        // lock_time
        tx.vLockTime = LockTime.of(ByteUtils.readUint32(payload));
        return tx;
    }

    private Transaction(int protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public Transaction() {
        this.protocolVersion = ProtocolVersion.CURRENT.intValue();
        version = 1;
        inputs = new ArrayList<>();
        outputs = new ArrayList<>();
        // We don't initialize appearsIn deliberately as it's only useful for transactions stored in the wallet.
        vLockTime = LockTime.unset();
    }

    /**
     * Returns the transaction id as you see them in block explorers. It is used as a reference by transaction inputs
     * via outpoints.
     */
    public Sha256Hash getTxId() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            bitcoinSerializeToStream(baos, false);
        } catch (IOException e) {
            throw new RuntimeException(e); // cannot happen
        }
        return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(baos.toByteArray()));
    }

    /**
     * Returns if tx witnesses are allowed based on the protocol version
     */
    private static boolean allowWitness(int protocolVersion) {
        return (protocolVersion & SERIALIZE_TRANSACTION_NO_WITNESS) == 0
                && protocolVersion >= WITNESS_VERSION.intValue();
    }

    /**
     * Returns the witness transaction id (aka witness id) as per BIP144. For transactions without witness, this is the
     * same as {@link #getTxId()}.
     */
    public Sha256Hash getWTxId() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            bitcoinSerializeToStream(baos, hasWitnesses());
        } catch (IOException e) {
            throw new RuntimeException(e); // cannot happen
        }
        return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(baos.toByteArray()));
    }

    /** Gets the transaction weight as defined in BIP141. */
    public int getWeight() {
        if (!hasWitnesses())
            return this.messageSize() * 4;
        try (final ByteArrayOutputStream stream = new ByteArrayOutputStream(255)) { // just a guess at an average tx length
            bitcoinSerializeToStream(stream, false);
            final int baseSize = stream.size();
            stream.reset();
            bitcoinSerializeToStream(stream, true);
            final int totalSize = stream.size();
            return baseSize * 3 + totalSize;
        } catch (IOException e) {
            throw new RuntimeException(e); // cannot happen
        }
    }

    /** Gets the virtual transaction size as defined in BIP141. */
    public int getVsize() {
        if (!hasWitnesses())
            return this.messageSize();
        return IntMath.divide(getWeight(), 4, RoundingMode.CEILING); // round up
    }


    /**
     * Gets the sum of all transaction inputs, regardless of who owns them.
     * <p>
     * <b>Warning:</b> Inputs with {@code null} {@link TransactionInput#getValue()} are silently skipped. Before completing
     * or signing a transaction you should verify that there are no inputs with {@code null} values.
     * @return The sum of all inputs with non-null values.
     */
    public Coin getInputSum() {
        return inputs.stream()
                .map(TransactionInput::getValue)
                .filter(Objects::nonNull)
                .reduce(Coin.ZERO, Coin::add);
    }

    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet.
     */
    public Coin getValueSentToMe(TransactionBag transactionBag) {
        // This is tested in WalletTest.
        Coin v = Coin.ZERO;
        for (TransactionOutput o : outputs) {
            if (!o.isMineOrWatched(transactionBag)) continue;
            v = v.add(o.getValue());
        }
        return v;
    }

    /**
     * Returns a map of block [hashes] which contain the transaction mapped to relativity counters, or null if this
     * transaction doesn't have that data because it's not stored in the wallet or because it has never appeared in a
     * block.
     */
    @Nullable
    public Map<Sha256Hash, Integer> getAppearsInHashes() {
        return appearsInHashes != null ? Collections.unmodifiableMap(new HashMap<>(appearsInHashes)) : null;
    }

    /**
     * Convenience wrapper around getConfidence().getConfidenceType()
     * @return true if this transaction hasn't been seen in any block yet.
     */
    public boolean isPending() {
        return getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.PENDING;
    }

    /**
     * <p>Puts the given block in the internal set of blocks in which this transaction appears. This is
     * used by the wallet to ensure transactions that appear on side chains are recorded properly even though the
     * block stores do not save the transaction data at all.</p>
     *
     * <p>If there is a re-org this will be called once for each block that was previously seen, to update which block
     * is the best chain. The best chain block is guaranteed to be called last. So this must be idempotent.</p>
     *
     * <p>Sets updatedAt to be the earliest valid block time where this tx was seen.</p>
     *
     * @param block     The {@link StoredBlock} in which the transaction has appeared.
     * @param bestChain whether to set the updatedAt timestamp from the block header (only if not already set)
     * @param relativityOffset A number that disambiguates the order of transactions within a block.
     */
    public void setBlockAppearance(StoredBlock block, boolean bestChain, int relativityOffset) {
        Instant blockTime = block.getHeader().time();
        if (bestChain && (updateTime == null || updateTime.equals(Instant.EPOCH) || updateTime.isAfter(blockTime))) {
            updateTime = blockTime;
        }

        addBlockAppearance(block.getHeader().getHash(), relativityOffset);

        if (bestChain) {
            TransactionConfidence transactionConfidence = getConfidence();
            // This sets type to BUILDING and depth to one.
            transactionConfidence.setAppearedAtChainHeight(block.getHeight());
        }
    }

    public void addBlockAppearance(final Sha256Hash blockHash, int relativityOffset) {
        if (appearsInHashes == null) {
            // TODO: This could be a lot more memory efficient as we'll typically only store one element.
            appearsInHashes = new TreeMap<>();
        }
        appearsInHashes.put(blockHash, relativityOffset);
    }

    /**
     * Calculates the sum of the inputs that are spending coins with keys in the wallet. This requires the
     * transactions sending coins to those keys to be in the wallet. This method will not attempt to download the
     * blocks containing the input transactions if the key is in the wallet but the transactions are not.
     *
     * @return sum of the inputs that are spending coins with keys in the wallet
     */
    public Coin getValueSentFromMe(TransactionBag wallet) throws ScriptException {
        // This is tested in WalletTest.
        Coin v = Coin.ZERO;
        for (TransactionInput input : inputs) {
            // This input is taking value from a transaction in our wallet. To discover the value,
            // we must find the connected transaction.
            TransactionOutput connected = input.getConnectedOutput(wallet.getTransactionPool(Pool.UNSPENT));
            if (connected == null)
                connected = input.getConnectedOutput(wallet.getTransactionPool(Pool.SPENT));
            if (connected == null)
                connected = input.getConnectedOutput(wallet.getTransactionPool(Pool.PENDING));
            if (connected == null)
                continue;
            // The connected output may be the change to the sender of a previous input sent to this wallet. In this
            // case we ignore it.
            if (!connected.isMineOrWatched(wallet))
                continue;
            v = v.add(connected.getValue());
        }
        return v;
    }

    /**
     * Gets the sum of the outputs of the transaction. If the outputs are less than the inputs, it does not count the fee.
     * @return the sum of the outputs regardless of who owns them.
     */
    public Coin getOutputSum() {
        return outputs.stream()
                .map(TransactionOutput::getValue)
                .reduce(Coin.ZERO, Coin::add);
    }

    /**
     * Returns the difference of {@link Transaction#getValueSentToMe(TransactionBag)} and {@link Transaction#getValueSentFromMe(TransactionBag)}.
     */
    public Coin getValue(TransactionBag wallet) throws ScriptException {
        return getValueSentToMe(wallet).subtract(getValueSentFromMe(wallet));
    }

    /**
     * The transaction fee is the difference of the value of all inputs and the value of all outputs. Currently, the fee
     * can only be determined for transactions created by us.
     *
     * @return fee, or null if it cannot be determined
     */
    public Coin getFee() {
        Coin fee = Coin.ZERO;
        if (inputs.isEmpty() || outputs.isEmpty()) // Incomplete transaction
            return null;
        for (TransactionInput input : inputs) {
            if (input.getValue() == null)
                return null;
            fee = fee.add(input.getValue());
        }
        for (TransactionOutput output : outputs) {
            fee = fee.subtract(output.getValue());
        }
        return fee;
    }

    /**
     * Returns true if any of the outputs is marked as spent.
     */
    public boolean isAnyOutputSpent() {
        for (TransactionOutput output : outputs) {
            if (!output.isAvailableForSpending())
                return true;
        }
        return false;
    }

    /**
     * Returns false if this transaction has at least one output that is owned by the given wallet and unspent, true
     * otherwise.
     */
    public boolean isEveryOwnedOutputSpent(TransactionBag transactionBag) {
        for (TransactionOutput output : outputs) {
            if (output.isAvailableForSpending() && output.isMineOrWatched(transactionBag))
                return false;
        }
        return true;
    }

    /**
     * Returns the earliest time at which the transaction was seen (broadcast or included into the chain),
     * or empty if that information isn't available.
     */
    public Optional<Instant> updateTime() {
        return Optional.ofNullable(updateTime);
    }

    /**
     * Sets the update time of this transaction.
     * @param updateTime update time
     */
    public void setUpdateTime(Instant updateTime) {
        this.updateTime = Objects.requireNonNull(updateTime);
    }

    /**
     * Clears the update time of this transaction.
     */
    public void clearUpdateTime() {
        this.updateTime = null;
    }

    /**
     * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
     * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
     */
    public enum SigHash {
        ALL(1),
        NONE(2),
        SINGLE(3),
        ANYONECANPAY(0x80), // Caution: Using this type in isolation is non-standard. Treated similar to ANYONECANPAY_ALL.
        ANYONECANPAY_ALL(0x81),
        ANYONECANPAY_NONE(0x82),
        ANYONECANPAY_SINGLE(0x83),
        UNSET(0); // Caution: Using this type in isolation is non-standard. Treated similar to ALL.

        public final int value;

        /**
         * @param value
         */
        SigHash(final int value) {
            this.value = value;
        }

        /**
         * @return the value as a byte
         */
        public byte byteValue() {
            return (byte) this.value;
        }
    }

    /**
     * @deprecated Instead use SigHash.ANYONECANPAY.value or SigHash.ANYONECANPAY.byteValue() as appropriate.
     */
    public static final byte SIGHASH_ANYONECANPAY_VALUE = (byte) 0x80;

    private void readInputs(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        VarInt numInputsVarInt = VarInt.read(payload);
        check(numInputsVarInt.fitsInt(), BufferUnderflowException::new);
        int numInputs = numInputsVarInt.intValue();
        inputs = new ArrayList<>(Math.min((int) numInputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (long i = 0; i < numInputs; i++) {
            inputs.add(TransactionInput.read(payload, this));
        }
    }

    private void readOutputs(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        VarInt numOutputsVarInt = VarInt.read(payload);
        check(numOutputsVarInt.fitsInt(), BufferUnderflowException::new);
        int numOutputs = numOutputsVarInt.intValue();
        outputs = new ArrayList<>(Math.min((int) numOutputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (long i = 0; i < numOutputs; i++) {
            outputs.add(TransactionOutput.read(payload, this));
        }
    }

    private void readWitnesses(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        for (TransactionInput input : inputs) {
            input.setWitness(TransactionWitness.read(payload));
        }
    }

    /** @return true of the transaction has any witnesses in any of its inputs */
    public boolean hasWitnesses() {
        return inputs.stream().anyMatch(TransactionInput::hasWitness);
    }

    /**
     * The priority (coin age) calculation doesn't use the regular message size, but rather one adjusted downwards
     * for the number of inputs. The goal is to incentivise cleaning up the UTXO set with free transactions, if one
     * can do so.
     */
    public int getMessageSizeForPriorityCalc() {
        int size = this.messageSize();
        for (TransactionInput input : inputs) {
            // 41: min size of an input
            // 110: enough to cover a compressed pubkey p2sh redemption (somewhat arbitrary).
            int benefit = 41 + Math.min(110, input.getScriptSig().program().length);
            if (size > benefit)
                size -= benefit;
        }
        return size;
    }

    /**
     * A coinbase transaction is one that creates a new coin. They are the first transaction in each block and their
     * value is determined by a formula that all implementations of Bitcoin share. In 2011 the value of a coinbase
     * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined not only by its
     * position in a block but by the data in the inputs.
     */
    public boolean isCoinBase() {
        return inputs.size() == 1 && inputs.get(0).isCoinBase();
    }

    @Override
    public String toString() {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this);
        helper.addValue(toString(null, null));
        return helper.toString();
    }

    /**
     * A human-readable version of the transaction useful for debugging. The format is not guaranteed to be stable.
     * @param chain if provided, will be used to estimate lock times (if set)
     * @param network if provided, network for output scripts converted to addresses
     */
    public String toString(@Nullable AbstractBlockChain chain, @Nullable Network network) {
        return toString(chain, network, "");
    }

    /**
     * A human-readable version of the transaction useful for debugging. The format is not guaranteed to be stable.
     * @param chain if provided, will be used to estimate lock times (if set)
     * @param network if provided, network for output scripts converted to addresses
     * @param indent characters that will be prepended to each line of the output
     */
    public String toString(@Nullable AbstractBlockChain chain, @Nullable Network network, CharSequence indent) {
        Objects.requireNonNull(indent);
        StringBuilder s = new StringBuilder();
        Sha256Hash txId = getTxId(), wTxId = getWTxId();
        s.append(indent).append(txId);
        if (!wTxId.equals(txId))
            s.append(", wtxid ").append(wTxId);
        s.append('\n');
        int weight = getWeight();
        int size = this.messageSize();
        int vsize = getVsize();
        s.append(indent).append("weight: ").append(weight).append(" wu, ");
        if (size != vsize)
            s.append(vsize).append(" virtual bytes, ");
        s.append(size).append(" bytes\n");
        updateTime().ifPresent(
                time -> s.append(indent).append("updated: ").append(TimeUtils.dateTimeFormat(time)).append('\n'));
        if (version != 1)
            s.append(indent).append("version ").append(version).append('\n');

        if (isTimeLocked()) {
            s.append(indent).append("time locked until ");
            LockTime locktime = lockTime();
            s.append(locktime);
            if (locktime instanceof HeightLock) {
                if (chain != null) {
                    s.append(" (estimated to be reached at ")
                            .append(TimeUtils.dateTimeFormat(chain.estimateBlockTimeInstant(((HeightLock) locktime).blockHeight())))
                            .append(')');
                }
            }
            s.append('\n');
        }
        if (hasRelativeLockTime()) {
            s.append(indent).append("has relative lock time\n");
        }
        if (isOptInFullRBF()) {
            s.append(indent).append("opts into full replace-by-fee\n");
        }
        if (purpose != null)
            s.append(indent).append("purpose: ").append(purpose).append('\n');
        if (isCoinBase()) {
            s.append(indent).append("coinbase\n");
        } else if (!inputs.isEmpty()) {
            int i = 0;
            for (TransactionInput in : inputs) {
                s.append(indent).append("   ");
                s.append("in   ");

                try {
                    s.append(in.getScriptSig());
                    final Coin value = in.getValue();
                    if (value != null)
                        s.append("  ").append(value.toFriendlyString());
                    s.append('\n');
                    if (in.hasWitness()) {
                        s.append(indent).append("        witness:");
                        s.append(in.getWitness());
                        s.append('\n');
                    }
                    final TransactionOutPoint outpoint = in.getOutpoint();
                    final TransactionOutput connectedOutput = outpoint.getConnectedOutput();
                    s.append(indent).append("        ");
                    if (connectedOutput != null) {
                        Script scriptPubKey = connectedOutput.getScriptPubKey();
                        ScriptType scriptType = scriptPubKey.getScriptType();
                        if (scriptType != null) {
                            s.append(scriptType);
                            if (network != null)
                                s.append(" addr:").append(scriptPubKey.getToAddress(network));
                        } else {
                            s.append("unknown script type");
                        }
                    } else {
                        s.append("unconnected");
                    }
                    s.append("  outpoint:").append(outpoint).append('\n');
                    if (in.hasSequence()) {
                        s.append(indent).append("        sequence:").append(Long.toHexString(in.getSequenceNumber()));
                        if (in.isOptInFullRBF())
                            s.append(", opts into full RBF");
                        if (version >= 2 && in.hasRelativeLockTime())
                            s.append(", has RLT");
                        s.append('\n');
                    }
                } catch (Exception e) {
                    s.append("[exception: ").append(e.getMessage()).append("]\n");
                }
                i++;
            }
        } else {
            s.append(indent).append("   ");
            s.append("INCOMPLETE: No inputs!\n");
        }
        for (TransactionOutput out : outputs) {
            s.append(indent).append("   ");
            s.append("out  ");
            try {
                Script scriptPubKey = out.getScriptPubKey();
                s.append(scriptPubKey.chunks().size() > 0 ? scriptPubKey.toString() : "<no scriptPubKey>");
                s.append("  ");
                s.append(out.getValue().toFriendlyString());
                s.append('\n');
                s.append(indent).append("        ");
                ScriptType scriptType = scriptPubKey.getScriptType();
                if (scriptType != null) {
                    s.append(scriptType);
                    if (network != null)
                        s.append(" addr:").append(scriptPubKey.getToAddress(network));
                } else {
                    s.append("unknown script type");
                }
                if (!out.isAvailableForSpending()) {
                    s.append("  spent");
                    final TransactionInput spentBy = out.getSpentBy();
                    if (spentBy != null) {
                        s.append(" by:");
                        s.append(spentBy.getParentTransaction().getTxId()).append(':')
                                .append(spentBy.getIndex());
                    }
                }
                s.append('\n');
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]\n");
            }
        }
        final Coin fee = getFee();
        if (fee != null) {
            s.append(indent).append("   fee  ");
            s.append(fee.multiply(1000).divide(weight).toFriendlyString()).append("/wu, ");
            if (size != vsize)
                s.append(fee.multiply(1000).divide(vsize).toFriendlyString()).append("/vkB, ");
            s.append(fee.multiply(1000).divide(size).toFriendlyString()).append("/kB  ");
            s.append(fee.toFriendlyString()).append('\n');
        }
        return s.toString();
    }

    /**
     * Removes all the inputs from this transaction.
     * Note that this also invalidates the length attribute
     */
    public void clearInputs() {
        for (TransactionInput input : inputs) {
            input.setParent(null);
        }
        inputs.clear();
    }

    /**
     * Adds an input to this transaction that imports value from the given output. Note that this input is <i>not</i>
     * complete and after every input is added with {@link #addInput(TransactionInput)} and every output is added with
     * {@link #addOutput(TransactionOutput)}, a {@link TransactionSigner} must be used to finalize the transaction and finish the inputs
     * off. Otherwise it won't be accepted by the network.
     * @return the newly created input.
     */
    public TransactionInput addInput(TransactionOutput from) {
        return addInput(new TransactionInput(this, from));
    }

    /**
     * Adds an input directly, with no checking that it's valid.
     * @return the new input.
     */
    public TransactionInput addInput(TransactionInput input) {
        input.setParent(this);
        inputs.add(input);
        return input;
    }

    /**
     * Creates and adds an input to this transaction, with no checking that it's valid.
     * @return the newly created input.
     */
    public TransactionInput addInput(Sha256Hash spendTxHash, long outputIndex, Script script) {
        return addInput(new TransactionInput(this, script.program(), new TransactionOutPoint(outputIndex, spendTxHash)));
    }

    /**
     * Adds a new and fully signed input for the given parameters. Note that this method is <b>not</b> thread safe
     * and requires external synchronization. Please refer to general documentation on Bitcoin scripting and contracts
     * to understand the values of sigHash and anyoneCanPay: otherwise you can use the other form of this method
     * that sets them to typical defaults.
     *
     * @param prevOut A reference to the output being spent
     * @param scriptPubKey The scriptPubKey of the output
     * @param amount The amount of the output (which is part of the signature hash for segwit)
     * @param sigKey The signing key
     * @param sigHash enum specifying how the transaction hash is calculated
     * @param anyoneCanPay anyone-can-pay hashing
     * @return The newly created input
     * @throws ScriptException if the scriptPubKey is something we don't know how to sign.
     */
    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, Coin amount, ECKey sigKey,
                                           SigHash sigHash, boolean anyoneCanPay) throws ScriptException {
        // Verify the API user didn't try to do operations out of order.
        checkState(!outputs.isEmpty(), () ->
                "attempting to sign tx without outputs");
        if (amount == null || amount.value <= 0) {
            log.warn("Illegal amount value. Amount is required for SegWit transactions.");
        }
        TransactionInput input = new TransactionInput(this, new byte[] {}, prevOut, amount);
        addInput(input);
        int inputIndex = inputs.size() - 1;
        if (ScriptPattern.isP2PK(scriptPubKey)) {
            TransactionSignature signature = calculateSignature(inputIndex, sigKey, scriptPubKey, sigHash,
                    anyoneCanPay);
            input.setScriptSig(ScriptBuilder.createInputScript(signature));
            input.setWitness(null);
        } else if (ScriptPattern.isP2PKH(scriptPubKey)) {
            TransactionSignature signature = calculateSignature(inputIndex, sigKey, scriptPubKey, sigHash,
                    anyoneCanPay);
            input.setScriptSig(ScriptBuilder.createInputScript(signature, sigKey));
            input.setWitness(null);
        } else if (ScriptPattern.isP2WPKH(scriptPubKey)) {
            Script scriptCode = ScriptBuilder.createP2PKHOutputScript(sigKey);
            TransactionSignature signature = calculateWitnessSignature(inputIndex, sigKey, scriptCode, input.getValue(),
                    sigHash, anyoneCanPay);
            input.setScriptSig(ScriptBuilder.createEmpty());
            input.setWitness(TransactionWitness.redeemP2WPKH(signature, sigKey));
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Don't know how to sign for this kind of scriptPubKey: " + scriptPubKey);
        }
        return input;
    }

    /**
     * @param prevOut A reference to the output being spent
     * @param scriptPubKey The scriptPubKey of the output
     * @param sigKey The signing key
     * @param sigHash enum specifying how the transaction hash is calculated
     * @param anyoneCanPay anyone-can-pay hashing
     * @return The newly created input
     * @throws ScriptException if the scriptPubKey is something we don't know how to sign.
     * @deprecated Use {@link Transaction#addSignedInput(TransactionOutPoint, Script, Coin, ECKey, SigHash, boolean)}
     */
    @Deprecated
    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, ECKey sigKey,
                                           SigHash sigHash, boolean anyoneCanPay) throws ScriptException {
        return addSignedInput(prevOut, scriptPubKey, null, sigKey, sigHash, anyoneCanPay);
    }

    /**
     * Adds a new and fully signed input for the given parameters. Note that this method is <b>not</b> thread safe
     * and requires external synchronization.
     * Defaults to {@link SigHash#ALL} and "false" for the anyoneCanPay flag. This is normally what you want.
     * @param prevOut A reference to the output being spent
     * @param scriptPubKey The scriptPubKey of the output
     * @param amount The amount of the output (which is part of the signature hash for segwit)
     * @param sigKey The signing key
     * @return The newly created input
     * @throws ScriptException if the scriptPubKey is something we don't know how to sign.
     */
    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, Coin amount, ECKey sigKey) throws ScriptException {
        return addSignedInput(prevOut, scriptPubKey, amount, sigKey, SigHash.ALL, false);
    }

    /**
     * @param prevOut A reference to the output being spent
     * @param scriptPubKey The scriptPubKey of the output
     * @param sigKey The signing key
     * @return The newly created input
     * @throws ScriptException if the scriptPubKey is something we don't know how to sign.
     * @deprecated Use {@link Transaction#addSignedInput(TransactionOutPoint, Script, Coin, ECKey)}
     */
    @Deprecated
    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, ECKey sigKey) throws ScriptException {
        return addSignedInput(prevOut, scriptPubKey, null, sigKey);
    }

    /**
     * Adds an input that points to the given output and contains a valid signature for it, calculated using the
     * signing key. Defaults to {@link SigHash#ALL} and "false" for the anyoneCanPay flag. This is normally what you want.
     * @param output output to sign and use as input
     * @param sigKey The signing key
     * @return The newly created input
     */
    public TransactionInput addSignedInput(TransactionOutput output, ECKey sigKey) {
        return addSignedInput(output, sigKey, SigHash.ALL, false);
    }

    /**
     * Adds an input that points to the given output and contains a valid signature for it, calculated using the
     * signing key.
     * @see Transaction#addSignedInput(TransactionOutPoint, Script, Coin, ECKey, SigHash, boolean)
     * @param output output to sign and use as input
     * @param sigKey The signing key
     * @param sigHash enum specifying how the transaction hash is calculated
     * @param anyoneCanPay anyone-can-pay hashing
     * @return The newly created input
     */
    public TransactionInput addSignedInput(TransactionOutput output, ECKey sigKey, SigHash sigHash, boolean anyoneCanPay) {
        Objects.requireNonNull(output.getValue(), "TransactionOutput.getValue() must not be null");
        checkState(output.getValue().value > 0, () ->
                "transactionOutput.getValue() must not be greater than zero");
        return addSignedInput(output.getOutPointFor(), output.getScriptPubKey(), output.getValue(), sigKey, sigHash, anyoneCanPay);
    }

    /**
     * Removes all the outputs from this transaction.
     * Note that this also invalidates the length attribute
     */
    public void clearOutputs() {
        for (TransactionOutput output : outputs) {
            output.setParent(null);
        }
        outputs.clear();
    }

    /**
     * Adds the given output to this transaction. The output must be completely initialized. Returns the given output.
     */
    public TransactionOutput addOutput(TransactionOutput to) {
        to.setParent(this);
        outputs.add(to);
        return to;
    }

    /**
     * Creates an output based on the given address and value, adds it to this transaction, and returns the new output.
     */
    public TransactionOutput addOutput(Coin value, Address address) {
        return addOutput(new TransactionOutput(this, value, address));
    }

    /**
     * Creates an output that pays to the given pubkey directly (no address) with the given value, adds it to this
     * transaction, and returns the new output.
     */
    public TransactionOutput addOutput(Coin value, ECKey pubkey) {
        return addOutput(new TransactionOutput(this, value, pubkey));
    }

    /**
     * Creates an output that pays to the given script. The address and key forms are specialisations of this method,
     * you won't normally need to use it unless you're doing unusual things.
     */
    public TransactionOutput addOutput(Coin value, Script script) {
        return addOutput(new TransactionOutput(this, value, script.program()));
    }


    /**
     * Calculates a signature that is valid for being inserted into the input at the given position. This is simply
     * a wrapper around calling {@link Transaction#hashForSignature(int, byte[], Transaction.SigHash, boolean)}
     * followed by {@link ECKey#sign(Sha256Hash)} and then returning a new {@link TransactionSignature}. The key
     * must be usable for signing as-is: if the key is encrypted it must be decrypted first external to this method.
     *
     * @param inputIndex Which input to calculate the signature for, as an index.
     * @param key The private key used to calculate the signature.
     * @param redeemScript Byte-exact contents of the scriptPubKey that is being satisfied, or the P2SH redeem script.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                                byte[] redeemScript,
                                                                SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, redeemScript, hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash), hashType, anyoneCanPay);
    }

    /**
     * Calculates a signature that is valid for being inserted into the input at the given position. This is simply
     * a wrapper around calling {@link Transaction#hashForSignature(int, byte[], Transaction.SigHash, boolean)}
     * followed by {@link ECKey#sign(Sha256Hash)} and then returning a new {@link TransactionSignature}.
     *
     * @param inputIndex Which input to calculate the signature for, as an index.
     * @param key The private key used to calculate the signature.
     * @param redeemScript The scriptPubKey that is being satisfied, or the P2SH redeem script.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                                 Script redeemScript,
                                                                 SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, redeemScript.program(), hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash), hashType, anyoneCanPay);
    }

    /**
     * Calculates a signature that is valid for being inserted into the input at the given position. This is simply
     * a wrapper around calling {@link Transaction#hashForSignature(int, byte[], Transaction.SigHash, boolean)}
     * followed by {@link ECKey#sign(Sha256Hash)} and then returning a new {@link TransactionSignature}. The key
     * must be usable for signing as-is: if the key is encrypted it must be decrypted first external to this method.
     *
     * @param inputIndex Which input to calculate the signature for, as an index.
     * @param key The private key used to calculate the signature.
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @param redeemScript Byte-exact contents of the scriptPubKey that is being satisfied, or the P2SH redeem script.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                   @Nullable AesKey aesKey,
                                                   byte[] redeemScript,
                                                   SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, redeemScript, hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash, aesKey), hashType, anyoneCanPay);
    }

    /**
     * Calculates a signature that is valid for being inserted into the input at the given position. This is simply
     * a wrapper around calling {@link Transaction#hashForSignature(int, byte[], Transaction.SigHash, boolean)}
     * followed by {@link ECKey#sign(Sha256Hash)} and then returning a new {@link TransactionSignature}.
     *
     * @param inputIndex Which input to calculate the signature for, as an index.
     * @param key The private key used to calculate the signature.
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @param redeemScript The scriptPubKey that is being satisfied, or the P2SH redeem script.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                   @Nullable AesKey aesKey,
                                                   Script redeemScript,
                                                   SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, redeemScript.program(), hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash, aesKey), hashType, anyoneCanPay);
    }

    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction. How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     *
     * <p>This is a low level API and when using the regular {@link Wallet} class you don't have to call this yourself.
     * When working with more complex transaction types and contracts, it can be necessary. When signing a P2SH output
     * the redeemScript should be the script encoded into the scriptSig field, for normal transactions, it's the
     * scriptPubKey of the output you're signing for.</p>
     *
     * @param inputIndex input the signature is being calculated for. Tx signatures are always relative to an input.
     * @param redeemScript the bytes that should be in the given input during signing.
     * @param type Should be SigHash.ALL
     * @param anyoneCanPay should be false.
     */
    public Sha256Hash hashForSignature(int inputIndex, byte[] redeemScript,
                                                    SigHash type, boolean anyoneCanPay) {
        byte sigHashType = (byte) TransactionSignature.calcSigHashValue(type, anyoneCanPay);
        return hashForSignature(inputIndex, redeemScript, sigHashType);
    }

    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction. How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     *
     * <p>This is a low level API and when using the regular {@link Wallet} class you don't have to call this yourself.
     * When working with more complex transaction types and contracts, it can be necessary. When signing a P2SH output
     * the redeemScript should be the script encoded into the scriptSig field, for normal transactions, it's the
     * scriptPubKey of the output you're signing for.</p>
     *
     * @param inputIndex input the signature is being calculated for. Tx signatures are always relative to an input.
     * @param redeemScript the script that should be in the given input during signing.
     * @param type Should be SigHash.ALL
     * @param anyoneCanPay should be false.
     */
    public Sha256Hash hashForSignature(int inputIndex, Script redeemScript,
                                                    SigHash type, boolean anyoneCanPay) {
        int sigHash = TransactionSignature.calcSigHashValue(type, anyoneCanPay);
        return hashForSignature(inputIndex, redeemScript.program(), (byte) sigHash);
    }

    /**
     * This is required for signatures which use a sigHashType which cannot be represented using SigHash and anyoneCanPay
     * See transaction c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73, which has sigHashType 0
     */
    public Sha256Hash hashForSignature(int inputIndex, byte[] connectedScript, byte sigHashType) {
        // The SIGHASH flags are used in the design of contracts, please see this page for a further understanding of
        // the purposes of the code in this method:
        //
        //   https://en.bitcoin.it/wiki/Contracts

        try {
            // Create a copy of this transaction to operate upon because we need make changes to the inputs and outputs.
            // It would not be thread-safe to change the attributes of the transaction object itself.
            Transaction tx = Transaction.read(ByteBuffer.wrap(serialize()));

            // Clear input scripts in preparation for signing. If we're signing a fresh
            // transaction that step isn't very helpful, but it doesn't add much cost relative to the actual
            // EC math so we'll do it anyway.
            for (int i = 0; i < tx.inputs.size(); i++) {
                TransactionInput input = tx.inputs.get(i);
                input.clearScriptBytes();
                input.setWitness(null);
            }

            // This step has no purpose beyond being synchronized with Bitcoin Core's bugs. OP_CODESEPARATOR
            // is a legacy holdover from a previous, broken design of executing scripts that shipped in Bitcoin 0.1.
            // It was seriously flawed and would have let anyone take anyone elses money. Later versions switched to
            // the design we use today where scripts are executed independently but share a stack. This left the
            // OP_CODESEPARATOR instruction having no purpose as it was only meant to be used internally, not actually
            // ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be required but if we don't
            // do it, we could split off the best chain.
            connectedScript = Script.removeAllInstancesOfOp(connectedScript, ScriptOpCodes.OP_CODESEPARATOR);

            // Set the input to the script of its output. Bitcoin Core does this but the step has no obvious purpose as
            // the signature covers the hash of the prevout transaction which obviously includes the output script
            // already. Perhaps it felt safer to him in some way, or is another leftover from how the code was written.
            TransactionInput input = tx.inputs.get(inputIndex);
            input.setScriptBytes(connectedScript);

            if ((sigHashType & 0x1f) == SigHash.NONE.value) {
                // SIGHASH_NONE means no outputs are signed at all - the signature is effectively for a "blank cheque".
                tx.outputs = new ArrayList<>(0);
                // The signature isn't broken by new versions of the transaction issued by other parties.
                for (int i = 0; i < tx.inputs.size(); i++)
                    if (i != inputIndex)
                        tx.inputs.get(i).setSequenceNumber(0);
            } else if ((sigHashType & 0x1f) == SigHash.SINGLE.value) {
                // SIGHASH_SINGLE means only sign the output at the same index as the input (ie, my output).
                if (inputIndex >= tx.outputs.size()) {
                    // The input index is beyond the number of outputs, it's a buggy signature made by a broken
                    // Bitcoin implementation. Bitcoin Core also contains a bug in handling this case:
                    // any transaction output that is signed in this case will result in both the signed output
                    // and any future outputs to this public key being steal-able by anyone who has
                    // the resulting signature and the public key (both of which are part of the signed tx input).

                    // Bitcoin Core's bug is that SignatureHash was supposed to return a hash and on this codepath it
                    // actually returns the constant "1" to indicate an error, which is never checked for. Oops.
                    return Sha256Hash.wrap("0100000000000000000000000000000000000000000000000000000000000000");
                }
                // In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
                // that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
                tx.outputs = new ArrayList<>(tx.outputs.subList(0, inputIndex + 1));
                for (int i = 0; i < inputIndex; i++)
                    tx.outputs.set(i, new TransactionOutput(tx, Coin.NEGATIVE_SATOSHI, new byte[] {}));
                // The signature isn't broken by new versions of the transaction issued by other parties.
                for (int i = 0; i < tx.inputs.size(); i++)
                    if (i != inputIndex)
                        tx.inputs.get(i).setSequenceNumber(0);
            }

            if ((sigHashType & SigHash.ANYONECANPAY.value) == SigHash.ANYONECANPAY.value) {
                // SIGHASH_ANYONECANPAY means the signature in the input is not broken by changes/additions/removals
                // of other inputs. For example, this is useful for building assurance contracts.
                tx.inputs = new ArrayList<>();
                tx.inputs.add(input);
            }

            ByteArrayOutputStream bos = new ByteArrayOutputStream(255); // just a guess at an average tx length
            tx.bitcoinSerializeToStream(bos, false);
            // We also have to write a hash type (sigHashType is actually an unsigned char)
            writeInt32LE(0x000000ff & sigHashType, bos);
            // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
            // however then we would expect that it is IS reversed.
            Sha256Hash hash = Sha256Hash.twiceOf(bos.toByteArray());
            bos.close();

            return hash;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public TransactionSignature calculateWitnessSignature(
            int inputIndex,
            ECKey key,
            byte[] scriptCode,
            Coin value,
            SigHash hashType,
            boolean anyoneCanPay) {
        Sha256Hash hash = hashForWitnessSignature(inputIndex, scriptCode, value, hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash), hashType, anyoneCanPay);
    }

    public TransactionSignature calculateWitnessSignature(
            int inputIndex,
            ECKey key,
            Script scriptCode,
            Coin value,
            SigHash hashType,
            boolean anyoneCanPay) {
        return calculateWitnessSignature(inputIndex, key, scriptCode.program(), value, hashType, anyoneCanPay);
    }

    public TransactionSignature calculateWitnessSignature(
            int inputIndex,
            ECKey key,
            @Nullable AesKey aesKey,
            byte[] scriptCode,
            Coin value,
            SigHash hashType,
            boolean anyoneCanPay) {
        Sha256Hash hash = hashForWitnessSignature(inputIndex, scriptCode, value, hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash, aesKey), hashType, anyoneCanPay);
    }

    public TransactionSignature calculateWitnessSignature(
            int inputIndex,
            ECKey key,
            @Nullable AesKey aesKey,
            Script scriptCode,
            Coin value,
            SigHash hashType,
            boolean anyoneCanPay) {
        return calculateWitnessSignature(inputIndex, key, aesKey, scriptCode.program(), value, hashType, anyoneCanPay);
    }

    public synchronized Sha256Hash hashForWitnessSignature(
            int inputIndex,
            byte[] scriptCode,
            Coin prevValue,
            SigHash type,
            boolean anyoneCanPay) {
        int sigHash = TransactionSignature.calcSigHashValue(type, anyoneCanPay);
        return hashForWitnessSignature(inputIndex, scriptCode, prevValue, (byte) sigHash);
    }

    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction. How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     *
     * <p>This is a low level API and when using the regular {@link Wallet} class you don't have to call this yourself.
     * When working with more complex transaction types and contracts, it can be necessary. When signing a Witness output
     * the scriptCode should be the script encoded into the scriptSig field, for normal transactions, it's the
     * scriptPubKey of the output you're signing for. (See BIP143: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)</p>
     *
     * @param inputIndex   input the signature is being calculated for. Tx signatures are always relative to an input.
     * @param scriptCode   the script that should be in the given input during signing.
     * @param prevValue    the value of the coin being spent
     * @param type         Should be SigHash.ALL
     * @param anyoneCanPay should be false.
     */
    public synchronized Sha256Hash hashForWitnessSignature(
            int inputIndex,
            Script scriptCode,
            Coin prevValue,
            SigHash type,
            boolean anyoneCanPay) {
        return hashForWitnessSignature(inputIndex, scriptCode.program(), prevValue, type, anyoneCanPay);
    }

    public synchronized Sha256Hash hashForWitnessSignature(
            int inputIndex,
            byte[] scriptCode,
            Coin prevValue,
            byte sigHashType){
        ByteArrayOutputStream bos = new ByteArrayOutputStream(255); // just a guess at an average tx length
        try {
            byte[] hashPrevouts = new byte[32];
            byte[] hashSequence = new byte[32];
            byte[] hashOutputs = new byte[32];
            int basicSigHashType = sigHashType & 0x1f;
            boolean anyoneCanPay = (sigHashType & SigHash.ANYONECANPAY.value) == SigHash.ANYONECANPAY.value;
            boolean signAll = (basicSigHashType != SigHash.SINGLE.value) && (basicSigHashType != SigHash.NONE.value);

            if (!anyoneCanPay) {
                ByteArrayOutputStream bosHashPrevouts = new ByteArrayOutputStream(256);
                for (TransactionInput input : this.inputs) {
                    bosHashPrevouts.write(input.getOutpoint().hash().serialize());
                    writeInt32LE(input.getOutpoint().index(), bosHashPrevouts);
                }
                hashPrevouts = Sha256Hash.hashTwice(bosHashPrevouts.toByteArray());
            }

            if (!anyoneCanPay && signAll) {
                ByteArrayOutputStream bosSequence = new ByteArrayOutputStream(256);
                for (TransactionInput input : this.inputs) {
                    writeInt32LE(input.getSequenceNumber(), bosSequence);
                }
                hashSequence = Sha256Hash.hashTwice(bosSequence.toByteArray());
            }

            if (signAll) {
                ByteArrayOutputStream bosHashOutputs = new ByteArrayOutputStream(256);
                for (TransactionOutput output : this.outputs) {
                    writeInt64LE(
                            BigInteger.valueOf(output.getValue().getValue()),
                            bosHashOutputs
                    );
                    bosHashOutputs.write(VarInt.of(output.getScriptBytes().length).serialize());
                    bosHashOutputs.write(output.getScriptBytes());
                }
                hashOutputs = Sha256Hash.hashTwice(bosHashOutputs.toByteArray());
            } else if (basicSigHashType == SigHash.SINGLE.value && inputIndex < outputs.size()) {
                ByteArrayOutputStream bosHashOutputs = new ByteArrayOutputStream(256);
                writeInt64LE(
                        BigInteger.valueOf(this.outputs.get(inputIndex).getValue().getValue()),
                        bosHashOutputs
                );
                bosHashOutputs.write(VarInt.of(this.outputs.get(inputIndex).getScriptBytes().length).serialize());
                bosHashOutputs.write(this.outputs.get(inputIndex).getScriptBytes());
                hashOutputs = Sha256Hash.hashTwice(bosHashOutputs.toByteArray());
            }
            writeInt32LE(version, bos);
            bos.write(hashPrevouts);
            bos.write(hashSequence);
            bos.write(inputs.get(inputIndex).getOutpoint().hash().serialize());
            writeInt32LE(inputs.get(inputIndex).getOutpoint().index(), bos);
            bos.write(VarInt.of(scriptCode.length).serialize());
            bos.write(scriptCode);
            writeInt64LE(BigInteger.valueOf(prevValue.getValue()), bos);
            writeInt32LE(inputs.get(inputIndex).getSequenceNumber(), bos);
            bos.write(hashOutputs);
            writeInt32LE(this.vLockTime.rawValue(), bos);
            writeInt32LE(0x000000ff & sigHashType, bos);
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }

        return Sha256Hash.twiceOf(bos.toByteArray());
    }

    @Override
    public int messageSize() {
        boolean useSegwit = hasWitnesses() && allowWitness(protocolVersion);
        int size = 4; // version
        if (useSegwit)
            size += 2; // marker, flag
        size += VarInt.sizeOf(inputs.size());
        for (TransactionInput in : inputs)
            size += in.messageSize();
        size += VarInt.sizeOf(outputs.size());
        for (TransactionOutput out : outputs)
            size += out.messageSize();
        if (useSegwit)
            for (TransactionInput in : inputs)
                size += in.getWitness().messageSize();
        size += 4; // locktime
        return size;
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        boolean useSegwit = hasWitnesses() && allowWitness(protocolVersion);
        bitcoinSerializeToStream(stream, useSegwit);
    }

    /**
     * Serialize according to <a href="https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki">BIP144</a> or the
     * <a href="https://en.bitcoin.it/wiki/Protocol_documentation#tx">classic format</a>, depending on if segwit is
     * desired.
     */
    protected void bitcoinSerializeToStream(OutputStream stream, boolean useSegwit) throws IOException {
        // version
        writeInt32LE(version, stream);
        // marker, flag
        if (useSegwit) {
            stream.write(0);
            stream.write(1);
        }
        // txin_count, txins
        stream.write(VarInt.of(inputs.size()).serialize());
        for (TransactionInput in : inputs)
            stream.write(in.serialize());
        // txout_count, txouts
        stream.write(VarInt.of(outputs.size()).serialize());
        for (TransactionOutput out : outputs)
            stream.write(out.serialize());
        // script_witnisses
        if (useSegwit) {
            for (TransactionInput in : inputs)
                stream.write(in.getWitness().serialize());
        }
        // lock_time
        writeInt32LE(vLockTime.rawValue(), stream);
    }

    /**
     * Transactions can have an associated lock time, specified either as a block height or as a timestamp (in seconds
     * since epoch). A transaction is not allowed to be confirmed by miners until the lock time is reached, and
     * since Bitcoin 0.8+ a transaction that did not end its lock period (non final) is considered to be non
     * standard and won't be relayed or included in the memory pool either.
     * @return lock time, wrapped in a {@link LockTime}
     */
    public LockTime lockTime() {
        return vLockTime;
    }

    /** @deprecated use {@link #lockTime()} */
    @Deprecated
    public long getLockTime() {
        return lockTime().rawValue();
    }

    /**
     * Transactions can have an associated lock time, specified either as a block height or as a timestamp (in seconds
     * since epoch). A transaction is not allowed to be confirmed by miners until the lock time is reached, and
     * since Bitcoin 0.8+ a transaction that did not end its lock period (non final) is considered to be non
     * standard and won't be relayed or included in the memory pool either.
     */
    public void setLockTime(long lockTime) {
        boolean seqNumSet = false;
        for (TransactionInput input : inputs) {
            if (input.getSequenceNumber() != TransactionInput.NO_SEQUENCE) {
                seqNumSet = true;
                break;
            }
        }
        if (lockTime != 0 && (!seqNumSet || inputs.isEmpty())) {
            // At least one input must have a non-default sequence number for lock times to have any effect.
            // For instance one of them can be set to zero to make this feature work.
            log.warn("You are setting the lock time on a transaction but none of the inputs have non-default sequence numbers. This will not do what you expect!");
        }
        this.vLockTime = LockTime.of(lockTime);
    }

    public long getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    /** Returns an unmodifiable view of all inputs. */
    public List<TransactionInput> getInputs() {
        return Collections.unmodifiableList(inputs);
    }

    /** Returns an unmodifiable view of all outputs. */
    public List<TransactionOutput> getOutputs() {
        return Collections.unmodifiableList(outputs);
    }

    /**
     * <p>Returns the list of transacion outputs, whether spent or unspent, that match a wallet by address or that are
     * watched by a wallet, i.e., transaction outputs whose script's address is controlled by the wallet and transaction
     * outputs whose script is watched by the wallet.</p>
     *
     * @param transactionBag The wallet that controls addresses and watches scripts.
     * @return linked list of outputs relevant to the wallet in this transaction
     */
    public List<TransactionOutput> getWalletOutputs(TransactionBag transactionBag){
        List<TransactionOutput> walletOutputs = new LinkedList<>();
        for (TransactionOutput o : outputs) {
            if (!o.isMineOrWatched(transactionBag)) continue;
            walletOutputs.add(o);
        }

        return walletOutputs;
    }

    /** Randomly re-orders the transaction outputs: good for privacy */
    public void shuffleOutputs() {
        Collections.shuffle(outputs);
    }

    /** Same as getInputs().get(index). */
    public TransactionInput getInput(long index) {
        return inputs.get((int)index);
    }

    /** Same as getOutputs().get(index) */
    public TransactionOutput getOutput(long index) {
        return outputs.get((int)index);
    }

    /**
     * Gets the output the gihven outpoint is referring to. Note the output must belong to this transaction, or else
     * an {@link IllegalArgumentException} will occur.
     *
     * @param outpoint outpoint referring to the output to get
     * @return output referred to by the given outpoint
     */
    public TransactionOutput getOutput(TransactionOutPoint outpoint) {
        checkArgument(outpoint.hash().equals(this.getTxId()), () ->
                "outpoint poins to a different transaction");
        return getOutput(outpoint.index());
    }

    /**
     * Returns the confidence object for this transaction from the {@link TxConfidenceTable}
     * referenced by the implicit {@link Context}.
     */
    public TransactionConfidence getConfidence() {
        return getConfidence(Context.get());
    }

    /**
     * Returns the confidence object for this transaction from the {@link TxConfidenceTable}
     * referenced by the given {@link Context}.
     */
    TransactionConfidence getConfidence(Context context) {
        return getConfidence(context.getConfidenceTable());
    }

    /**
     * Returns the confidence object for this transaction from the {@link TxConfidenceTable}
     */
    TransactionConfidence getConfidence(TxConfidenceTable table) {
        if (confidence == null)
            confidence = table.getOrCreate(getTxId()) ;
        return confidence;
    }

    /** Check if the transaction has a known confidence */
    public boolean hasConfidence() {
        return getConfidence().getConfidenceType() != TransactionConfidence.ConfidenceType.UNKNOWN;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getTxId().equals(((Transaction)o).getTxId());
    }

    @Override
    public int hashCode() {
        return getTxId().hashCode();
    }

    /**
     * Gets the count of regular SigOps in this transactions
     */
    public int getSigOpCount() throws ScriptException {
        int sigOps = 0;
        for (TransactionInput input : inputs)
            sigOps += Script.getSigOpCount(input.getScriptBytes());
        for (TransactionOutput output : outputs)
            sigOps += Script.getSigOpCount(output.getScriptBytes());
        return sigOps;
    }

    /**
     * Check block height is in coinbase input script, for use after BIP 34
     * enforcement is enabled.
     */
    public void checkCoinBaseHeight(final int height)
            throws VerificationException {
        checkArgument(height >= Block.BLOCK_HEIGHT_GENESIS);
        checkState(isCoinBase());

        // Check block height is in coinbase input script
        final TransactionInput in = this.getInput(0);
        final ScriptBuilder builder = new ScriptBuilder();
        builder.number(height);
        final byte[] expected = builder.build().program();
        final byte[] actual = in.getScriptBytes();
        if (actual.length < expected.length) {
            throw new VerificationException.CoinbaseHeightMismatch("Block height mismatch in coinbase.");
        }
        for (int scriptIdx = 0; scriptIdx < expected.length; scriptIdx++) {
            if (actual[scriptIdx] != expected[scriptIdx]) {
                throw new VerificationException.CoinbaseHeightMismatch("Block height mismatch in coinbase.");
            }
        }
    }

    /** Loops the outputs of a coinbase transaction to locate the witness commitment. */
    public Sha256Hash findWitnessCommitment() {
        checkState(isCoinBase());
        List<TransactionOutput> reversed = new ArrayList<>(outputs);
        Collections.reverse(reversed);
        return reversed.stream()
                        .map(TransactionOutput::getScriptPubKey)
                        .filter(ScriptPattern::isWitnessCommitment)
                        .findFirst()
                        .map(ScriptPattern::extractWitnessCommitmentHash)
                        .orElse(null);
    }

    /**
     * <p>A transaction is time-locked if at least one of its inputs is non-final and it has a lock time. A transaction can
     * also have a relative lock time which this method doesn't tell. Use {@link #hasRelativeLockTime()} to find out.</p>
     *
     * <p>To check if this transaction is final at a given height and time, see {@link Transaction#isFinal(int, Instant)}
     * </p>
     */
    public boolean isTimeLocked() {
        if (!lockTime().isSet())
            return false;
        for (TransactionInput input : getInputs())
            if (input.hasSequence())
                return true;
        return false;
    }

    /**
     * A transaction has a relative lock time
     * (<a href="https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki">BIP 68</a>) if it is version 2 or
     * higher and at least one of its inputs has its {@link TransactionInput#SEQUENCE_LOCKTIME_DISABLE_FLAG} cleared.
     */
    public boolean hasRelativeLockTime() {
        if (version < 2)
            return false;
        for (TransactionInput input : getInputs())
            if (input.hasRelativeLockTime())
                return true;
        return false;
    }

    /**
     * Returns whether this transaction will opt into the
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki">full replace-by-fee </a> semantics.
     */
    public boolean isOptInFullRBF() {
        for (TransactionInput input : getInputs())
            if (input.isOptInFullRBF())
                return true;
        return false;
    }

    /**
     * <p>Returns true if this transaction is considered finalized and can be placed in a block. Non-finalized
     * transactions won't be included by miners and can be replaced with newer versions using sequence numbers.
     * This is useful in certain types of <a href="http://en.bitcoin.it/wiki/Contracts">contracts</a>, such as
     * micropayment channels.</p>
     *
     * <p>Note that currently the replacement feature is disabled in Bitcoin Core and will need to be
     * re-activated before this functionality is useful.</p>
     */
    public boolean isFinal(int height, Instant blockTime) {
        LockTime locktime = lockTime();
        return locktime.rawValue() < (locktime instanceof HeightLock ? height : blockTime.getEpochSecond()) ||
                !isTimeLocked();
    }

    /**
     * Returns either the lock time, if it was specified as a timestamp, or an estimate based on the time in
     * the current head block if it was specified as a block height.
     */
    public Instant estimateUnlockTime(AbstractBlockChain chain) {
        LockTime locktime = lockTime();
        return locktime instanceof HeightLock ?
                chain.estimateBlockTimeInstant(((HeightLock) locktime).blockHeight()) :
                ((TimeLock) locktime).timestamp();
    }

    /**
     * Returns the purpose for which this transaction was created. See the javadoc for {@link Purpose} for more
     * information on the point of this field and what it can be.
     */
    public Purpose getPurpose() {
        return purpose;
    }

    /**
     * Marks the transaction as being created for the given purpose. See the javadoc for {@link Purpose} for more
     * information on the point of this field and what it can be.
     */
    public void setPurpose(Purpose purpose) {
        this.purpose = purpose;
    }

    /**
     * Getter for {@link #exchangeRate}.
     */
    @Nullable
    public ExchangeRate getExchangeRate() {
        return exchangeRate;
    }

    /**
     * Setter for {@link #exchangeRate}.
     */
    public void setExchangeRate(ExchangeRate exchangeRate) {
        this.exchangeRate = exchangeRate;
    }

    /**
     * Returns the transaction {@link #memo}.
     */
    @Nullable
    public String getMemo() {
        return memo;
    }

    /**
     * Set the transaction {@link #memo}. It can be used to record the memo of the payment request that initiated the
     * transaction.
     */
    public void setMemo(String memo) {
        this.memo = memo;
    }

    /**
     * <p>Checks the transaction contents for sanity, in ways that can be done in a standalone manner.
     * Does <b>not</b> perform all checks on a transaction such as whether the inputs are already spent.
     * Specifically this method verifies:</p>
     *
     * <ul>
     *     <li>That there is at least one input and output.</li>
     *     <li>That the serialized size is not larger than the max block size.</li>
     *     <li>That no outputs have negative value.</li>
     *     <li>That the outputs do not sum to larger than the max allowed quantity of coin in the system.</li>
     *     <li>If the tx is a coinbase tx, the coinbase scriptSig size is within range. Otherwise that there are no
     *     coinbase inputs in the tx.</li>
     * </ul>
     *
     * @param network network for the verification rules
     * @param tx      transaction to verify
     * @throws VerificationException if at least one of the rules is violated
     */
    public static void verify(Network network, Transaction tx) throws VerificationException {
        if (tx.inputs.size() == 0 || tx.outputs.size() == 0)
            throw new VerificationException.EmptyInputsOrOutputs();
        if (tx.messageSize() > Block.MAX_BLOCK_SIZE)
            throw new VerificationException.LargerThanMaxBlockSize();

        HashSet<TransactionOutPoint> outpoints = new HashSet<>();
        for (TransactionInput input : tx.inputs) {
            if (outpoints.contains(input.getOutpoint()))
                throw new VerificationException.DuplicatedOutPoint();
            outpoints.add(input.getOutpoint());
        }

        Coin valueOut = Coin.ZERO;
        for (TransactionOutput output : tx.outputs) {
            Coin value = output.getValue();
            if (value.signum() < 0)
                throw new VerificationException.NegativeValueOutput();
            try {
                valueOut = valueOut.add(value);
            } catch (ArithmeticException e) {
                throw new VerificationException.ExcessiveValue();
            }
            if (network.exceedsMaxMoney(valueOut))
                throw new VerificationException.ExcessiveValue();
        }

        if (tx.isCoinBase()) {
            if (tx.inputs.get(0).getScriptBytes().length < 2 || tx.inputs.get(0).getScriptBytes().length > 100)
                throw new VerificationException.CoinbaseScriptSizeOutOfRange();
        } else {
            for (TransactionInput input : tx.inputs)
                if (input.isCoinBase())
                    throw new VerificationException.UnexpectedCoinbaseInput();
        }
    }
}
