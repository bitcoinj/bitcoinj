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

import org.bitcoinj.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptError;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.utils.ExchangeRate;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletTransaction.Pool;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.io.*;
import java.util.*;

import static org.bitcoinj.core.Utils.*;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import java.math.BigInteger;

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
public class Transaction extends ChildMessage {
    /**
     * A comparator that can be used to sort transactions by their updateTime field. The ordering goes from most recent
     * into the past.
     */
    public static final Comparator<Transaction> SORT_TX_BY_UPDATE_TIME = new Comparator<Transaction>() {
        @Override
        public int compare(final Transaction tx1, final Transaction tx2) {
            final long time1 = tx1.getUpdateTime().getTime();
            final long time2 = tx2.getUpdateTime().getTime();
            final int updateTimeComparison = -(Longs.compare(time1, time2));
            //If time1==time2, compare by tx hash to make comparator consistent with equals
            return updateTimeComparison != 0 ? updateTimeComparison : tx1.getHash().compareTo(tx2.getHash());
        }
    };
    /** A comparator that can be used to sort transactions by their chain height. */
    public static final Comparator<Transaction> SORT_TX_BY_HEIGHT = new Comparator<Transaction>() {
        @Override
        public int compare(final Transaction tx1, final Transaction tx2) {
            final TransactionConfidence confidence1 = tx1.getConfidence();
            final int height1 = confidence1.getConfidenceType() == ConfidenceType.BUILDING
                    ? confidence1.getAppearedAtChainHeight() : Block.BLOCK_HEIGHT_UNKNOWN;
            final TransactionConfidence confidence2 = tx2.getConfidence();
            final int height2 = confidence2.getConfidenceType() == ConfidenceType.BUILDING
                    ? confidence2.getAppearedAtChainHeight() : Block.BLOCK_HEIGHT_UNKNOWN;
            final int heightComparison = -(Ints.compare(height1, height2));
            //If height1==height2, compare by tx hash to make comparator consistent with equals
            return heightComparison != 0 ? heightComparison : tx1.getHash().compareTo(tx2.getHash());
        }
    };
    private static final Logger log = LoggerFactory.getLogger(Transaction.class);

    /** Threshold for lockTime: below this value it is interpreted as block number, otherwise as timestamp. **/
    public static final int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
    /** Same but as a BigInteger for CHECKLOCKTIMEVERIFY */
    public static final BigInteger LOCKTIME_THRESHOLD_BIG = BigInteger.valueOf(LOCKTIME_THRESHOLD);

    /** How many bytes a transaction can be before it won't be relayed anymore. Currently 100kb. */
    public static final int MAX_STANDARD_TX_SIZE = 100000;

    /**
     * If feePerKb is lower than this, Bitcoin Core will treat it as if there were no fee.
     */
    public static final Coin REFERENCE_DEFAULT_MIN_TX_FEE = Coin.valueOf(1000); // 0.01 mBTC

    /**
     * If using this feePerKb, transactions will get confirmed within the next couple of blocks.
     * This should be adjusted from time to time. Last adjustment: February 2017.
     */
    public static final Coin DEFAULT_TX_FEE = Coin.valueOf(100000); // 1 mBTC

    /**
     * Any standard (ie P2PKH) output smaller than this value (in satoshis) will most likely be rejected by the network.
     * This is calculated by assuming a standard output will be 34 bytes, and then using the formula used in
     * {@link TransactionOutput#getMinNonDustValue(Coin)}.
     */
    public static final Coin MIN_NONDUST_OUTPUT = Coin.valueOf(546); // satoshis

    // These are bitcoin serialized.
    private long version;
    private ArrayList<TransactionInput> inputs;
    private ArrayList<TransactionOutput> outputs;

    private long lockTime;

    // This is either the time the transaction was broadcast as measured from the local clock, or the time from the
    // block in which it was included. Note that this can be changed by re-orgs so the wallet may update this field.
    // Old serialized transactions don't have this field, thus null is valid. It is used for returning an ordered
    // list of transactions from a wallet, which is helpful for presenting to users.
    private Date updatedAt;

    // This is an in memory helper only. It contains the transaction hash (aka txid), used as a reference by transaction
    // inputs via outpoints.
    private Sha256Hash hash;

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

    // Transactions can be encoded in a way that will use more bytes than is optimal
    // (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs) so that Blocks
    // can properly keep track of optimal encoded size
    private int optimalEncodingMessageSize;

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

    public Transaction(NetworkParameters params) {
        super(params);
        version = 1;
        inputs = new ArrayList<>();
        outputs = new ArrayList<>();
        // We don't initialize appearsIn deliberately as it's only useful for transactions stored in the wallet.
        length = 8; // 8 for std fields
    }

    /**
     * Creates a transaction from the given serialized bytes, eg, from a block or a tx network message.
     */
    public Transaction(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }

    /**
     * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
     */
    public Transaction(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
        // inputs/outputs will be created in parse()
    }

    /**
     * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param parent The parent of the transaction.
     * @param setSerializer The serializer to use for this transaction.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public Transaction(NetworkParameters params, byte[] payload, int offset, @Nullable Message parent, MessageSerializer setSerializer, int length)
            throws ProtocolException {
        super(params, payload, offset, parent, setSerializer, length);
    }

    /**
     * Creates a transaction by reading payload. Length of a transaction is fixed.
     */
    public Transaction(NetworkParameters params, byte[] payload, @Nullable Message parent, MessageSerializer setSerializer, int length)
            throws ProtocolException {
        super(params, payload, 0, parent, setSerializer, length);
    }

    /**
     * Returns the transaction hash (aka txid) as you see them in block explorers. It is used as a reference by
     * transaction inputs via outpoints.
     */
    @Override
    public Sha256Hash getHash() {
        if (hash == null) {
            ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length < 32 ? 32 : length + 32);
            try {
                bitcoinSerializeToStream(stream, false);
            } catch (IOException e) {
                // Cannot happen, we are serializing to a memory stream.
            }
            hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(stream.toByteArray()));
        }
        return hash;
    }

    /**
     * Used by BitcoinSerializer.  The serializer has to calculate a hash for checksumming so to
     * avoid wasting the considerable effort a set method is provided so the serializer can set it.
     *
     * No verification is performed on this hash.
     */
    void setHash(Sha256Hash hash) {
        this.hash = hash;
    }

    /**
     * Returns the transaction hash (aka txid) as you see them in block explorers, as a hex string.
     */
    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Gets the sum of the inputs, regardless of who owns them.
     */
    public Coin getInputSum() {
        Coin inputTotal = Coin.ZERO;

        for (TransactionInput input: inputs) {
            Coin inputValue = input.getValue();
            if (inputValue != null) {
                inputTotal = inputTotal.add(inputValue);
            }
        }

        return inputTotal;
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
        return appearsInHashes != null ? ImmutableMap.copyOf(appearsInHashes) : null;
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
        long blockTime = block.getHeader().getTimeSeconds() * 1000;
        if (bestChain && (updatedAt == null || updatedAt.getTime() == 0 || updatedAt.getTime() > blockTime)) {
            updatedAt = new Date(blockTime);
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
        Coin totalOut = Coin.ZERO;

        for (TransactionOutput output: outputs) {
            totalOut = totalOut.add(output.getValue());
        }

        return totalOut;
    }

    @Nullable private Coin cachedValue;
    @Nullable private TransactionBag cachedForBag;

    /**
     * Returns the difference of {@link Transaction#getValueSentToMe(TransactionBag)} and {@link Transaction#getValueSentFromMe(TransactionBag)}.
     */
    public Coin getValue(TransactionBag wallet) throws ScriptException {
        // FIXME: TEMP PERF HACK FOR ANDROID - this crap can go away once we have a real payments API.
        boolean isAndroid = Utils.isAndroidRuntime();
        if (isAndroid && cachedValue != null && cachedForBag == wallet)
            return cachedValue;
        Coin result = getValueSentToMe(wallet).subtract(getValueSentFromMe(wallet));
        if (isAndroid) {
            cachedValue = result;
            cachedForBag = wallet;
        }
        return result;
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
     * or the epoch if that information isn't available.
     */
    public Date getUpdateTime() {
        if (updatedAt == null) {
            // Older wallets did not store this field. Set to the epoch.
            updatedAt = new Date(0);
        }
        return updatedAt;
    }

    public void setUpdateTime(Date updatedAt) {
        this.updatedAt = updatedAt;
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
        private SigHash(final int value) {
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

    @Override
    protected void unCache() {
        super.unCache();
        hash = null;
    }

    protected static int calcLength(byte[] buf, int offset) {
        VarInt varint;
        // jump past version (uint32)
        int cursor = offset + 4;

        int i;
        long scriptLen;

        varint = new VarInt(buf, cursor);
        long txInCount = varint.value;
        cursor += varint.getOriginalSizeInBytes();

        for (i = 0; i < txInCount; i++) {
            // 36 = length of previous_outpoint
            cursor += 36;
            varint = new VarInt(buf, cursor);
            scriptLen = varint.value;
            // 4 = length of sequence field (unint32)
            cursor += scriptLen + 4 + varint.getOriginalSizeInBytes();
        }

        varint = new VarInt(buf, cursor);
        long txOutCount = varint.value;
        cursor += varint.getOriginalSizeInBytes();

        for (i = 0; i < txOutCount; i++) {
            // 8 = length of tx value field (uint64)
            cursor += 8;
            varint = new VarInt(buf, cursor);
            scriptLen = varint.value;
            cursor += scriptLen + varint.getOriginalSizeInBytes();
        }
        // 4 = length of lock_time field (uint32)
        return cursor - offset + 4;
    }

    /**
     * Deserialize according to <a href="https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki">BIP144</a> or
     * the <a href="https://en.bitcoin.it/wiki/Protocol_documentation#tx">classic format</a>, depending on if the
     * transaction is segwit or not.
     */
    @Override
    protected void parse() throws ProtocolException {
        cursor = offset;
        optimalEncodingMessageSize = 4;

        // version
        version = readUint32();
        // peek at marker
        byte marker = payload[cursor];
        boolean useSegwit = marker == 0;
        // marker, flag
        if (useSegwit) {
            readBytes(2);
            optimalEncodingMessageSize += 2;
        }
        // txin_count, txins
        parseInputs();
        // txout_count, txouts
        parseOutputs();
        // script_witnesses
        if (useSegwit)
            parseWitnesses();
        // lock_time
        lockTime = readUint32();
        optimalEncodingMessageSize += 4;

        length = cursor - offset;
    }

    private void parseInputs() {
        long numInputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numInputs);
        inputs = new ArrayList<>(Math.min((int) numInputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (long i = 0; i < numInputs; i++) {
            TransactionInput input = new TransactionInput(params, this, payload, cursor, serializer);
            inputs.add(input);
            long scriptLen = readVarInt(TransactionOutPoint.MESSAGE_LENGTH);
            optimalEncodingMessageSize += TransactionOutPoint.MESSAGE_LENGTH + VarInt.sizeOf(scriptLen) + scriptLen + 4;
            cursor += scriptLen + 4;
        }
    }

    private void parseOutputs() {
        long numOutputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numOutputs);
        outputs = new ArrayList<>(Math.min((int) numOutputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (long i = 0; i < numOutputs; i++) {
            TransactionOutput output = new TransactionOutput(params, this, payload, cursor, serializer);
            outputs.add(output);
            long scriptLen = readVarInt(8);
            optimalEncodingMessageSize += 8 + VarInt.sizeOf(scriptLen) + scriptLen;
            cursor += scriptLen;
        }
    }

    private void parseWitnesses() {
        int numWitnesses = inputs.size();
        for (int i = 0; i < numWitnesses; i++) {
            long pushCount = readVarInt();
            TransactionWitness witness = new TransactionWitness((int) pushCount);
            getInput(i).setWitness(witness);
            optimalEncodingMessageSize += VarInt.sizeOf(pushCount);
            for (int y = 0; y < pushCount; y++) {
                long pushSize = readVarInt();
                optimalEncodingMessageSize += VarInt.sizeOf(pushSize) + pushSize;
                byte[] push = readBytes((int) pushSize);
                witness.setPush(y, push);
            }
        }
    }

    /** @return true of the transaction has any witnesses in any of its inputs */
    public boolean hasWitnesses() {
        for (TransactionInput in : inputs)
            if (in.hasWitness())
                return true;
        return false;
    }

    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        optimalEncodingMessageSize = getMessageSize();
        return optimalEncodingMessageSize;
    }

    /**
     * The priority (coin age) calculation doesn't use the regular message size, but rather one adjusted downwards
     * for the number of inputs. The goal is to incentivise cleaning up the UTXO set with free transactions, if one
     * can do so.
     */
    public int getMessageSizeForPriorityCalc() {
        int size = getMessageSize();
        for (TransactionInput input : inputs) {
            // 41: min size of an input
            // 110: enough to cover a compressed pubkey p2sh redemption (somewhat arbitrary).
            int benefit = 41 + Math.min(110, input.getScriptSig().getProgram().length);
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

    /**
     * A transaction is mature if it is either a building coinbase tx that is as deep or deeper than the required coinbase depth, or a non-coinbase tx.
     */
    public boolean isMature() {
        if (!isCoinBase())
            return true;

        if (getConfidence().getConfidenceType() != ConfidenceType.BUILDING)
            return false;

        return getConfidence().getDepthInBlocks() >= params.getSpendableCoinbaseDepth();
    }

    @Override
    public String toString() {
        return toString(null);
    }

    /**
     * A human readable version of the transaction useful for debugging. The format is not guaranteed to be stable.
     * @param chain If provided, will be used to estimate lock times (if set). Can be null.
     */
    public String toString(@Nullable AbstractBlockChain chain) {
        StringBuilder s = new StringBuilder();
        s.append("  ").append(getHashAsString()).append('\n');
        if (updatedAt != null)
            s.append("  updated: ").append(Utils.dateTimeFormat(updatedAt)).append('\n');
        if (version != 1)
            s.append("  version ").append(version).append('\n');
        if (isTimeLocked()) {
            s.append("  time locked until ");
            if (lockTime < LOCKTIME_THRESHOLD) {
                s.append("block ").append(lockTime);
                if (chain != null) {
                    s.append(" (estimated to be reached at ")
                            .append(Utils.dateTimeFormat(chain.estimateBlockTime((int) lockTime))).append(')');
                }
            } else {
                s.append(Utils.dateTimeFormat(lockTime * 1000));
            }
            s.append('\n');
        }
        if (hasRelativeLockTime()) {
            s.append("  has relative lock time\n");
        }
        if (isOptInFullRBF()) {
            s.append("  opts into full replace-by-fee\n");
        }
        if (isCoinBase()) {
            String script;
            String script2;
            try {
                script = inputs.get(0).getScriptSig().toString();
                script2 = outputs.get(0).getScriptPubKey().toString();
            } catch (ScriptException e) {
                script = "???";
                script2 = "???";
            }
            s.append("     == COINBASE TXN (scriptSig ").append(script)
                .append(")  (scriptPubKey ").append(script2).append(")\n");
            return s.toString();
        }
        if (!inputs.isEmpty()) {
            int i = 0;
            for (TransactionInput in : inputs) {
                s.append("     ");
                s.append("in   ");

                try {
                    String scriptSigStr = in.getScriptSig().toString();
                    s.append(!Strings.isNullOrEmpty(scriptSigStr) ? scriptSigStr : "<no scriptSig>");
                    final Coin value = in.getValue();
                    if (value != null)
                        s.append(" ").append(value.toFriendlyString());
                    if (in.hasWitness()) {
                        s.append("\n          ");
                        s.append("witness:");
                        s.append(in.getWitness());
                    }
                    s.append("\n          ");
                    s.append("outpoint:");
                    final TransactionOutPoint outpoint = in.getOutpoint();
                    s.append(outpoint.toString());
                    final TransactionOutput connectedOutput = outpoint.getConnectedOutput();
                    if (connectedOutput != null) {
                        Script scriptPubKey = connectedOutput.getScriptPubKey();
                        try {
                            byte[] pubKeyHash = scriptPubKey.getPubKeyHash();
                            s.append(" hash160:");
                            s.append(Utils.HEX.encode(pubKeyHash));
                        } catch (ScriptException x) {
                            // ignore
                        }
                    }
                    if (in.hasSequence()) {
                        s.append("\n          sequence:").append(Long.toHexString(in.getSequenceNumber()));
                        if (in.isOptInFullRBF())
                            s.append(", opts into full RBF");
                        if (version >=2 && in.hasRelativeLockTime())
                            s.append(", has RLT");
                    }
                } catch (Exception e) {
                    s.append("[exception: ").append(e.getMessage()).append("]");
                }
                s.append('\n');
                i++;
            }
        } else {
            s.append("     ");
            s.append("INCOMPLETE: No inputs!\n");
        }
        for (TransactionOutput out : outputs) {
            s.append("     ");
            s.append("out  ");
            try {
                Script scriptPubKey = out.getScriptPubKey();
                s.append(scriptPubKey.getChunks().size() > 0 ? scriptPubKey.toString() : "<no scriptPubKey>");
                s.append(" ");
                s.append(out.getValue().toFriendlyString());
                if (!out.isAvailableForSpending()) {
                    s.append(" Spent");
                }
                final TransactionInput spentBy = out.getSpentBy();
                if (spentBy != null) {
                    s.append(" by ");
                    s.append(spentBy.getParentTransaction().getHashAsString());
                }
                s.append('\n');
                ScriptType scriptType = scriptPubKey.getScriptType();
                if (scriptType != null)
                    s.append("          " + scriptType + " addr:" + scriptPubKey.getToAddress(params));
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]");
            }
            s.append('\n');
        }
        final Coin fee = getFee();
        if (fee != null) {
            final int size = unsafeBitcoinSerialize().length;
            s.append("     fee  ").append(fee.multiply(1000).divide(size).toFriendlyString()).append("/kB, ")
                    .append(fee.toFriendlyString()).append(" for ").append(size).append(" bytes\n");
        }
        if (purpose != null)
            s.append("     prps ").append(purpose).append('\n');
        return s.toString();
    }

    /**
     * Removes all the inputs from this transaction.
     * Note that this also invalidates the length attribute
     */
    public void clearInputs() {
        unCache();
        for (TransactionInput input : inputs) {
            input.setParent(null);
        }
        inputs.clear();
        // You wanted to reserialize, right?
        this.length = this.unsafeBitcoinSerialize().length;
    }

    /**
     * Adds an input to this transaction that imports value from the given output. Note that this input is <i>not</i>
     * complete and after every input is added with {@link #addInput(TransactionInput)} and every output is added with
     * {@link #addOutput(TransactionOutput)}, a {@link TransactionSigner} must be used to finalize the transaction and finish the inputs
     * off. Otherwise it won't be accepted by the network.
     * @return the newly created input.
     */
    public TransactionInput addInput(TransactionOutput from) {
        return addInput(new TransactionInput(params, this, from));
    }

    /**
     * Adds an input directly, with no checking that it's valid.
     * @return the new input.
     */
    public TransactionInput addInput(TransactionInput input) {
        unCache();
        input.setParent(this);
        inputs.add(input);
        adjustLength(inputs.size(), input.length);
        return input;
    }

    /**
     * Creates and adds an input to this transaction, with no checking that it's valid.
     * @return the newly created input.
     */
    public TransactionInput addInput(Sha256Hash spendTxHash, long outputIndex, Script script) {
        return addInput(new TransactionInput(params, this, script.getProgram(), new TransactionOutPoint(params, outputIndex, spendTxHash)));
    }

    /**
     * Adds a new and fully signed input for the given parameters. Note that this method is <b>not</b> thread safe
     * and requires external synchronization. Please refer to general documentation on Bitcoin scripting and contracts
     * to understand the values of sigHash and anyoneCanPay: otherwise you can use the other form of this method
     * that sets them to typical defaults.
     *
     * @throws ScriptException if the scriptPubKey is not a pay to address or pay to pubkey script.
     */
    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, ECKey sigKey,
                                           SigHash sigHash, boolean anyoneCanPay) throws ScriptException {
        // Verify the API user didn't try to do operations out of order.
        checkState(!outputs.isEmpty(), "Attempting to sign tx without outputs.");
        TransactionInput input = new TransactionInput(params, this, new byte[]{}, prevOut);
        addInput(input);
        Sha256Hash hash = hashForSignature(inputs.size() - 1, scriptPubKey, sigHash, anyoneCanPay);
        ECKey.ECDSASignature ecSig = sigKey.sign(hash);
        TransactionSignature txSig = new TransactionSignature(ecSig, sigHash, anyoneCanPay);
        if (ScriptPattern.isPayToPubKey(scriptPubKey))
            input.setScriptSig(ScriptBuilder.createInputScript(txSig));
        else if (ScriptPattern.isPayToPubKeyHash(scriptPubKey))
            input.setScriptSig(ScriptBuilder.createInputScript(txSig, sigKey));
        else
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Don't know how to sign for this kind of scriptPubKey: " + scriptPubKey);
        return input;
    }

    /**
     * Same as {@link #addSignedInput(TransactionOutPoint, Script, ECKey, Transaction.SigHash, boolean)}
     * but defaults to {@link SigHash#ALL} and "false" for the anyoneCanPay flag. This is normally what you want.
     */
    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, ECKey sigKey) throws ScriptException {
        return addSignedInput(prevOut, scriptPubKey, sigKey, SigHash.ALL, false);
    }

    /**
     * Adds an input that points to the given output and contains a valid signature for it, calculated using the
     * signing key.
     */
    public TransactionInput addSignedInput(TransactionOutput output, ECKey signingKey) {
        return addSignedInput(output.getOutPointFor(), output.getScriptPubKey(), signingKey);
    }

    /**
     * Adds an input that points to the given output and contains a valid signature for it, calculated using the
     * signing key.
     */
    public TransactionInput addSignedInput(TransactionOutput output, ECKey signingKey, SigHash sigHash, boolean anyoneCanPay) {
        return addSignedInput(output.getOutPointFor(), output.getScriptPubKey(), signingKey, sigHash, anyoneCanPay);
    }

    /**
     * Removes all the outputs from this transaction.
     * Note that this also invalidates the length attribute
     */
    public void clearOutputs() {
        unCache();
        for (TransactionOutput output : outputs) {
            output.setParent(null);
        }
        outputs.clear();
        // You wanted to reserialize, right?
        this.length = this.unsafeBitcoinSerialize().length;
    }

    /**
     * Adds the given output to this transaction. The output must be completely initialized. Returns the given output.
     */
    public TransactionOutput addOutput(TransactionOutput to) {
        unCache();
        to.setParent(this);
        outputs.add(to);
        adjustLength(outputs.size(), to.length);
        return to;
    }

    /**
     * Creates an output based on the given address and value, adds it to this transaction, and returns the new output.
     */
    public TransactionOutput addOutput(Coin value, Address address) {
        return addOutput(new TransactionOutput(params, this, value, address));
    }

    /**
     * Creates an output that pays to the given pubkey directly (no address) with the given value, adds it to this
     * transaction, and returns the new output.
     */
    public TransactionOutput addOutput(Coin value, ECKey pubkey) {
        return addOutput(new TransactionOutput(params, this, value, pubkey));
    }

    /**
     * Creates an output that pays to the given script. The address and key forms are specialisations of this method,
     * you won't normally need to use it unless you're doing unusual things.
     */
    public TransactionOutput addOutput(Coin value, Script script) {
        return addOutput(new TransactionOutput(params, this, value, script.getProgram()));
    }


    /**
     * Calculates a signature that is valid for being inserted into the input at the given position. This is simply
     * a wrapper around calling {@link Transaction#hashForSignature(int, byte[], Transaction.SigHash, boolean)}
     * followed by {@link ECKey#sign(Sha256Hash)} and then returning a new {@link TransactionSignature}. The key
     * must be usable for signing as-is: if the key is encrypted it must be decrypted first external to this method.
     *
     * @param inputIndex Which input to calculate the signature for, as an index.
     * @param key The private key used to calculate the signature.
     * @param redeemScript Byte-exact contents of the scriptPubKey that is being satisified, or the P2SH redeem script.
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
     * @param redeemScript The scriptPubKey that is being satisified, or the P2SH redeem script.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                                 Script redeemScript,
                                                                 SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, redeemScript.getProgram(), hashType, anyoneCanPay);
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
     * @param redeemScript Byte-exact contents of the scriptPubKey that is being satisified, or the P2SH redeem script.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                   @Nullable KeyParameter aesKey,
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
     * @param redeemScript The scriptPubKey that is being satisified, or the P2SH redeem script.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                   @Nullable KeyParameter aesKey,
                                                   Script redeemScript,
                                                   SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, redeemScript.getProgram(), hashType, anyoneCanPay);
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
        return hashForSignature(inputIndex, redeemScript.getProgram(), (byte) sigHash);
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
            Transaction tx = this.params.getDefaultSerializer().makeTransaction(this.bitcoinSerialize());

            // Clear input scripts in preparation for signing. If we're signing a fresh
            // transaction that step isn't very helpful, but it doesn't add much cost relative to the actual
            // EC math so we'll do it anyway.
            for (int i = 0; i < tx.inputs.size(); i++) {
                tx.inputs.get(i).clearScriptBytes();
            }

            // This step has no purpose beyond being synchronized with Bitcoin Core's bugs. OP_CODESEPARATOR
            // is a legacy holdover from a previous, broken design of executing scripts that shipped in Bitcoin 0.1.
            // It was seriously flawed and would have let anyone take anyone elses money. Later versions switched to
            // the design we use today where scripts are executed independently but share a stack. This left the
            // OP_CODESEPARATOR instruction having no purpose as it was only meant to be used internally, not actually
            // ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be required but if we don't
            // do it, we could split off the main chain.
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
                    tx.outputs.set(i, new TransactionOutput(tx.params, tx, Coin.NEGATIVE_SATOSHI, new byte[] {}));
                // The signature isn't broken by new versions of the transaction issued by other parties.
                for (int i = 0; i < tx.inputs.size(); i++)
                    if (i != inputIndex)
                        tx.inputs.get(i).setSequenceNumber(0);
            }

            if ((sigHashType & SigHash.ANYONECANPAY.value) == SigHash.ANYONECANPAY.value) {
                // SIGHASH_ANYONECANPAY means the signature in the input is not broken by changes/additions/removals
                // of other inputs. For example, this is useful for building assurance contracts.
                tx.inputs = new ArrayList<TransactionInput>();
                tx.inputs.add(input);
            }

            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(tx.length == UNKNOWN_LENGTH ? 256 : tx.length + 4);
            tx.bitcoinSerialize(bos);
            // We also have to write a hash type (sigHashType is actually an unsigned char)
            uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
            // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
            // however then we would expect that it is IS reversed.
            Sha256Hash hash = Sha256Hash.twiceOf(bos.toByteArray());
            bos.close();

            return hash;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        boolean useSegwit = hasWitnesses()
                && protocolVersion >= NetworkParameters.ProtocolVersion.WITNESS_VERSION.getBitcoinProtocolVersion();
        bitcoinSerializeToStream(stream, useSegwit);
    }

    /**
     * Serialize according to <a href="https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki">BIP144</a> or the
     * <a href="https://en.bitcoin.it/wiki/Protocol_documentation#tx">classic format</a>, depending on if segwit is
     * desired.
     */
    protected void bitcoinSerializeToStream(OutputStream stream, boolean useSegwit) throws IOException {
        // version
        uint32ToByteStreamLE(version, stream);
        // marker, flag
        if (useSegwit) {
            stream.write(0);
            stream.write(1);
        }
        // txin_count, txins
        stream.write(new VarInt(inputs.size()).encode());
        for (TransactionInput in : inputs)
            in.bitcoinSerialize(stream);
        // txout_count, txouts
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput out : outputs)
            out.bitcoinSerialize(stream);
        // script_witnisses
        if (useSegwit) {
            for (TransactionInput in : inputs) {
                in.getWitness().bitcoinSerializeToStream(stream);
            }
        }
        // lock_time
        uint32ToByteStreamLE(lockTime, stream);
    }

    /**
     * Transactions can have an associated lock time, specified either as a block height or in seconds since the
     * UNIX epoch. A transaction is not allowed to be confirmed by miners until the lock time is reached, and
     * since Bitcoin 0.8+ a transaction that did not end its lock period (non final) is considered to be non
     * standard and won't be relayed or included in the memory pool either.
     */
    public long getLockTime() {
        return lockTime;
    }

    /**
     * Transactions can have an associated lock time, specified either as a block height or in seconds since the
     * UNIX epoch. A transaction is not allowed to be confirmed by miners until the lock time is reached, and
     * since Bitcoin 0.8+ a transaction that did not end its lock period (non final) is considered to be non
     * standard and won't be relayed or included in the memory pool either.
     */
    public void setLockTime(long lockTime) {
        unCache();
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
        this.lockTime = lockTime;
    }

    public long getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
        unCache();
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
    public TransactionConfidence getConfidence(Context context) {
        return getConfidence(context.getConfidenceTable());
    }

    /**
     * Returns the confidence object for this transaction from the {@link TxConfidenceTable}
     */
    public TransactionConfidence getConfidence(TxConfidenceTable table) {
        if (confidence == null)
            confidence = table.getOrCreate(getHash()) ;
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
        return getHash().equals(((Transaction)o).getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
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
        final TransactionInput in = this.getInputs().get(0);
        final ScriptBuilder builder = new ScriptBuilder();
        builder.number(height);
        final byte[] expected = builder.build().getProgram();
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
     * @throws VerificationException
     */
    public void verify() throws VerificationException {
        if (inputs.size() == 0 || outputs.size() == 0)
            throw new VerificationException.EmptyInputsOrOutputs();
        if (this.getMessageSize() > Block.MAX_BLOCK_SIZE)
            throw new VerificationException.LargerThanMaxBlockSize();

        Coin valueOut = Coin.ZERO;
        HashSet<TransactionOutPoint> outpoints = new HashSet<>();
        for (TransactionInput input : inputs) {
            if (outpoints.contains(input.getOutpoint()))
                throw new VerificationException.DuplicatedOutPoint();
            outpoints.add(input.getOutpoint());
        }
        try {
            for (TransactionOutput output : outputs) {
                if (output.getValue().signum() < 0)    // getValue() can throw IllegalStateException
                    throw new VerificationException.NegativeValueOutput();
                valueOut = valueOut.add(output.getValue());
                if (params.hasMaxMoney() && valueOut.compareTo(params.getMaxMoney()) > 0)
                    throw new IllegalArgumentException();
            }
        } catch (IllegalStateException e) {
            throw new VerificationException.ExcessiveValue();
        } catch (IllegalArgumentException e) {
            throw new VerificationException.ExcessiveValue();
        }

        if (isCoinBase()) {
            if (inputs.get(0).getScriptBytes().length < 2 || inputs.get(0).getScriptBytes().length > 100)
                throw new VerificationException.CoinbaseScriptSizeOutOfRange();
        } else {
            for (TransactionInput input : inputs)
                if (input.isCoinBase())
                    throw new VerificationException.UnexpectedCoinbaseInput();
        }
    }

    /**
     * <p>A transaction is time-locked if at least one of its inputs is non-final and it has a lock time. A transaction can
     * also have a relative lock time which this method doesn't tell. Use {@link #hasRelativeLockTime()} to find out.</p>
     *
     * <p>To check if this transaction is final at a given height and time, see {@link Transaction#isFinal(int, long)}
     * </p>
     */
    public boolean isTimeLocked() {
        if (getLockTime() == 0)
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
    public boolean isFinal(int height, long blockTimeSeconds) {
        long time = getLockTime();
        return time < (time < LOCKTIME_THRESHOLD ? height : blockTimeSeconds) || !isTimeLocked();
    }

    /**
     * Returns either the lock time as a date, if it was specified in seconds, or an estimate based on the time in
     * the current head block if it was specified as a block time.
     */
    public Date estimateLockTime(AbstractBlockChain chain) {
        if (lockTime < LOCKTIME_THRESHOLD)
            return chain.estimateBlockTime((int)getLockTime());
        else
            return new Date(getLockTime()*1000);
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
}
