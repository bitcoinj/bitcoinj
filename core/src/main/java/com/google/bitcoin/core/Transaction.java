/**
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;

import com.google.bitcoin.core.TransactionConfidence.ConfidenceType;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.script.ScriptOpCodes;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.*;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.annotation.Nullable;

import static com.google.bitcoin.core.Utils.*;

/**
 * <p>A transaction represents the movement of coins from some addresses to some other addresses. It can also represent
 * the minting of new coins. A Transaction object corresponds to the equivalent in the Bitcoin C++ implementation.</p>
 *
 * <p>Transactions are the fundamental atoms of Bitcoin and have many powerful features. Read
 * <a href="http://code.google.com/p/bitcoinj/wiki/WorkingWithTransactions">"Working with transactions"</a> in the
 * documentation to learn more about how to use this class.</p>
 *
 * <p>All Bitcoin transactions are at risk of being reversed, though the risk is much less than with traditional payment
 * systems. Transactions have <i>confidence levels</i>, which help you decide whether to trust a transaction or not.
 * Whether to trust a transaction is something that needs to be decided on a case by case basis - a rule that makes 
 * sense for selling MP3s might not make sense for selling cars, or accepting payments from a family member. If you
 * are building a wallet, how to present confidence to your users is something to consider carefully.</p>
 */
public class Transaction extends ChildMessage implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(Transaction.class);
    private static final long serialVersionUID = -8567546957352643140L;
    
    /** Threshold for lockTime: below this value it is interpreted as block number, otherwise as timestamp. **/
    public static final int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

    /** How many bytes a transaction can be before it won't be relayed anymore. Currently 100kb. */
    public static final int MAX_STANDARD_TX_SIZE = 100 * 1024;

    /**
     * If fee is lower than this value (in satoshis), a default reference client will treat it as if there were no fee.
     * Currently this is 10000 satoshis.
     */
    public static final BigInteger REFERENCE_DEFAULT_MIN_TX_FEE = BigInteger.valueOf(10000);

    /**
     * Any standard (ie pay-to-address) output smaller than this value (in satoshis) will most likely be rejected by the network.
     * This is calculated by assuming a standard output will be 34 bytes, and then using the formula used in
     * {@link TransactionOutput#getMinNonDustValue(BigInteger)}. Currently it's 5460 satoshis.
     */
    public static final BigInteger MIN_NONDUST_OUTPUT = BigInteger.valueOf(5460);

    // These are serialized in both bitcoin and java serialization.
    private long version;
    private ArrayList<TransactionInput> inputs;
    private ArrayList<TransactionOutput> outputs;

    private long lockTime;

    // This is either the time the transaction was broadcast as measured from the local clock, or the time from the
    // block in which it was included. Note that this can be changed by re-orgs so the wallet may update this field.
    // Old serialized transactions don't have this field, thus null is valid. It is used for returning an ordered
    // list of transactions from a wallet, which is helpful for presenting to users.
    private Date updatedAt;

    // This is an in memory helper only.
    private transient Sha256Hash hash;
    
    // Data about how confirmed this tx is. Serialized, may be null. 
    private TransactionConfidence confidence;

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
    private transient int optimalEncodingMessageSize;

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

        // In future: de/refragmentation, privacy boosting/mixing, child-pays-for-parent fees, etc.
    }

    private Purpose purpose = Purpose.UNKNOWN;

    public Transaction(NetworkParameters params) {
        super(params);
        version = 1;
        inputs = new ArrayList<TransactionInput>();
        outputs = new ArrayList<TransactionOutput>();
        // We don't initialize appearsIn deliberately as it's only useful for transactions stored in the wallet.
        length = 8; // 8 for std fields
    }

    public Transaction(NetworkParameters params, int version, Sha256Hash hash) {
        super(params);
        this.version = version & ((1L<<32) - 1); // this field is unsigned - remove any sign extension
        inputs = new ArrayList<TransactionInput>();
        outputs = new ArrayList<TransactionOutput>();
        this.hash = hash;
        // We don't initialize appearsIn deliberately as it's only useful for transactions stored in the wallet.
        length = 8; //8 for std fields
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
     * @param msg Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first msg byte within the array.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public Transaction(NetworkParameters params, byte[] msg, int offset, Message parent, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, msg, offset, parent, parseLazy, parseRetain, length);
    }

    /**
     * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
     */
    public Transaction(NetworkParameters params, byte[] msg, Message parent, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, msg, 0, parent, parseLazy, parseRetain, length);
    }

    /**
     * Returns the transaction hash as you see them in the block explorer.
     */
    public Sha256Hash getHash() {
        if (hash == null) {
            byte[] bits = bitcoinSerialize();
            hash = new Sha256Hash(reverseBytes(doubleDigest(bits)));
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

    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet. The flag controls whether to
     * include spent outputs or not.
     */
    BigInteger getValueSentToMe(Wallet wallet, boolean includeSpent) {
        maybeParse();
        // This is tested in WalletTest.
        BigInteger v = BigInteger.ZERO;
        for (TransactionOutput o : outputs) {
            if (!o.isMine(wallet)) continue;
            if (!includeSpent && !o.isAvailableForSpending()) continue;
            v = v.add(o.getValue());
        }
        return v;
    }
    
    /*
     * If isSpent - check that all my outputs spent, otherwise check that there at least
     * one unspent.
     */
    boolean isConsistent(Wallet wallet, boolean isSpent) {
        boolean isActuallySpent = true;
        for (TransactionOutput o : outputs) {
            if (o.isAvailableForSpending()) {
                if (o.isMine(wallet)) isActuallySpent = false;
                if (o.getSpentBy() != null) {
                    log.error("isAvailableForSpending != spentBy");
                    return false;
                }
            } else {
                if (o.getSpentBy() == null) {
                    log.error("isAvailableForSpending != spentBy");
                    return false;
                }
            }
        }
        return isActuallySpent == isSpent;
    }

    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet.
     */
    public BigInteger getValueSentToMe(Wallet wallet) {
        return getValueSentToMe(wallet, true);
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
            // Reset the work done.
            try {
                transactionConfidence.setWorkDone(block.getHeader().getWork());
            } catch (VerificationException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
            // This sets type to BUILDING and depth to one.
            transactionConfidence.setAppearedAtChainHeight(block.getHeight());
        }
    }

    public void addBlockAppearance(final Sha256Hash blockHash, int relativityOffset) {
        if (appearsInHashes == null) {
            // TODO: This could be a lot more memory efficient as we'll typically only store one element.
            appearsInHashes = new TreeMap<Sha256Hash, Integer>();
        }
        appearsInHashes.put(blockHash, relativityOffset);
    }

    /**
     * Calculates the sum of the inputs that are spending coins with keys in the wallet. This requires the
     * transactions sending coins to those keys to be in the wallet. This method will not attempt to download the
     * blocks containing the input transactions if the key is in the wallet but the transactions are not.
     *
     * @return sum in nanocoins.
     */
    public BigInteger getValueSentFromMe(Wallet wallet) throws ScriptException {
        maybeParse();
        // This is tested in WalletTest.
        BigInteger v = BigInteger.ZERO;
        for (TransactionInput input : inputs) {
            // This input is taking value from a transaction in our wallet. To discover the value,
            // we must find the connected transaction.
            TransactionOutput connected = input.getConnectedOutput(wallet.unspent);
            if (connected == null)
                connected = input.getConnectedOutput(wallet.spent);
            if (connected == null)
                connected = input.getConnectedOutput(wallet.pending);
            if (connected == null)
                continue;
            // The connected output may be the change to the sender of a previous input sent to this wallet. In this
            // case we ignore it.
            if (!connected.isMine(wallet))
                continue;
            v = v.add(connected.getValue());
        }
        return v;
    }

    /**
     * Returns the difference of {@link Transaction#getValueSentFromMe(Wallet)} and {@link Transaction#getValueSentToMe(Wallet)}.
     */
    public BigInteger getValue(Wallet wallet) throws ScriptException {
        return getValueSentToMe(wallet).subtract(getValueSentFromMe(wallet));
    }

    boolean disconnectInputs() {
        boolean disconnected = false;
        maybeParse();
        for (TransactionInput input : inputs) {
            disconnected |= input.disconnect();
        }
        return disconnected;
    }

    /**
     * Connects all inputs using the provided transactions. If any input cannot be connected returns that input or
     * null on success.
     */
    TransactionInput connectForReorganize(Map<Sha256Hash, Transaction> transactions) {
        maybeParse();
        for (TransactionInput input : inputs) {
            // Coinbase transactions, by definition, do not have connectable inputs.
            if (input.isCoinBase()) continue;
            TransactionInput.ConnectionResult result =
                    input.connect(transactions, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
            // Connected to another tx in the wallet?
            if (result == TransactionInput.ConnectionResult.SUCCESS)
                continue;
            // The input doesn't exist in the wallet, eg because it belongs to somebody else (inbound spend).
            if (result == TransactionInput.ConnectionResult.NO_SUCH_TX)
                continue;
            // Could not connect this input, so return it and abort.
            return input;
        }
        return null;
    }

    /**
     * Returns true if every output is marked as spent.
     */
    public boolean isEveryOutputSpent() {
        maybeParse();
        for (TransactionOutput output : outputs) {
            if (output.isAvailableForSpending())
                return false;
        }
        return true;
    }

    /**
     * Returns false if this transaction has at least one output that is owned by the given wallet and unspent, true
     * otherwise.
     */
    public boolean isEveryOwnedOutputSpent(Wallet wallet) {
        maybeParse();
        for (TransactionOutput output : outputs) {
            if (output.isAvailableForSpending() && output.isMine(wallet))
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
     * <p/>
     * In the official client, this enum also has another flag, SIGHASH_ANYONECANPAY. In this implementation,
     * that's kept separate. Only SIGHASH_ALL is actually used in the official client today. The other flags
     * exist to allow for distributed contracts.
     */
    public enum SigHash {
        ALL,         // 1
        NONE,        // 2
        SINGLE,      // 3
    }
    public static final byte SIGHASH_ANYONECANPAY_VALUE = (byte) 0x80;

    protected void unCache() {
        super.unCache();
        hash = null;
    }

    protected void parseLite() throws ProtocolException {

        //skip this if the length has been provided i.e. the tx is not part of a block
        if (parseLazy && length == UNKNOWN_LENGTH) {
            //If length hasn't been provided this tx is probably contained within a block.
            //In parseRetain mode the block needs to know how long the transaction is
            //unfortunately this requires a fairly deep (though not total) parse.
            //This is due to the fact that transactions in the block's list do not include a
            //size header and inputs/outputs are also variable length due the contained
            //script so each must be instantiated so the scriptlength varint can be read
            //to calculate total length of the transaction.
            //We will still persist will this semi-light parsing because getting the lengths
            //of the various components gains us the ability to cache the backing bytearrays
            //so that only those subcomponents that have changed will need to be reserialized.

            //parse();
            //parsed = true;
            length = calcLength(bytes, offset);
            cursor = offset + length;
        }
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

    void parse() throws ProtocolException {

        if (parsed)
            return;

        cursor = offset;

        version = readUint32();
        optimalEncodingMessageSize = 4;

        // First come the inputs.
        long numInputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numInputs);
        inputs = new ArrayList<TransactionInput>((int) numInputs);
        for (long i = 0; i < numInputs; i++) {
            TransactionInput input = new TransactionInput(params, this, bytes, cursor, parseLazy, parseRetain);
            inputs.add(input);
            long scriptLen = readVarInt(TransactionOutPoint.MESSAGE_LENGTH);
            optimalEncodingMessageSize += TransactionOutPoint.MESSAGE_LENGTH + VarInt.sizeOf(scriptLen) + scriptLen + 4;
            cursor += scriptLen + 4;
        }
        // Now the outputs
        long numOutputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numOutputs);
        outputs = new ArrayList<TransactionOutput>((int) numOutputs);
        for (long i = 0; i < numOutputs; i++) {
            TransactionOutput output = new TransactionOutput(params, this, bytes, cursor, parseLazy, parseRetain);
            outputs.add(output);
            long scriptLen = readVarInt(8);
            optimalEncodingMessageSize += 8 + VarInt.sizeOf(scriptLen) + scriptLen;
            cursor += scriptLen;
        }
        lockTime = readUint32();
        optimalEncodingMessageSize += 4;
        length = cursor - offset;
    }
    
    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        maybeParse();
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        optimalEncodingMessageSize = getMessageSize();
        return optimalEncodingMessageSize;
    }

    /**
     * A coinbase transaction is one that creates a new coin. They are the first transaction in each block and their
     * value is determined by a formula that all implementations of Bitcoin share. In 2011 the value of a coinbase
     * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined not only by its
     * position in a block but by the data in the inputs.
     */
    public boolean isCoinBase() {
        maybeParse();
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

    public String toString() {
        return toString(null);
    }

    /**
     * A human readable version of the transaction useful for debugging. The format is not guaranteed to be stable.
     * @param chain If provided, will be used to estimate lock times (if set). Can be null.
     */
    public String toString(AbstractBlockChain chain) {
        // Basic info about the tx.
        StringBuffer s = new StringBuffer();
        s.append(String.format("  %s: %s%n", getHashAsString(), getConfidence()));
        if (isTimeLocked()) {
            String time;
            if (lockTime < LOCKTIME_THRESHOLD) {
                time = "block " + lockTime;
                if (chain != null) {
                    time = time + " (estimated to be reached at " +
                            chain.estimateBlockTime((int)lockTime).toString() + ")";
                }
            } else {
                time = new Date(lockTime*1000).toString();
            }
            s.append(String.format("  time locked until %s%n", time));
        }
        if (inputs.size() == 0) {
            s.append(String.format("  INCOMPLETE: No inputs!%n"));
            return s.toString();
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
            s.append("     == COINBASE TXN (scriptSig " + script + ")  (scriptPubKey " + script2 + ")\n");
            return s.toString();
        }
        for (TransactionInput in : inputs) {
            s.append("     ");
            s.append("from ");

            try {
                Script scriptSig = in.getScriptSig();
                if (scriptSig.getChunks().size() == 2)
                    s.append(scriptSig.getFromAddress(params).toString());
                else if (scriptSig.getChunks().size() == 1) {
                    s.append("[sig:");
                    s.append(bytesToHexString(scriptSig.getChunks().get(0).data));
                    s.append("]");
                } else
                    s.append(scriptSig);
                s.append(" / ");
                s.append(in.getOutpoint().toString());
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]");
            }
            s.append(String.format("%n"));
        }
        for (TransactionOutput out : outputs) {
            s.append("       ");
            s.append("to ");
            try {
                Script scriptPubKey = out.getScriptPubKey();
                if (scriptPubKey.isSentToAddress()) {
                    s.append(scriptPubKey.getToAddress(params).toString());
                } else if (scriptPubKey.isSentToRawPubKey()) {
                    s.append("[pubkey:");
                    s.append(bytesToHexString(scriptPubKey.getPubKey()));
                    s.append("]");
                } else {
                    s.append(scriptPubKey);
                }
                s.append(" ");
                s.append(bitcoinValueToFriendlyString(out.getValue()));
                s.append(" BTC");
                if (!out.isAvailableForSpending()) {
                    s.append(" Spent");
                }
                if (out.getSpentBy() != null) {
                    s.append(" by ");
                    s.append(out.getSpentBy().getParentTransaction().getHashAsString());
                }
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]");
            }
            s.append(String.format("%n"));
        }
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
        this.length = this.bitcoinSerialize().length;
    }

    /**
     * Adds an input to this transaction that imports value from the given output. Note that this input is NOT
     * complete and after every input is added with addInput() and every output is added with addOutput(),
     * signInputs() must be called to finalize the transaction and finish the inputs off. Otherwise it won't be
     * accepted by the network. Returns the newly created input.
     */
    public TransactionInput addInput(TransactionOutput from) {
        return addInput(new TransactionInput(params, this, from));
    }

    /**
     * Adds an input directly, with no checking that it's valid. Returns the new input.
     */
    public TransactionInput addInput(TransactionInput input) {
        unCache();
        input.setParent(this);
        inputs.add(input);
        adjustLength(inputs.size(), input.length);
        return input;
    }

    /**
     * Removes all the inputs from this transaction.
     * Note that this also invalidates the length attribute
     */
    public void clearOutputs() {
        unCache();
        for (TransactionOutput output : outputs) {
            output.setParent(null);
        }
        outputs.clear();
        // You wanted to reserialize, right?
        this.length = this.bitcoinSerialize().length;
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
    public TransactionOutput addOutput(BigInteger value, Address address) {
        return addOutput(new TransactionOutput(params, this, value, address));
    }

    /**
     * Creates an output that pays to the given pubkey directly (no address) with the given value, adds it to this
     * transaction, and returns the new output.
     */
    public TransactionOutput addOutput(BigInteger value, ECKey pubkey) {
        return addOutput(new TransactionOutput(params, this, value, pubkey));
    }

    /**
     * Creates an output that pays to the given script. The address and key forms are specialisations of this method,
     * you won't normally need to use it unless you're doing unusual things.
     */
    public TransactionOutput addOutput(BigInteger value, Script script) {
        return addOutput(new TransactionOutput(params, this, value, script.getProgram()));
    }

    /**
     * Once a transaction has some inputs and outputs added, the signatures in the inputs can be calculated. The
     * signature is over the transaction itself, to prove the redeemer actually created that transaction,
     * so we have to do this step last.<p>
     * <p/>
     * This method is similar to SignatureHash in script.cpp
     *
     * @param hashType This should always be set to SigHash.ALL currently. Other types are unused.
     * @param wallet   A wallet is required to fetch the keys needed for signing.
     */
    public synchronized void signInputs(SigHash hashType, Wallet wallet) throws ScriptException {
        signInputs(hashType, wallet, null);
    }

    /**
     * <p>Once a transaction has some inputs and outputs added, the signatures in the inputs can be calculated. The
     * signature is over the transaction itself, to prove the redeemer actually created that transaction,
     * so we have to do this step last.</p>
     *
     * @param hashType This should always be set to SigHash.ALL currently. Other types are unused.
     * @param wallet  A wallet is required to fetch the keys needed for signing.
     * @param aesKey The AES key to use to decrypt the key before signing. Null if no decryption is required.
     */
    public synchronized void signInputs(SigHash hashType, Wallet wallet, KeyParameter aesKey) throws ScriptException {
        // TODO: This should be a method of the TransactionInput that (possibly?) operates with a copy of this object.
        Preconditions.checkState(inputs.size() > 0);
        Preconditions.checkState(outputs.size() > 0);

        // I don't currently have an easy way to test other modes work, as the official client does not use them.
        Preconditions.checkArgument(hashType == SigHash.ALL, "Only SIGHASH_ALL is currently supported");

        // The transaction is signed with the input scripts empty except for the input we are signing. In the case
        // where addInput has been used to set up a new transaction, they are already all empty. The input being signed
        // has to have the connected OUTPUT program in it when the hash is calculated!
        //
        // Note that each input may be claiming an output sent to a different key. So we have to look at the outputs
        // to figure out which key to sign with.

        TransactionSignature[] signatures = new TransactionSignature[inputs.size()];
        ECKey[] signingKeys = new ECKey[inputs.size()];
        for (int i = 0; i < inputs.size(); i++) {
            TransactionInput input = inputs.get(i);
            // We don't have the connected output, we assume it was signed already and move on
            if (input.getOutpoint().getConnectedOutput() == null) {
                log.warn("Missing connected output, assuming input {} is already signed.", i);
                continue;
            }
            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard output types or a way to get processed signatures out of script execution)
                input.getScriptSig().correctlySpends(this, i, input.getOutpoint().getConnectedOutput().getScriptPubKey(), true);
                log.warn("Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                continue;
            } catch (ScriptException e) {
                // Expected.
            }
            if (input.getScriptBytes().length != 0)
                log.warn("Re-signing an already signed transaction! Be sure this is what you want.");
            // Find the signing key we'll need to use.
            ECKey key = input.getOutpoint().getConnectedKey(wallet);
            // This assert should never fire. If it does, it means the wallet is inconsistent.
            Preconditions.checkNotNull(key, "Transaction exists in wallet that we cannot redeem: %s",
                                       input.getOutpoint().getHash());
            // Keep the key around for the script creation step below.
            signingKeys[i] = key;
            // The anyoneCanPay feature isn't used at the moment.
            boolean anyoneCanPay = false;
            byte[] connectedPubKeyScript = input.getOutpoint().getConnectedPubKeyScript();
            signatures[i] = calculateSignature(i, key, aesKey, connectedPubKeyScript, hashType, anyoneCanPay);
        }

        // Now we have calculated each signature, go through and create the scripts. Reminder: the script consists:
        // 1) For pay-to-address outputs: a signature (over a hash of the simplified transaction) and the complete
        //    public key needed to sign for the connected output. The output script checks the provided pubkey hashes
        //    to the address and then checks the signature.
        // 2) For pay-to-key outputs: just a signature.
        for (int i = 0; i < inputs.size(); i++) {
            if (signatures[i] == null)
                continue;
            TransactionInput input = inputs.get(i);
            Script scriptPubKey = input.getOutpoint().getConnectedOutput().getScriptPubKey();
            if (scriptPubKey.isSentToAddress()) {
                input.setScriptSig(ScriptBuilder.createInputScript(signatures[i], signingKeys[i]));
            } else if (scriptPubKey.isSentToRawPubKey()) {
                input.setScriptSig(ScriptBuilder.createInputScript(signatures[i]));
            } else {
                // Should be unreachable - if we don't recognize the type of script we're trying to sign for, we should
                // have failed above when fetching the key to sign with.
                throw new RuntimeException("Do not understand script type: " + scriptPubKey);
            }
        }

        // Every input is now complete.
    }

    /**
     * Calculates a signature that is valid for being inserted into the input at the given position. This is simply
     * a wrapper around calling {@link Transaction#hashForSignature(int, byte[], com.google.bitcoin.core.Transaction.SigHash, boolean)}
     * followed by {@link ECKey#sign(Sha256Hash, org.spongycastle.crypto.params.KeyParameter)} and then returning
     * a new {@link TransactionSignature}.
     *
     * @param inputIndex Which input to calculate the signature for, as an index.
     * @param key The private key used to calculate the signature.
     * @param aesKey If not null, this will be used to decrypt the key.
     * @param connectedPubKeyScript Byte-exact contents of the scriptPubKey that is being satisified.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public synchronized  TransactionSignature calculateSignature(int inputIndex, ECKey key, KeyParameter aesKey,
                                                                 byte[] connectedPubKeyScript,
                                                                 SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, connectedPubKeyScript, hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash, aesKey), hashType, anyoneCanPay);
    }

    /**
     * Calculates a signature that is valid for being inserted into the input at the given position. This is simply
     * a wrapper around calling {@link Transaction#hashForSignature(int, byte[], com.google.bitcoin.core.Transaction.SigHash, boolean)}
     * followed by {@link ECKey#sign(Sha256Hash)} and then returning a new {@link TransactionSignature}.
     *
     * @param inputIndex Which input to calculate the signature for, as an index.
     * @param key The private key used to calculate the signature.
     * @param connectedPubKeyScript The scriptPubKey that is being satisified.
     * @param hashType Signing mode, see the enum for documentation.
     * @param anyoneCanPay Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public synchronized  TransactionSignature calculateSignature(int inputIndex, ECKey key, Script connectedPubKeyScript,
                                                                 SigHash hashType, boolean anyoneCanPay) {
        Sha256Hash hash = hashForSignature(inputIndex, connectedPubKeyScript.getProgram(), hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash), hashType, anyoneCanPay);
    }

    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction. How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     *
     * <p>You don't normally ever need to call this yourself. It will become more useful in future as the contracts
     * features of Bitcoin are developed.</p>
     *
     * @param inputIndex input the signature is being calculated for. Tx signatures are always relative to an input.
     * @param connectedScript the bytes that should be in the given input during signing.
     * @param type Should be SigHash.ALL
     * @param anyoneCanPay should be false.
     */
    public synchronized Sha256Hash hashForSignature(int inputIndex, byte[] connectedScript,
                                                    SigHash type, boolean anyoneCanPay) {
        byte sigHashType = (byte) TransactionSignature.calcSigHashValue(type, anyoneCanPay);
        return hashForSignature(inputIndex, connectedScript, sigHashType);
    }

    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction. How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     *
     * <p>You don't normally ever need to call this yourself. It will become more useful in future as the contracts
     * features of Bitcoin are developed.</p>
     *
     * @param inputIndex input the signature is being calculated for. Tx signatures are always relative to an input.
     * @param connectedScript the script that should be in the given input during signing.
     * @param type Should be SigHash.ALL
     * @param anyoneCanPay should be false.
     */
    public synchronized Sha256Hash hashForSignature(int inputIndex, Script connectedScript,
                                                    SigHash type, boolean anyoneCanPay) {
        int sigHash = TransactionSignature.calcSigHashValue(type, anyoneCanPay);
        return hashForSignature(inputIndex, connectedScript.getProgram(), (byte) sigHash);
    }

    /**
     * This is required for signatures which use a sigHashType which cannot be represented using SigHash and anyoneCanPay
     * See transaction c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73, which has sigHashType 0
     */
    public synchronized Sha256Hash hashForSignature(int inputIndex, byte[] connectedScript, byte sigHashType) {
        // The SIGHASH flags are used in the design of contracts, please see this page for a further understanding of
        // the purposes of the code in this method:
        //
        //   https://en.bitcoin.it/wiki/Contracts

        try {
            // Store all the input scripts and clear them in preparation for signing. If we're signing a fresh
            // transaction that step isn't very helpful, but it doesn't add much cost relative to the actual
            // EC math so we'll do it anyway.
            //
            // Also store the input sequence numbers in case we are clearing them with SigHash.NONE/SINGLE
            byte[][] inputScripts = new byte[inputs.size()][];
            long[] inputSequenceNumbers = new long[inputs.size()];
            for (int i = 0; i < inputs.size(); i++) {
                inputScripts[i] = inputs.get(i).getScriptBytes();
                inputSequenceNumbers[i] = inputs.get(i).getSequenceNumber();
                inputs.get(i).setScriptBytes(TransactionInput.EMPTY_ARRAY);
            }

            // This step has no purpose beyond being synchronized with the reference clients bugs. OP_CODESEPARATOR
            // is a legacy holdover from a previous, broken design of executing scripts that shipped in Bitcoin 0.1.
            // It was seriously flawed and would have let anyone take anyone elses money. Later versions switched to
            // the design we use today where scripts are executed independently but share a stack. This left the
            // OP_CODESEPARATOR instruction having no purpose as it was only meant to be used internally, not actually
            // ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be required but if we don't
            // do it, we could split off the main chain.
            connectedScript = Script.removeAllInstancesOfOp(connectedScript, ScriptOpCodes.OP_CODESEPARATOR);
            
            // Set the input to the script of its output. Satoshi does this but the step has no obvious purpose as
            // the signature covers the hash of the prevout transaction which obviously includes the output script
            // already. Perhaps it felt safer to him in some way, or is another leftover from how the code was written.
            TransactionInput input = inputs.get(inputIndex);
            input.setScriptBytes(connectedScript);
            
            ArrayList<TransactionOutput> outputs = this.outputs;
            if ((sigHashType & 0x1f) == (SigHash.NONE.ordinal() + 1)) {
                // SIGHASH_NONE means no outputs are signed at all - the signature is effectively for a "blank cheque".
                this.outputs = new ArrayList<TransactionOutput>(0);
                // The signature isn't broken by new versions of the transaction issued by other parties.
                for (int i = 0; i < inputs.size(); i++)
                    if (i != inputIndex)
                        inputs.get(i).setSequenceNumber(0);
            } else if ((sigHashType & 0x1f) == (SigHash.SINGLE.ordinal() + 1)) {
                // SIGHASH_SINGLE means only sign the output at the same index as the input (ie, my output).
                if (inputIndex >= this.outputs.size()) {
                    // The input index is beyond the number of outputs, it's a buggy signature made by a broken
                    // Bitcoin implementation. The reference client also contains a bug in handling this case:
                    // any transaction output that is signed in this case will result in both the signed output
                    // and any future outputs to this public key being steal-able by anyone who has
                    // the resulting signature and the public key (both of which are part of the signed tx input).
                    // Put the transaction back to how we found it.
                    //
                    // TODO: Only allow this to happen if we are checking a signature, not signing a transactions
                    for (int i = 0; i < inputs.size(); i++) {
                        inputs.get(i).setScriptBytes(inputScripts[i]);
                        inputs.get(i).setSequenceNumber(inputSequenceNumbers[i]);
                    }
                    this.outputs = outputs;
                    // Satoshis bug is that SignatureHash was supposed to return a hash and on this codepath it
                    // actually returns the constant "1" to indicate an error, which is never checked for. Oops.
                    return new Sha256Hash("0100000000000000000000000000000000000000000000000000000000000000");
                }
                // In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
                // that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
                this.outputs = new ArrayList<TransactionOutput>(this.outputs.subList(0, inputIndex + 1));
                for (int i = 0; i < inputIndex; i++)
                    this.outputs.set(i, new TransactionOutput(params, this, NEGATIVE_ONE, new byte[] {}));
                // The signature isn't broken by new versions of the transaction issued by other parties.
                for (int i = 0; i < inputs.size(); i++)
                    if (i != inputIndex)
                        inputs.get(i).setSequenceNumber(0);
            }
            
            ArrayList<TransactionInput> inputs = this.inputs;
            if ((sigHashType & SIGHASH_ANYONECANPAY_VALUE) == SIGHASH_ANYONECANPAY_VALUE) {
                // SIGHASH_ANYONECANPAY means the signature in the input is not broken by changes/additions/removals
                // of other inputs. For example, this is useful for building assurance contracts.
                this.inputs = new ArrayList<TransactionInput>();
                this.inputs.add(input);
            }

            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? 256 : length + 4);
            bitcoinSerialize(bos);
            // We also have to write a hash type (sigHashType is actually an unsigned char)
            uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
            // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
            // however then we would expect that it is IS reversed.
            Sha256Hash hash = new Sha256Hash(doubleDigest(bos.toByteArray()));
            bos.close();

            // Put the transaction back to how we found it.
            this.inputs = inputs;
            for (int i = 0; i < inputs.size(); i++) {
                inputs.get(i).setScriptBytes(inputScripts[i]);
                inputs.get(i).setSequenceNumber(inputSequenceNumbers[i]);
            }
            this.outputs = outputs;
            return hash;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(version, stream);
        stream.write(new VarInt(inputs.size()).encode());
        for (TransactionInput in : inputs)
            in.bitcoinSerialize(stream);
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput out : outputs)
            out.bitcoinSerialize(stream);
        uint32ToByteStreamLE(lockTime, stream);
    }


    /**
     * Transactions can have an associated lock time, specified either as a block height or in seconds since the
     * UNIX epoch. A transaction is not allowed to be confirmed by miners until the lock time is reached, and
     * since Bitcoin 0.8+ a transaction that did not end its lock period (non final) is considered to be non
     * standard and won't be relayed or included in the memory pool either.
     */
    public long getLockTime() {
        maybeParse();
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
        // TODO: Consider checking that at least one input has a non-final sequence number.
        this.lockTime = lockTime;
    }

    /**
     * @return the version
     */
    public long getVersion() {
        maybeParse();
        return version;
    }

    /** Returns an unmodifiable view of all inputs. */
    public List<TransactionInput> getInputs() {
        maybeParse();
        return Collections.unmodifiableList(inputs);
    }

    /** Returns an unmodifiable view of all outputs. */
    public List<TransactionOutput> getOutputs() {
        maybeParse();
        return Collections.unmodifiableList(outputs);
    }

    /** @return the given transaction: same as getInputs().get(index). */
    public TransactionInput getInput(int index) {
        maybeParse();
        return inputs.get(index);
    }

    public TransactionOutput getOutput(int index) {
        maybeParse();
        return outputs.get(index);
    }

    public synchronized TransactionConfidence getConfidence() {
        if (confidence == null) {
            confidence = new TransactionConfidence(this);
        }
        return confidence;
    }

    /** Check if the transaction has a known confidence */
    public synchronized boolean hasConfidence() {
        return confidence != null && confidence.getConfidenceType() != TransactionConfidence.ConfidenceType.UNKNOWN;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Transaction)) return false;
        Transaction t = (Transaction) other;

        return t.getHash().equals(getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

    /**
     * Ensure object is fully parsed before invoking java serialization.  The backing byte array
     * is transient so if the object has parseLazy = true and hasn't invoked checkParse yet
     * then data will be lost during serialization.
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        maybeParse();
        out.defaultWriteObject();
    }

    /**
     * Gets the count of regular SigOps in this transactions
     */
    public int getSigOpCount() throws ScriptException {
        maybeParse();
        int sigOps = 0;
        for (TransactionInput input : inputs)
            sigOps += Script.getSigOpCount(input.getScriptBytes());
        for (TransactionOutput output : outputs)
            sigOps += Script.getSigOpCount(output.getScriptBytes());
        return sigOps;
    }

    /**
     * Checks the transaction contents for sanity, in ways that can be done in a standalone manner.
     * Does <b>not</b> perform all checks on a transaction such as whether the inputs are already spent.
     *
     * @throws VerificationException
     */
    public void verify() throws VerificationException {
        maybeParse();
        if (inputs.size() == 0 || outputs.size() == 0)
            throw new VerificationException("Transaction had no inputs or no outputs.");
        if (this.getMessageSize() > Block.MAX_BLOCK_SIZE)
            throw new VerificationException("Transaction larger than MAX_BLOCK_SIZE");
        
        BigInteger valueOut = BigInteger.ZERO;
        for (TransactionOutput output : outputs) {
            if (output.getValue().compareTo(BigInteger.ZERO) < 0)
                throw new VerificationException("Transaction output negative");
            valueOut = valueOut.add(output.getValue());
        }
        if (valueOut.compareTo(params.MAX_MONEY) > 0)
            throw new VerificationException("Total transaction output value greater than possible");
        
        if (isCoinBase()) {
            if (inputs.get(0).getScriptBytes().length < 2 || inputs.get(0).getScriptBytes().length > 100)
                throw new VerificationException("Coinbase script size out of range");
        } else {
            for (TransactionInput input : inputs)
                if (input.isCoinBase())
                    throw new VerificationException("Coinbase input as input in non-coinbase transaction");
        }
    }

    /**
     * <p>A transaction is time locked if at least one of its inputs is non-final and it has a lock time</p>
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
     * <p>Returns true if this transaction is considered finalized and can be placed in a block. Non-finalized
     * transactions won't be included by miners and can be replaced with newer versions using sequence numbers.
     * This is useful in certain types of <a href="http://en.bitcoin.it/wiki/Contracts">contracts</a>, such as
     * micropayment channels.</p>
     *
     * <p>Note that currently the replacement feature is disabled in the Satoshi client and will need to be
     * re-activated before this functionality is useful.</p>
     */
    public boolean isFinal(int height, long blockTimeSeconds) {
        long time = getLockTime();
        if (time < (time < LOCKTIME_THRESHOLD ? height : blockTimeSeconds))
            return true;
        if (!isTimeLocked())
            return true;
        return false;
    }

    /**
     * Parses the string either as a whole number of blocks, or if it contains slashes as a YYYY/MM/DD format date
     * and returns the lock time in wire format.
     */
    public static long parseLockTimeStr(String lockTimeStr) throws ParseException {
        if (lockTimeStr.indexOf("/") != -1) {
            SimpleDateFormat format = new SimpleDateFormat("yyyy/MM/dd");
            Date date = format.parse(lockTimeStr);
            return date.getTime() / 1000;
        }
        return Long.parseLong(lockTimeStr);
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
}
