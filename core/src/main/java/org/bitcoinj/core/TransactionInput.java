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

import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.wallet.DefaultRiskAnalysis;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;

import com.google.common.base.Joiner;
import com.google.common.base.Objects;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.Map;

import static com.google.common.base.Preconditions.checkElementIndex;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>A transfer of coins from one address to another creates a transaction in which the outputs
 * can be claimed by the recipient in the input of another transaction. You can imagine a
 * transaction as being a module which is wired up to others, the inputs of one have to be wired
 * to the outputs of another. The exceptions are coinbase transactions, which create new coins.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class TransactionInput extends ChildMessage {
    /** Magic sequence number that indicates there is no sequence number. */
    public static final long NO_SEQUENCE = 0xFFFFFFFFL;
    /**
     * BIP68: If this flag set, sequence is NOT interpreted as a relative lock-time.
     */
    public static final long SEQUENCE_LOCKTIME_DISABLE_FLAG = 1L << 31;
    /**
     * BIP68: If sequence encodes a relative lock-time and this flag is set, the relative lock-time has units of 512
     * seconds, otherwise it specifies blocks with a granularity of 1.
     */
    public static final long SEQUENCE_LOCKTIME_TYPE_FLAG = 1L << 22;
    /**
     * BIP68: If sequence encodes a relative lock-time, this mask is applied to extract that lock-time from the sequence
     * field.
     */
    public static final long SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    private static final byte[] EMPTY_ARRAY = new byte[0];
    // Magic outpoint index that indicates the input is in fact unconnected.
    private static final long UNCONNECTED = 0xFFFFFFFFL;

    // Allows for altering transactions after they were broadcast. Values below NO_SEQUENCE-1 mean it can be altered.
    private long sequence;
    // Data needed to connect to the output of the transaction we're gathering coins from.
    private TransactionOutPoint outpoint;
    // The "script bytes" might not actually be a script. In coinbase transactions where new coins are minted there
    // is no input transaction, so instead the scriptBytes contains some extra stuff (like a rollover nonce) that we
    // don't care about much. The bytes are turned into a Script object (cached below) on demand via a getter.
    private byte[] scriptBytes;
    // The Script object obtained from parsing scriptBytes. Only filled in on demand and if the transaction is not
    // coinbase.
    private WeakReference<Script> scriptSig;
    /** Value of the output connected to the input, if known. This field does not participate in equals()/hashCode(). */
    @Nullable
    private Coin value;

    private TransactionWitness witness;

    /**
     * Creates an input that connects to nothing - used only in creation of coinbase transactions.
     */
    public TransactionInput(NetworkParameters params, @Nullable Transaction parentTransaction, byte[] scriptBytes) {
        this(params, parentTransaction, scriptBytes, new TransactionOutPoint(params, UNCONNECTED, (Transaction) null));
    }

    public TransactionInput(NetworkParameters params, @Nullable Transaction parentTransaction, byte[] scriptBytes,
                            TransactionOutPoint outpoint) {
        this(params, parentTransaction, scriptBytes, outpoint, null);
    }

    public TransactionInput(NetworkParameters params, @Nullable Transaction parentTransaction, byte[] scriptBytes,
            TransactionOutPoint outpoint, @Nullable Coin value) {
        super(params);
        this.scriptBytes = scriptBytes;
        this.outpoint = outpoint;
        this.sequence = NO_SEQUENCE;
        this.value = value;
        setParent(parentTransaction);
        length = 40 + (scriptBytes == null ? 1 : VarInt.sizeOf(scriptBytes.length) + scriptBytes.length);
    }

    /**
     * Creates an UNSIGNED input that links to the given output
     */
    TransactionInput(NetworkParameters params, Transaction parentTransaction, TransactionOutput output) {
        super(params);
        long outputIndex = output.getIndex();
        if(output.getParentTransaction() != null ) {
            outpoint = new TransactionOutPoint(params, outputIndex, output.getParentTransaction());
        } else {
            outpoint = new TransactionOutPoint(params, output);
        }
        scriptBytes = EMPTY_ARRAY;
        sequence = NO_SEQUENCE;
        setParent(parentTransaction);
        this.value = output.getValue();
        length = 41;
    }

    /**
     * Deserializes an input message. This is usually part of a transaction message.
     */
    public TransactionInput(NetworkParameters params, @Nullable Transaction parentTransaction, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
        setParent(parentTransaction);
        this.value = null;
    }

    /**
     * Deserializes an input message. This is usually part of a transaction message.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @throws ProtocolException
     */
    public TransactionInput(NetworkParameters params, Transaction parentTransaction, byte[] payload, int offset, MessageSerializer serializer)
            throws ProtocolException {
        super(params, payload, offset, parentTransaction, serializer, UNKNOWN_LENGTH);
        this.value = null;
    }

    /**
     * Gets the index of this input in the parent transaction, or throws if this input is free standing. Iterates
     * over the parents list to discover this.
     */
    public int getIndex() {
        final int myIndex = getParentTransaction().getInputs().indexOf(this);
        if (myIndex < 0)
            throw new IllegalStateException("Input linked to wrong parent transaction?");
        return myIndex;
    }

    @Override
    protected void parse() throws ProtocolException {
        outpoint = new TransactionOutPoint(params, payload, cursor, this, serializer);
        cursor += outpoint.getMessageSize();
        int scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen + 4;
        scriptBytes = readBytes(scriptLen);
        sequence = readUint32();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        outpoint.bitcoinSerialize(stream);
        stream.write(new VarInt(scriptBytes.length).encode());
        stream.write(scriptBytes);
        Utils.uint32ToByteStreamLE(sequence, stream);
    }

    /**
     * Coinbase transactions have special inputs with hashes of zero. If this is such an input, returns true.
     */
    public boolean isCoinBase() {
        return outpoint.getHash().equals(Sha256Hash.ZERO_HASH) &&
                (outpoint.getIndex() & 0xFFFFFFFFL) == 0xFFFFFFFFL;  // -1 but all is serialized to the wire as unsigned int.
    }

    /**
     * Returns the script that is fed to the referenced output (scriptPubKey) script in order to satisfy it: usually
     * contains signatures and maybe keys, but can contain arbitrary data if the output script accepts it.
     */
    public Script getScriptSig() throws ScriptException {
        // Transactions that generate new coins don't actually have a script. Instead this
        // parameter is overloaded to be something totally different.
        Script script = scriptSig == null ? null : scriptSig.get();
        if (script == null) {
            script = new Script(scriptBytes);
            scriptSig = new WeakReference<>(script);
        }
        return script;
    }

    /** Set the given program as the scriptSig that is supposed to satisfy the connected output script. */
    public void setScriptSig(Script scriptSig) {
        this.scriptSig = new WeakReference<>(checkNotNull(scriptSig));
        // TODO: This should all be cleaned up so we have a consistent internal representation.
        setScriptBytes(scriptSig.getProgram());
    }

    /**
     * Sequence numbers allow participants in a multi-party transaction signing protocol to create new versions of the
     * transaction independently of each other. Newer versions of a transaction can replace an existing version that's
     * in nodes memory pools if the existing version is time locked. See the Contracts page on the Bitcoin wiki for
     * examples of how you can use this feature to build contract protocols.
     */
    public long getSequenceNumber() {
        return sequence;
    }

    /**
     * Sequence numbers allow participants in a multi-party transaction signing protocol to create new versions of the
     * transaction independently of each other. Newer versions of a transaction can replace an existing version that's
     * in nodes memory pools if the existing version is time locked. See the Contracts page on the Bitcoin wiki for
     * examples of how you can use this feature to build contract protocols.
     */
    public void setSequenceNumber(long sequence) {
        unCache();
        this.sequence = sequence;
    }

    /**
     * @return The previous output transaction reference, as an OutPoint structure.  This contains the 
     * data needed to connect to the output of the transaction we're gathering coins from.
     */
    public TransactionOutPoint getOutpoint() {
        return outpoint;
    }

    /**
     * The "script bytes" might not actually be a script. In coinbase transactions where new coins are minted there
     * is no input transaction, so instead the scriptBytes contains some extra stuff (like a rollover nonce) that we
     * don't care about much. The bytes are turned into a Script object (cached below) on demand via a getter.
     * @return the scriptBytes
     */
    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /** Clear input scripts, e.g. in preparation for signing. */
    public void clearScriptBytes() {
        setScriptBytes(TransactionInput.EMPTY_ARRAY);
    }

    /**
     * @param scriptBytes the scriptBytes to set
     */
    void setScriptBytes(byte[] scriptBytes) {
        unCache();
        this.scriptSig = null;
        int oldLength = length;
        this.scriptBytes = scriptBytes;
        // 40 = previous_outpoint (36) + sequence (4)
        int newLength = 40 + (scriptBytes == null ? 1 : VarInt.sizeOf(scriptBytes.length) + scriptBytes.length);
        adjustLength(newLength - oldLength);
    }

    /**
     * @return The Transaction that owns this input.
     */
    public Transaction getParentTransaction() {
        return (Transaction) parent;
    }

    /**
     * @return Value of the output connected to this input, if known. Null if unknown.
     */
    @Nullable
    public Coin getValue() {
        return value;
    }

    /**
     * Get the transaction witness of this input.
     * 
     * @return the witness of the input
     */
    public TransactionWitness getWitness() {
        return witness != null ? witness : TransactionWitness.EMPTY;
    }

    /**
     * Set the transaction witness of an input.
     */
    public void setWitness(TransactionWitness witness) {
        this.witness = witness;
    }

    /**
     * Determine if the transaction has witnesses.
     * 
     * @return true if the transaction has witnesses
     */
    public boolean hasWitness() {
        return witness != null && witness.getPushCount() != 0;
    }

    public enum ConnectionResult {
        NO_SUCH_TX,
        ALREADY_SPENT,
        SUCCESS
    }

    // TODO: Clean all this up once TransactionOutPoint disappears.

    /**
     * Locates the referenced output from the given pool of transactions.
     *
     * @return The TransactionOutput or null if the transactions map doesn't contain the referenced tx.
     */
    @Nullable
    TransactionOutput getConnectedOutput(Map<Sha256Hash, Transaction> transactions) {
        Transaction tx = transactions.get(outpoint.getHash());
        if (tx == null)
            return null;
        return tx.getOutputs().get((int) outpoint.getIndex());
    }

    /**
     * Alias for getOutpoint().getConnectedRedeemData(keyBag)
     * @see TransactionOutPoint#getConnectedRedeemData(KeyBag)
     */
    @Nullable
    public RedeemData getConnectedRedeemData(KeyBag keyBag) throws ScriptException {
        return getOutpoint().getConnectedRedeemData(keyBag);
    }


    public enum ConnectMode {
        DISCONNECT_ON_CONFLICT,
        ABORT_ON_CONFLICT
    }

    /**
     * Connects this input to the relevant output of the referenced transaction if it's in the given map.
     * Connecting means updating the internal pointers and spent flags. If the mode is to ABORT_ON_CONFLICT then
     * the spent output won't be changed, but the outpoint.fromTx pointer will still be updated.
     *
     * @param transactions Map of txhash to transaction.
     * @param mode   Whether to abort if there's a pre-existing connection or not.
     * @return NO_SUCH_TX if the prevtx wasn't found, ALREADY_SPENT if there was a conflict, SUCCESS if not.
     */
    public ConnectionResult connect(Map<Sha256Hash, Transaction> transactions, ConnectMode mode) {
        Transaction tx = transactions.get(outpoint.getHash());
        if (tx == null) {
            return TransactionInput.ConnectionResult.NO_SUCH_TX;
        }
        return connect(tx, mode);
    }

    /**
     * Connects this input to the relevant output of the referenced transaction.
     * Connecting means updating the internal pointers and spent flags. If the mode is to ABORT_ON_CONFLICT then
     * the spent output won't be changed, but the outpoint.fromTx pointer will still be updated.
     *
     * @param transaction The transaction to try.
     * @param mode   Whether to abort if there's a pre-existing connection or not.
     * @return NO_SUCH_TX if transaction is not the prevtx, ALREADY_SPENT if there was a conflict, SUCCESS if not.
     */
    public ConnectionResult connect(Transaction transaction, ConnectMode mode) {
        if (!transaction.getTxId().equals(outpoint.getHash()))
            return ConnectionResult.NO_SUCH_TX;
        checkElementIndex((int) outpoint.getIndex(), transaction.getOutputs().size(), "Corrupt transaction");
        TransactionOutput out = transaction.getOutput((int) outpoint.getIndex());
        if (!out.isAvailableForSpending()) {
            if (getParentTransaction().equals(outpoint.fromTx)) {
                // Already connected.
                return ConnectionResult.SUCCESS;
            } else if (mode == ConnectMode.DISCONNECT_ON_CONFLICT) {
                out.markAsUnspent();
            } else if (mode == ConnectMode.ABORT_ON_CONFLICT) {
                outpoint.fromTx = out.getParentTransaction();
                return TransactionInput.ConnectionResult.ALREADY_SPENT;
            }
        }
        connect(out);
        return TransactionInput.ConnectionResult.SUCCESS;
    }

    /** Internal use only: connects this TransactionInput to the given output (updates pointers and spent flags) */
    public void connect(TransactionOutput out) {
        outpoint.fromTx = out.getParentTransaction();
        out.markAsSpent(this);
        value = out.getValue();
    }

    /**
     * If this input is connected, check the output is connected back to this input and release it if so, making
     * it spendable once again.
     *
     * @return true if the disconnection took place, false if it was not connected.
     */
    public boolean disconnect() {
        TransactionOutput connectedOutput;
        if (outpoint.fromTx != null) {
            // The outpoint is connected using a "standard" wallet, disconnect it.
            connectedOutput = outpoint.fromTx.getOutput((int) outpoint.getIndex());
            outpoint.fromTx = null;
        } else if (outpoint.connectedOutput != null) {
            // The outpoint is connected using a UTXO based wallet, disconnect it.
            connectedOutput = outpoint.connectedOutput;
            outpoint.connectedOutput = null;
        } else {
            // The outpoint is not connected, do nothing.
            return false;
        }

        if (connectedOutput != null && connectedOutput.getSpentBy() == this) {
            // The outpoint was connected to an output, disconnect the output.
            connectedOutput.markAsUnspent();
            return true;
        } else {
            return false;
        }
    }

    /**
     * @return true if this transaction's sequence number is set (ie it may be a part of a time-locked transaction)
     */
    public boolean hasSequence() {
        return sequence != NO_SEQUENCE;
    }

    /**
     * Returns whether this input will cause a transaction to opt into the
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki">full replace-by-fee </a> semantics.
     */
    public boolean isOptInFullRBF() {
        return sequence < NO_SEQUENCE - 1;
    }

    /**
     * Returns whether this input, if it belongs to a version 2 (or higher) transaction, has
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki">relative lock-time</a> enabled.
     */
    public boolean hasRelativeLockTime() {
        return (sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0;
    }

    /**
     * For a connected transaction, runs the script against the connected pubkey and verifies they are correct.
     * @throws ScriptException if the script did not verify.
     * @throws VerificationException If the outpoint doesn't match the given output.
     */
    public void verify() throws VerificationException {
        final Transaction fromTx = getOutpoint().fromTx;
        long spendingIndex = getOutpoint().getIndex();
        checkNotNull(fromTx, "Not connected");
        final TransactionOutput output = fromTx.getOutput((int) spendingIndex);
        verify(output);
    }

    /**
     * Verifies that this input can spend the given output. Note that this input must be a part of a transaction.
     * Also note that the consistency of the outpoint will be checked, even if this input has not been connected.
     *
     * @param output the output that this input is supposed to spend.
     * @throws ScriptException If the script doesn't verify.
     * @throws VerificationException If the outpoint doesn't match the given output.
     */
    public void verify(TransactionOutput output) throws VerificationException {
        if (output.parent != null) {
            if (!getOutpoint().getHash().equals(output.getParentTransaction().getTxId()))
                throw new VerificationException("This input does not refer to the tx containing the output.");
            if (getOutpoint().getIndex() != output.getIndex())
                throw new VerificationException("This input refers to a different output on the given tx.");
        }
        Script pubKey = output.getScriptPubKey();
        getScriptSig().correctlySpends(getParentTransaction(), getIndex(), getWitness(), getValue(), pubKey,
                Script.ALL_VERIFY_FLAGS);
    }

    /**
     * Returns the connected output, assuming the input was connected with
     * {@link TransactionInput#connect(TransactionOutput)} or variants at some point. If it wasn't connected, then
     * this method returns null.
     */
    @Nullable
    public TransactionOutput getConnectedOutput() {
        return getOutpoint().getConnectedOutput();
    }

    /**
     * Returns the connected transaction, assuming the input was connected with
     * {@link TransactionInput#connect(TransactionOutput)} or variants at some point. If it wasn't connected, then
     * this method returns null.
     */
    @Nullable
    public Transaction getConnectedTransaction() {
        return getOutpoint().fromTx;
    }

    /** Returns a copy of the input detached from its containing transaction, if need be. */
    public TransactionInput duplicateDetached() {
        return new TransactionInput(params, null, bitcoinSerialize(), 0);
    }

    /**
     * <p>Returns either RuleViolation.NONE if the input is standard, or which rule makes it non-standard if so.
     * The "IsStandard" rules control whether the default Bitcoin Core client blocks relay of a tx / refuses to mine it,
     * however, non-standard transactions can still be included in blocks and will be accepted as valid if so.</p>
     *
     * <p>This method simply calls {@code DefaultRiskAnalysis.isInputStandard(this)}.</p>
     */
    public DefaultRiskAnalysis.RuleViolation isStandard() {
        return DefaultRiskAnalysis.isInputStandard(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionInput other = (TransactionInput) o;
        return sequence == other.sequence && parent == other.parent
            && outpoint.equals(other.outpoint) && Arrays.equals(scriptBytes, other.scriptBytes);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(sequence, outpoint, Arrays.hashCode(scriptBytes));
    }

    /**
     * Returns a human readable debug string.
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder("TxIn");
        try {
            if (isCoinBase()) {
                s.append(": COINBASE");
            } else {
                s.append(" for [").append(outpoint).append("]: ").append(getScriptSig());
                String flags = Joiner.on(", ").skipNulls().join(hasWitness() ? "witness" : null,
                        hasSequence() ? "sequence: " + Long.toHexString(sequence) : null,
                        isOptInFullRBF() ? "opts into full RBF" : null);
                if (!flags.isEmpty())
                    s.append(" (").append(flags).append(')');
            }
            return s.toString();
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }
}
