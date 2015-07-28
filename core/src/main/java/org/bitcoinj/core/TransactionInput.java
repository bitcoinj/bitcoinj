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
import org.bitcoinj.wallet.DefaultRiskAnalysis;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;
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
 * A transfer of coins from one address to another creates a transaction in which the outputs
 * can be claimed by the recipient in the input of another transaction. You can imagine a
 * transaction as being a module which is wired up to others, the inputs of one have to be wired
 * to the outputs of another. The exceptions are coinbase transactions, which create new coins.
 */
public class TransactionInput extends ChildMessage {
    public static final long NO_SEQUENCE = 0xFFFFFFFFL;
    public static final byte[] EMPTY_ARRAY = new byte[0];

    // Allows for altering transactions after they were broadcast. Tx replacement is currently disabled in the C++
    // client so this is always the UINT_MAX.
    // TODO: Document this in more detail and build features that use it.
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

    /**
     * Creates an input that connects to nothing - used only in creation of coinbase transactions.
     */
    public TransactionInput(NetworkParameters params, @Nullable Transaction parentTransaction, byte[] scriptBytes) {
        this(params, parentTransaction, scriptBytes, new TransactionOutPoint(params, NO_SEQUENCE, (Transaction) null));
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
            scriptSig = new WeakReference<Script>(script);
        }
        return script;
    }

    /** Set the given program as the scriptSig that is supposed to satisfy the connected output script. */
    public void setScriptSig(Script scriptSig) {
        this.scriptSig = new WeakReference<Script>(checkNotNull(scriptSig));
        // TODO: This should all be cleaned up so we have a consistent internal representation.
        setScriptBytes(scriptSig.getProgram());
    }

    /**
     * Convenience method that returns the from address of this input by parsing the scriptSig. The concept of a
     * "from address" is not well defined in Bitcoin and you should not assume that senders of a transaction can
     * actually receive coins on the same address they used to sign (e.g. this is not true for shared wallets).
     */
    @Deprecated
    public Address getFromAddress() throws ScriptException {
        if (isCoinBase()) {
            throw new ScriptException(
                    "This is a coinbase transaction which generates new coins. It does not have a from address.");
        }
        return getScriptSig().getFromAddress(params);
    }

    /**
     * Sequence numbers allow participants in a multi-party transaction signing protocol to create new versions of the
     * transaction independently of each other. Newer versions of a transaction can replace an existing version that's
     * in nodes memory pools if the existing version is time locked. See the Contracts page on the Bitcoin wiki for
     * examples of how you can use this feature to build contract protocols. Note that as of 2012 the tx replacement
     * feature is disabled so sequence numbers are unusable.
     */
    public long getSequenceNumber() {
        return sequence;
    }

    /**
     * Sequence numbers allow participants in a multi-party transaction signing protocol to create new versions of the
     * transaction independently of each other. Newer versions of a transaction can replace an existing version that's
     * in nodes memory pools if the existing version is time locked. See the Contracts page on the Bitcoin wiki for
     * examples of how you can use this feature to build contract protocols. Note that as of 2012 the tx replacement
     * feature is disabled so sequence numbers are unusable.
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
     * Returns a human readable debug string.
     */
    @Override
    public String toString() {
        try {
            return isCoinBase() ? "TxIn: COINBASE" : "TxIn for [" + outpoint + "]: " + getScriptSig();
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
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
     * @see TransactionOutPoint#getConnectedRedeemData(org.bitcoinj.wallet.KeyBag)
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
     * @param transactions Map of txhash->transaction.
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
        if (!transaction.getHash().equals(outpoint.getHash()))
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
        if (outpoint.fromTx == null) return false;
        TransactionOutput output = outpoint.fromTx.getOutput((int) outpoint.getIndex());
        if (output.getSpentBy() == this) {
            output.markAsUnspent();
            outpoint.fromTx = null;
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
            if (!getOutpoint().getHash().equals(output.getParentTransaction().getHash()))
                throw new VerificationException("This input does not refer to the tx containing the output.");
            if (getOutpoint().getIndex() != output.getIndex())
                throw new VerificationException("This input refers to a different output on the given tx.");
        }
        Script pubKey = output.getScriptPubKey();
        int myIndex = getParentTransaction().getInputs().indexOf(this);
        getScriptSig().correctlySpends(getParentTransaction(), myIndex, pubKey);
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

    /** Returns a copy of the input detached from its containing transaction, if need be. */
    public TransactionInput duplicateDetached() {
        return new TransactionInput(params, null, bitcoinSerialize(), 0);
    }

    /**
     * <p>Returns either RuleViolation.NONE if the input is standard, or which rule makes it non-standard if so.
     * The "IsStandard" rules control whether the default Bitcoin Core client blocks relay of a tx / refuses to mine it,
     * however, non-standard transactions can still be included in blocks and will be accepted as valid if so.</p>
     *
     * <p>This method simply calls <tt>DefaultRiskAnalysis.isInputStandard(this)</tt>.</p>
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
}
