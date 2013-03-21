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

import com.google.common.base.Preconditions;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Map;

import static com.google.common.base.Preconditions.checkElementIndex;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A transfer of coins from one address to another creates a transaction in which the outputs
 * can be claimed by the recipient in the input of another transaction. You can imagine a
 * transaction as being a module which is wired up to others, the inputs of one have to be wired
 * to the outputs of another. The exceptions are coinbase transactions, which create new coins.
 */
public class TransactionInput extends ChildMessage implements Serializable {
    public static final long NO_SEQUENCE = 0xFFFFFFFFL;
    private static final long serialVersionUID = 2;
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
    transient private Script scriptSig;
    // A pointer to the transaction that owns this input.
    private Transaction parentTransaction;

    /**
     * Creates an input that connects to nothing - used only in creation of coinbase transactions.
     */
    public TransactionInput(NetworkParameters params, Transaction parentTransaction, byte[] scriptBytes) {
        super(params);
        this.scriptBytes = scriptBytes;
        this.outpoint = new TransactionOutPoint(params, NO_SEQUENCE, (Transaction)null);
        this.sequence = NO_SEQUENCE;
        this.parentTransaction = parentTransaction;
        length = 40 + (scriptBytes == null ? 1 : VarInt.sizeOf(scriptBytes.length) + scriptBytes.length);
    }

    public TransactionInput(NetworkParameters params, Transaction parentTransaction,
            byte[] scriptBytes,
            TransactionOutPoint outpoint) {
        super(params);
        this.scriptBytes = scriptBytes;
        this.outpoint = outpoint;
        this.sequence = NO_SEQUENCE;
        this.parentTransaction = parentTransaction;

        length = 40 + (scriptBytes == null ? 1 : VarInt.sizeOf(scriptBytes.length) + scriptBytes.length);
    }

    /**
     * Creates an UNSIGNED input that links to the given output
     */
    TransactionInput(NetworkParameters params, Transaction parentTransaction, TransactionOutput output) {
        super(params);
        long outputIndex = output.getIndex();
        outpoint = new TransactionOutPoint(params, outputIndex, output.parentTransaction);
        scriptBytes = EMPTY_ARRAY;
        sequence = NO_SEQUENCE;
        this.parentTransaction = parentTransaction;

        length = 41;
    }

    /**
     * Deserializes an input message. This is usually part of a transaction message.
     */
    public TransactionInput(NetworkParameters params, Transaction parentTransaction,
                            byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
        this.parentTransaction = parentTransaction;
    }

    /**
     * Deserializes an input message. This is usually part of a transaction message.
     * @param params NetworkParameters object.
     * @param msg Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first msg byte within the array.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public TransactionInput(NetworkParameters params, Transaction parentTransaction, byte[] msg, int offset,
                            boolean parseLazy, boolean parseRetain)
            throws ProtocolException {
        super(params, msg, offset, parentTransaction, parseLazy, parseRetain, UNKNOWN_LENGTH);
        this.parentTransaction = parentTransaction;
    }

    protected void parseLite() {
        int curs = cursor;
        int scriptLen = (int) readVarInt(36);
        length = cursor - offset + scriptLen + 4;
        cursor = curs;
    }

    void parse() throws ProtocolException {
        outpoint = new TransactionOutPoint(params, bytes, cursor, this, parseLazy, parseRetain);
        cursor += outpoint.getMessageSize();
        int scriptLen = (int) readVarInt();
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
        maybeParse();
        return outpoint.getHash().equals(Sha256Hash.ZERO_HASH) &&
                outpoint.getIndex() == NO_SEQUENCE;
    }

    /**
     * Returns the input script.
     */
    public Script getScriptSig() throws ScriptException {
        // Transactions that generate new coins don't actually have a script. Instead this
        // parameter is overloaded to be something totally different.
        if (scriptSig == null) {
            maybeParse();
            scriptSig = new Script(params, Preconditions.checkNotNull(scriptBytes), 0, scriptBytes.length);
        }
        return scriptSig;
    }

    /**
     * Convenience method that returns the from address of this input by parsing the scriptSig.
     *
     * @throws ScriptException if the scriptSig could not be understood (eg, if this is a coinbase transaction).
     */
    public Address getFromAddress() throws ScriptException {
        if (isCoinBase()) {
            throw new ScriptException(
                    "This is a coinbase transaction which generates new coins. It does not have a from address.");
        }
        return getScriptSig().getFromAddress();
    }

    /**
     * Sequence numbers allow participants in a multi-party transaction signing protocol to create new versions of the
     * transaction independently of each other. Newer versions of a transaction can replace an existing version that's
     * in nodes memory pools if the existing version is time locked. See the Contracts page on the Bitcoin wiki for
     * examples of how you can use this feature to build contract protocols. Note that as of 2012 the tx replacement
     * feature is disabled so sequence numbers are unusable.
     */
    public long getSequenceNumber() {
        maybeParse();
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
        maybeParse();
        return outpoint;
    }

    /**
     * The "script bytes" might not actually be a script. In coinbase transactions where new coins are minted there
     * is no input transaction, so instead the scriptBytes contains some extra stuff (like a rollover nonce) that we
     * don't care about much. The bytes are turned into a Script object (cached below) on demand via a getter.
     * @return the scriptBytes
     */
    public byte[] getScriptBytes() {
        maybeParse();
        return scriptBytes;
    }

    /**
     * @param scriptBytes the scriptBytes to set
     */
    void setScriptBytes(byte[] scriptBytes) {
        unCache();
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
        return parentTransaction;
    }

    /**
     * Returns a human readable debug string.
     */
    public String toString() {
        if (isCoinBase())
            return "TxIn: COINBASE";
        try {
            return "TxIn from tx " + outpoint + " (pubkey: " + Utils.bytesToHexString(getScriptSig().getPubKey()) +
                    ") script:" +
                    getScriptSig().toString();
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }

    enum ConnectionResult {
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
    TransactionOutput getConnectedOutput(Map<Sha256Hash, Transaction> transactions) {
        Transaction tx = transactions.get(outpoint.getHash());
        if (tx == null)
            return null;
        TransactionOutput out = tx.getOutputs().get((int) outpoint.getIndex());
        return out;
    }

    enum ConnectMode {
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
        if (!transaction.getHash().equals(outpoint.getHash()) && mode != ConnectMode.DISCONNECT_ON_CONFLICT)
            return ConnectionResult.NO_SUCH_TX;
        checkElementIndex((int) outpoint.getIndex(), transaction.getOutputs().size(), "Corrupt transaction");
        TransactionOutput out = transaction.getOutput((int) outpoint.getIndex());
        if (!out.isAvailableForSpending()) {
            if (mode == ConnectMode.DISCONNECT_ON_CONFLICT) {
                out.markAsUnspent();
            } else if (mode == ConnectMode.ABORT_ON_CONFLICT) {
                outpoint.fromTx = checkNotNull(out.parentTransaction);
                return TransactionInput.ConnectionResult.ALREADY_SPENT;
            }
        }
        connect(out);
        return TransactionInput.ConnectionResult.SUCCESS;
    }

    /** Internal use only: connects this TransactionInput to the given output (updates pointers and spent flags) */
    public void connect(TransactionOutput out) {
        outpoint.fromTx = checkNotNull(out.parentTransaction);
        out.markAsSpent(this);
    }

    /**
     * If this input is connected, check the output is connected back to this input and release it if so, making
     * it spendable once again.
     *
     * @return true if the disconnection took place, false if it was not connected.
     */
    boolean disconnect() {
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
     * Ensure object is fully parsed before invoking java serialization.  The backing byte array
     * is transient so if the object has parseLazy = true and hasn't invoked checkParse yet
     * then data will be lost during serialization.
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        maybeParse();
        out.defaultWriteObject();
    }

    public boolean hasSequence() {
        return sequence != NO_SEQUENCE;
    }

    /**
     * For a connected transaction, runs the script against the connected pubkey and verifies they are correct.
     * @throws ScriptException if the script did not verify.
     */
    public void verify() throws ScriptException {
        Preconditions.checkNotNull(getOutpoint().fromTx, "Not connected");
        long spendingIndex = getOutpoint().getIndex();
        Script pubKey = getOutpoint().fromTx.getOutputs().get((int) spendingIndex).getScriptPubKey();
        Script sig = getScriptSig();
        int myIndex = parentTransaction.getInputs().indexOf(this);
        sig.correctlySpends(parentTransaction, myIndex, pubKey, true);
    }
}
