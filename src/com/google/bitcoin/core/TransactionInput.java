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

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Map;

/**
 * A transfer of coins from one address to another creates a transaction in which the outputs
 * can be claimed by the recipient in the input of another transaction. You can imagine a
 * transaction as being a module which is wired up to others, the inputs of one have to be wired
 * to the outputs of another. The exceptions are coinbase transactions, which create new coins.
 */
public class TransactionInput extends Message implements Serializable {
    private static final long serialVersionUID = 2;
    public static final byte[] EMPTY_ARRAY = new byte[0];

    // Allows for altering transactions after they were broadcast. Tx replacement is currently disabled in the C++
    // client so this is always the UINT_MAX.
    // TODO: Document this in more detail and build features that use it.
    long sequence;
    // Data needed to connect to the output of the transaction we're gathering coins from.
    TransactionOutPoint outpoint;
    // The "script bytes" might not actually be a script. In coinbase transactions where new coins are minted there
    // is no input transaction, so instead the scriptBytes contains some extra stuff (like a rollover nonce) that we
    // don't care about much. The bytes are turned into a Script object (cached below) on demand via a getter.
    byte[] scriptBytes;
    // The Script object obtained from parsing scriptBytes. Only filled in on demand and if the transaction is not
    // coinbase.
    transient private Script scriptSig;
    // A pointer to the transaction that owns this input.
    Transaction parentTransaction;

    /** Used only in creation of the genesis block. */
    TransactionInput(NetworkParameters params, Transaction parentTransaction, byte[] scriptBytes) {
        super(params);
        this.scriptBytes = scriptBytes;
        this.outpoint = new TransactionOutPoint(params, -1, null);
        this.sequence = 0xFFFFFFFFL;
        this.parentTransaction = parentTransaction;
    }

    /** Creates an UNSIGNED input that links to the given output */
    TransactionInput(NetworkParameters params, Transaction parentTransaction, TransactionOutput output) {
        super(params);
        long outputIndex = output.getIndex();
        outpoint = new TransactionOutPoint(params, outputIndex, output.parentTransaction);
        scriptBytes = EMPTY_ARRAY;
        sequence = 0xFFFFFFFFL;
        this.parentTransaction = parentTransaction;
    }

    /** Deserializes an input message. This is usually part of a transaction message. */
    public TransactionInput(NetworkParameters params, Transaction parentTransaction,
                            byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
        this.parentTransaction = parentTransaction;
    }
    
    void parse() throws ProtocolException {
        outpoint = new TransactionOutPoint(params, bytes, cursor);
        cursor += outpoint.getMessageSize(); 
        int scriptLen = (int) readVarInt();
        scriptBytes = readBytes(scriptLen);
        sequence = readUint32();
    }
    
    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        outpoint.bitcoinSerializeToStream(stream);
        stream.write(new VarInt(scriptBytes.length).encode());
        stream.write(scriptBytes);
        Utils.uint32ToByteStreamLE(sequence, stream);
    }

    /**
     * Coinbase transactions have special inputs with hashes of zero. If this is such an input, returns true.
     */
    public boolean isCoinBase() {
        return outpoint.hash.equals(Sha256Hash.ZERO_HASH);
    }

    /**
     * Returns the input script.
     */
    public Script getScriptSig() throws ScriptException {
        // Transactions that generate new coins don't actually have a script. Instead this
        // parameter is overloaded to be something totally different.
        if (scriptSig == null) {
            assert scriptBytes != null;
            scriptSig = new Script(params, scriptBytes, 0, scriptBytes.length);
        }
        return scriptSig;
    }

    /**
     * Convenience method that returns the from address of this input by parsing the scriptSig.
     * @throws ScriptException if the scriptSig could not be understood (eg, if this is a coinbase transaction).
     */
    public Address getFromAddress() throws ScriptException {
        assert !isCoinBase();
        return getScriptSig().getFromAddress();
    }


    /** Returns a human readable debug string. */
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
     * @return The TransactionOutput or null if the transactions map doesn't contain the referenced tx.
     */
    TransactionOutput getConnectedOutput(Map<Sha256Hash, Transaction> transactions) {
        Transaction tx = transactions.get(outpoint.hash);
        if (tx == null)
            return null;
        TransactionOutput out = tx.outputs.get((int)outpoint.index);
        return out;
    }

    /**
     * Connects this input to the relevant output of the referenced transaction if it's in the given map.
     * Connecting means updating the internal pointers and spent flags.
     *
     * @param transactions Map of txhash->transaction.
     * @param disconnect Whether to abort if there's a pre-existing connection or not.
     * @return true if connection took place, false if the referenced transaction was not in the list.
     */
    ConnectionResult connect(Map<Sha256Hash, Transaction> transactions, boolean disconnect) {
        Transaction tx = transactions.get(outpoint.hash);
        if (tx == null)
            return TransactionInput.ConnectionResult.NO_SUCH_TX;
        TransactionOutput out = tx.outputs.get((int)outpoint.index);
        if (!out.isAvailableForSpending()) {
            if (disconnect)
                out.markAsUnspent();
            else
                return TransactionInput.ConnectionResult.ALREADY_SPENT;
        }
        outpoint.fromTx = tx;
        out.markAsSpent(this);
        return TransactionInput.ConnectionResult.SUCCESS;
    }

    /**
     * Release the connected output, making it spendable once again.
     *
     * @return true if the disconnection took place, false if it was not connected.
     */
    boolean disconnect() {
        if (outpoint.fromTx == null) return false;
        outpoint.fromTx.outputs.get((int)outpoint.index).markAsUnspent();
        outpoint.fromTx = null;
        return true;
    }
}
