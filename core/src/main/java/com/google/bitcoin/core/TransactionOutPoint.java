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
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * This message is a reference or pointer to an output of a different transaction.
 */
public class TransactionOutPoint extends ChildMessage implements Serializable {
    private static final long serialVersionUID = -6320880638344662579L;

    static final int MESSAGE_LENGTH = 36;

    /** Hash of the transaction to which we refer. */
    private Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    private long index;

    // This is not part of Bitcoin serialization. It's included in Java serialization.
    // It points to the connected transaction.
    Transaction fromTx;

    public TransactionOutPoint(NetworkParameters params, long index, Transaction fromTx) {
        super(params);
        this.index = index;
        if (fromTx != null) {
            this.hash = fromTx.getHash();
            this.fromTx = fromTx;
        } else {
            // This happens when constructing the genesis block.
            hash = Sha256Hash.ZERO_HASH;
        }
        length = MESSAGE_LENGTH;
    }

    public TransactionOutPoint(NetworkParameters params, long index, Sha256Hash hash) {
        super(params);
        this.index = index;
        this.hash = hash;
        length = MESSAGE_LENGTH;
    }

    /**
    /**
     * Deserializes the message. This is usually part of a transaction message.
     */
    public TransactionOutPoint(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
    }

    /**
     * Deserializes the message. This is usually part of a transaction message.
     * @param params NetworkParameters object.
     * @param offset The location of the first msg byte within the array.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @throws ProtocolException
     */
    public TransactionOutPoint(NetworkParameters params, byte[] payload, int offset, Message parent, boolean parseLazy, boolean parseRetain) throws ProtocolException {
        super(params, payload, offset, parent, parseLazy, parseRetain, MESSAGE_LENGTH);
    }

    protected void parseLite() throws ProtocolException {
        length = MESSAGE_LENGTH;
    }

    @Override
    void parse() throws ProtocolException {
        hash = readHash();
        index = readUint32();
    }

    /* (non-Javadoc)
      * @see Message#getMessageSize()
      */
    @Override
    int getMessageSize() {
        return MESSAGE_LENGTH;
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(Utils.reverseBytes(hash.getBytes()));
        Utils.uint32ToByteStreamLE(index, stream);
    }

    /**
     * An outpoint is a part of a transaction input that points to the output of another transaction. If we have both
     * sides in memory, and they have been linked together, this returns a pointer to the connected output, or null
     * if there is no such connection.
     */
    TransactionOutput getConnectedOutput() {
        if (fromTx == null) return null;
        return fromTx.getOutputs().get((int) index);
    }

    /**
     * Returns the pubkey script from the connected output.
     */
    byte[] getConnectedPubKeyScript() {
        byte[] result = checkNotNull(getConnectedOutput().getScriptBytes());
        checkState(result.length > 0);
        return result;
    }

    /**
     * Convenience method to get the connected outputs pubkey hash.
     */
    byte[] getConnectedPubKeyHash() throws ScriptException {
        return getConnectedOutput().getScriptPubKey().getPubKeyHash();
    }

    /**
     * Returns the ECKey identified in the connected output, for either pay-to-address scripts or pay-to-key scripts.
     * If the script forms cannot be understood, throws ScriptException.
     * @return an ECKey or null if the connected key cannot be found in the wallet.
     */
    public ECKey getConnectedKey(Wallet wallet) throws ScriptException {
        Script connectedScript = getConnectedOutput().getScriptPubKey();
        if (connectedScript.isSentToAddress()) {
            byte[] addressBytes = connectedScript.getPubKeyHash();
            return wallet.findKeyFromPubHash(addressBytes);
        } else if (connectedScript.isSentToRawPubKey()) {
            byte[] pubkeyBytes = connectedScript.getPubKey();
            return wallet.findKeyFromPubKey(pubkeyBytes);
        } else {
            throw new ScriptException("Could not understand form of connected output script: " + connectedScript);
        }
    }

    @Override
    public String toString() {
        return "outpoint " + hash.toString() + ":" + index;
    }


    /**
     * Returns the hash of the transaction this outpoint references/spends/is connected to.
     */
    public Sha256Hash getHash() {
        maybeParse();
        return hash;
    }

    /**
     * @param hash the hash to set
     */
    void setHash(Sha256Hash hash) {
        this.hash = hash;
    }

    /**
     * @return the index
     */
    public long getIndex() {
        maybeParse();
        return index;
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

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof TransactionOutPoint)) return false;
        TransactionOutPoint o = (TransactionOutPoint) other;
        return o.getIndex() == getIndex() && o.getHash().equals(getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }
}
