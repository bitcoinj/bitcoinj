/*
 * Copyright 2011 Google Inc.
 * Copyright 2015 Andreas Schildbach
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

import com.google.common.base.Objects;
import org.bitcoinj.script.*;
import org.bitcoinj.wallet.*;

import javax.annotation.*;
import java.io.*;

import static com.google.common.base.Preconditions.*;

/**
 * <p>This message is a reference or pointer to an output of a different transaction.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class TransactionOutPoint extends ChildMessage {

    static final int MESSAGE_LENGTH = 36;

    /** Hash of the transaction to which we refer. */
    private Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    private long index;

    // This is not part of bitcoin serialization. It points to the connected transaction.
    Transaction fromTx;

    // The connected output.
    TransactionOutput connectedOutput;

    public TransactionOutPoint(NetworkParameters params, long index, @Nullable Transaction fromTx) {
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

    public TransactionOutPoint(NetworkParameters params, TransactionOutput connectedOutput) {
        this(params, connectedOutput.getIndex(), connectedOutput.getParentTransactionHash());
        this.connectedOutput = connectedOutput;
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
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @throws ProtocolException
     */
    public TransactionOutPoint(NetworkParameters params, byte[] payload, int offset, Message parent, MessageSerializer serializer) throws ProtocolException {
        super(params, payload, offset, parent, serializer, MESSAGE_LENGTH);
    }

    @Override
    protected void parse() throws ProtocolException {
        length = MESSAGE_LENGTH;
        hash = readHash();
        index = readUint32();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(hash.getReversedBytes());
        Utils.uint32ToByteStreamLE(index, stream);
    }

    /**
     * An outpoint is a part of a transaction input that points to the output of another transaction. If we have both
     * sides in memory, and they have been linked together, this returns a pointer to the connected output, or null
     * if there is no such connection.
     */
    @Nullable
    public TransactionOutput getConnectedOutput() {
        if (fromTx != null) {
            return fromTx.getOutputs().get((int) index);
        } else if (connectedOutput != null) {
            return connectedOutput;
        }
        return null;
    }

    /**
     * Returns the pubkey script from the connected output.
     * @throws java.lang.NullPointerException if there is no connected output.
     */
    public byte[] getConnectedPubKeyScript() {
        byte[] result = checkNotNull(getConnectedOutput()).getScriptBytes();
        checkState(result.length > 0);
        return result;
    }

    /**
     * Returns the ECKey identified in the connected output, for either P2PKH scripts or P2PK scripts.
     * For P2SH scripts you can use {@link #getConnectedRedeemData(KeyBag)} and then get the
     * key from RedeemData.
     * If the script form cannot be understood, throws ScriptException.
     *
     * @return an ECKey or null if the connected key cannot be found in the wallet.
     */
    @Nullable
    public ECKey getConnectedKey(KeyBag keyBag) throws ScriptException {
        TransactionOutput connectedOutput = getConnectedOutput();
        checkNotNull(connectedOutput, "Input is not connected so cannot retrieve key");
        Script connectedScript = connectedOutput.getScriptPubKey();
        if (ScriptPattern.isPayToPubKeyHash(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromPayToPubKeyHash(connectedScript);
            return keyBag.findKeyFromPubHash(addressBytes);
        } else if (ScriptPattern.isPayToPubKey(connectedScript)) {
            byte[] pubkeyBytes = ScriptPattern.extractKeyFromPayToPubKey(connectedScript);
            return keyBag.findKeyFromPubKey(pubkeyBytes);
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Could not understand form of connected output script: " + connectedScript);
        }
    }

    /**
     * Returns the RedeemData identified in the connected output, for either P2PKH scripts, P2PK
     * or P2SH scripts.
     * If the script forms cannot be understood, throws ScriptException.
     *
     * @return a RedeemData or null if the connected data cannot be found in the wallet.
     */
    @Nullable
    public RedeemData getConnectedRedeemData(KeyBag keyBag) throws ScriptException {
        TransactionOutput connectedOutput = getConnectedOutput();
        checkNotNull(connectedOutput, "Input is not connected so cannot retrieve key");
        Script connectedScript = connectedOutput.getScriptPubKey();
        if (ScriptPattern.isPayToPubKeyHash(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromPayToPubKeyHash(connectedScript);
            return RedeemData.of(keyBag.findKeyFromPubHash(addressBytes), connectedScript);
        } else if (ScriptPattern.isPayToPubKey(connectedScript)) {
            byte[] pubkeyBytes = ScriptPattern.extractKeyFromPayToPubKey(connectedScript);
            return RedeemData.of(keyBag.findKeyFromPubKey(pubkeyBytes), connectedScript);
        } else if (ScriptPattern.isPayToScriptHash(connectedScript)) {
            byte[] scriptHash = ScriptPattern.extractHashFromPayToScriptHash(connectedScript);
            return keyBag.findRedeemDataFromScriptHash(scriptHash);
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Could not understand form of connected output script: " + connectedScript);
        }
    }

    @Override
    public String toString() {
        return hash + ":" + index;
    }

    /**
     * Returns the hash of the transaction this outpoint references/spends/is connected to.
     */
    @Override
    public Sha256Hash getHash() {
        return hash;
    }

    void setHash(Sha256Hash hash) {
        this.hash = hash;
    }

    public long getIndex() {
        return index;
    }
    
    public void setIndex(long index) {
        this.index = index;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionOutPoint other = (TransactionOutPoint) o;
        return getIndex() == other.getIndex() && getHash().equals(other.getHash());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getIndex(), getHash());
    }
}
