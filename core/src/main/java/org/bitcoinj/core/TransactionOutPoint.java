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

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptError;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;

import javax.annotation.Nullable;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * <p>This message is a reference or pointer to an output of a different transaction.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class TransactionOutPoint {
    public static final int BYTES = 36;

    /** Special outpoint that normally marks a coinbase input. It's also used as a test dummy. */
    public static final TransactionOutPoint UNCONNECTED =
            new TransactionOutPoint(ByteUtils.MAX_UNSIGNED_INTEGER, Sha256Hash.ZERO_HASH);

    /** Hash of the transaction to which we refer. */
    private final Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    private final long index;

    // This is not part of bitcoin serialization. It points to the connected transaction.
    final Transaction fromTx;

    // The connected output.
    final TransactionOutput connectedOutput;

    /**
     * Deserialize this transaction outpoint from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read transaction outpoint
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static TransactionOutPoint read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        Sha256Hash hash = Sha256Hash.read(payload);
        long index = ByteUtils.readUint32(payload);
        return new TransactionOutPoint(index, hash);
    }

    public TransactionOutPoint(long index, Transaction fromTx) {
        this(fromTx.getTxId(), index, fromTx, null);
    }

    public TransactionOutPoint(long index, Sha256Hash hash) {
        this(hash, index, null, null);
    }

    public TransactionOutPoint(TransactionOutput connectedOutput) {
        this(connectedOutput.getParentTransactionHash(), connectedOutput.getIndex(), null, connectedOutput);
    }

    private TransactionOutPoint(Sha256Hash hash, long index, @Nullable Transaction fromTx,
                                @Nullable TransactionOutput connectedOutput) {
        this.hash = Objects.requireNonNull(hash);
        checkArgument(index >= 0 && index <= ByteUtils.MAX_UNSIGNED_INTEGER, () ->
                "index out of range: " + index);
        this.index = index;
        this.fromTx = fromTx;
        this.connectedOutput = connectedOutput;
    }

    /**
     * Write this transaction outpoint into the given buffer.
     *
     * @param buf buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the outpoint doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        buf.put(hash.serialize());
        ByteUtils.writeInt32LE(index, buf);
        return buf;
    }

    /**
     * Allocates a byte array and writes this transaction outpoint into it.
     *
     * @return byte array containing the transaction outpoint
     */
    public byte[] serialize() {
        return write(ByteBuffer.allocate(BYTES)).array();
    }

    /**
     * An outpoint is a part of a transaction input that points to the output of another transaction. If we have both
     * sides in memory, and they have been linked together, this returns a pointer to the connected output, or null
     * if there is no such connection.
     */
    @Nullable
    public TransactionOutput getConnectedOutput() {
        if (fromTx != null) {
            return fromTx.getOutput(index);
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
        byte[] result = Objects.requireNonNull(getConnectedOutput()).getScriptBytes();
        checkState(result.length > 0);
        return result;
    }

    /**
     * Returns the ECKey identified in the connected output, for either P2PKH, P2WPKH or P2PK scripts.
     * For P2SH scripts you can use {@link #getConnectedRedeemData(KeyBag)} and then get the
     * key from RedeemData.
     * If the script form cannot be understood, throws ScriptException.
     *
     * @return an ECKey or null if the connected key cannot be found in the wallet.
     */
    @Nullable
    public ECKey getConnectedKey(KeyBag keyBag) throws ScriptException {
        TransactionOutput connectedOutput = getConnectedOutput();
        Objects.requireNonNull(connectedOutput, "Input is not connected so cannot retrieve key");
        Script connectedScript = connectedOutput.getScriptPubKey();
        if (ScriptPattern.isP2PKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2PKH(connectedScript);
            return keyBag.findKeyFromPubKeyHash(addressBytes, ScriptType.P2PKH);
        } else if (ScriptPattern.isP2WPKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2WH(connectedScript);
            return keyBag.findKeyFromPubKeyHash(addressBytes, ScriptType.P2WPKH);
        } else if (ScriptPattern.isP2PK(connectedScript)) {
            byte[] pubkeyBytes = ScriptPattern.extractKeyFromP2PK(connectedScript);
            return keyBag.findKeyFromPubKey(pubkeyBytes);
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Could not understand form of connected output script: " + connectedScript);
        }
    }

    /**
     * Returns the RedeemData identified in the connected output, for either P2PKH, P2WPKH, P2PK
     * or P2SH scripts.
     * If the script forms cannot be understood, throws ScriptException.
     *
     * @return a RedeemData or null if the connected data cannot be found in the wallet.
     */
    @Nullable
    public RedeemData getConnectedRedeemData(KeyBag keyBag) throws ScriptException {
        TransactionOutput connectedOutput = getConnectedOutput();
        Objects.requireNonNull(connectedOutput, "Input is not connected so cannot retrieve key");
        Script connectedScript = connectedOutput.getScriptPubKey();
        if (ScriptPattern.isP2PKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2PKH(connectedScript);
            return RedeemData.of(keyBag.findKeyFromPubKeyHash(addressBytes, ScriptType.P2PKH), connectedScript);
        } else if (ScriptPattern.isP2WPKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2WH(connectedScript);
            return RedeemData.of(keyBag.findKeyFromPubKeyHash(addressBytes, ScriptType.P2WPKH), connectedScript);
        } else if (ScriptPattern.isP2PK(connectedScript)) {
            byte[] pubkeyBytes = ScriptPattern.extractKeyFromP2PK(connectedScript);
            return RedeemData.of(keyBag.findKeyFromPubKey(pubkeyBytes), connectedScript);
        } else if (ScriptPattern.isP2SH(connectedScript)) {
            byte[] scriptHash = ScriptPattern.extractHashFromP2SH(connectedScript);
            return keyBag.findRedeemDataFromScriptHash(scriptHash);
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Could not understand form of connected output script: " + connectedScript);
        }
    }

    /**
     * Returns a copy of this outpoint, but with the connectedOutput removed.
     * @return outpoint with removed connectedOutput
     */
    public TransactionOutPoint disconnectOutput() {
        return new TransactionOutPoint(hash, index, fromTx, null);
    }

    /**
     * Returns a copy of this outpoint, but with the provided transaction as fromTx.
     * @param transaction transaction to set as fromTx
     * @return outpoint with fromTx set
     */
    public TransactionOutPoint connectTransaction(Transaction transaction) {
        return new TransactionOutPoint(hash, index, Objects.requireNonNull(transaction), connectedOutput);
    }

    /**
     * Returns a copy of this outpoint, but with fromTx removed.
     * @return outpoint with removed fromTx
     */
    public TransactionOutPoint disconnectTransaction() {
        return new TransactionOutPoint(hash, index, null, connectedOutput);
    }

    @Override
    public String toString() {
        return hash + ":" + index;
    }

    /**
     * Returns the hash of the transaction this outpoint references/spends/is connected to.
     */
    public Sha256Hash hash() {
        return hash;
    }

    /**
     * @return the index of this outpoint
     */
    public long index() {
        return index;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionOutPoint other = (TransactionOutPoint) o;
        return index == other.index && hash.equals(other.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(index, hash);
    }
}
