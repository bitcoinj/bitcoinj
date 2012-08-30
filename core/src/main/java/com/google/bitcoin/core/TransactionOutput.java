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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * A TransactionOutput message contains a scriptPubKey that controls who is able to spend its value. It is a sub-part
 * of the Transaction message.
 */
public class TransactionOutput extends ChildMessage implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(TransactionOutput.class);
    private static final long serialVersionUID = -590332479859256824L;

    // A transaction output has some value and a script used for authenticating that the redeemer is allowed to spend
    // this output.
    private BigInteger value;
    private byte[] scriptBytes;

    // The script bytes are parsed and turned into a Script on demand.
    private transient Script scriptPubKey;

    // These fields are Java serialized but not Bitcoin serialized. They are used for tracking purposes in our wallet
    // only. If set to true, this output is counted towards our balance. If false and spentBy is null the tx output
    // was owned by us and was sent to somebody else. If false and spentBy is set it means this output was owned by
    // us and used in one of our own transactions (eg, because it is a change output).
    private boolean availableForSpending;
    private TransactionInput spentBy;

    // A reference to the transaction which holds this output.
    Transaction parentTransaction;
    private transient int scriptLen;

    /**
     * Deserializes a transaction output message. This is usually part of a transaction message.
     */
    public TransactionOutput(NetworkParameters params, Transaction parent, byte[] payload,
                             int offset) throws ProtocolException {
        super(params, payload, offset);
        parentTransaction = parent;
        availableForSpending = true;
    }

    /**
     * Deserializes a transaction output message. This is usually part of a transaction message.
     *
     * @param params NetworkParameters object.
     * @param msg Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first msg byte within the array.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @throws ProtocolException
     */
    public TransactionOutput(NetworkParameters params, Transaction parent, byte[] msg, int offset,
                             boolean parseLazy, boolean parseRetain) throws ProtocolException {
        super(params, msg, offset, parent, parseLazy, parseRetain, UNKNOWN_LENGTH);
        parentTransaction = parent;
        availableForSpending = true;
    }

    /**
     * Creates an output that sends 'value' to the given address (public key hash). The amount should be created with
     * something like {@link Utils#toNanoCoins(int, int)}. Typically you would use
     * {@link Transaction#addOutput(java.math.BigInteger, Address)} instead of creating a TransactionOutput directly.
     */
    public TransactionOutput(NetworkParameters params, Transaction parent, BigInteger value, Address to) {
        this(params, parent, value, Script.createOutputScript(to));
    }

    /**
     * Creates an output that sends 'value' to the given public key using a simple CHECKSIG script (no addresses). The
     * amount should be created with something like {@link Utils#toNanoCoins(int, int)}. Typically you would use
     * {@link Transaction#addOutput(java.math.BigInteger, ECKey)} instead of creating an output directly.
     */
    public TransactionOutput(NetworkParameters params, Transaction parent, BigInteger value, ECKey to) {
        this(params, parent, value, Script.createOutputScript(to));
    }

    public TransactionOutput(NetworkParameters params, Transaction parent, BigInteger value, byte[] scriptBytes) {
        super(params);
        this.value = value;
        this.scriptBytes = scriptBytes;
        parentTransaction = parent;
        availableForSpending = true;
        length = 8 + VarInt.sizeOf(scriptBytes.length) + scriptBytes.length;
    }

    public Script getScriptPubKey() throws ScriptException {
        if (scriptPubKey == null) {
            maybeParse();
            scriptPubKey = new Script(params, scriptBytes, 0, scriptBytes.length);
        }
        return scriptPubKey;
    }

    protected void parseLite() {
        // TODO: There is no reason to use BigInteger for values, they are always smaller than 21 million * COIN
        // The only reason to use BigInteger would be to properly read values from the reference implementation, however
        // the reference implementation uses signed 64-bit integers for its values as well (though it probably shouldn't)
        long outputValue = readInt64();
        value = BigInteger.valueOf(outputValue);
        scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen;
    }

    void parse() throws ProtocolException {
        scriptBytes = readBytes(scriptLen);
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        checkNotNull(scriptBytes);
        Utils.uint64ToByteStreamLE(getValue(), stream);
        // TODO: Move script serialization into the Script class, where it belongs.
        stream.write(new VarInt(scriptBytes.length).encode());
        stream.write(scriptBytes);
    }

    /**
     * Returns the value of this output in nanocoins. This is the amount of currency that the destination address
     * receives.
     */
    public BigInteger getValue() {
        maybeParse();
        return value;
    }

    int getIndex() {
        checkNotNull(parentTransaction);
        for (int i = 0; i < parentTransaction.getOutputs().size(); i++) {
            if (parentTransaction.getOutputs().get(i) == this)
                return i;
        }
        // Should never happen.
        throw new RuntimeException("Output linked to wrong parent transaction?");
    }

    /**
     * Sets this objects availableForSpending flag to false and the spentBy pointer to the given input.
     * If the input is null, it means this output was signed over to somebody else rather than one of our own keys.
     * @throws IllegalStateException if the transaction was already marked as spent.
     */
    public void markAsSpent(TransactionInput input) {
        checkState(availableForSpending);
        availableForSpending = false;
        spentBy = input;
    }

    /**
     * Resets the spent pointer / availableForSpending flag to null.
     */
    public void markAsUnspent() {
        availableForSpending = true;
        spentBy = null;
    }

    /**
     * Returns whether {@link TransactionOutput#markAsSpent(TransactionInput)} has been called on this class. A
     * {@link Wallet} will mark a transaction output as spent once it sees a transaction input that is connected to it.
     * Note that this flag can be false when an output has in fact been spent according to the rest of the network if
     * the spending transaction wasn't downloaded yet, and it can be marked as spent when in reality the rest of the
     * network believes it to be unspent if the signature or script connecting to it was not actually valid.
     */
    public boolean isAvailableForSpending() {
        return availableForSpending;
    }

    /**
     * The backing script bytes which can be turned into a Script object.
     * @return the scriptBytes
    */
    public byte[] getScriptBytes() {
        maybeParse();
        return scriptBytes;
    }

    /**
     * Returns true if this output is to a key, or an address we have the keys for, in the wallet.
     */
    public boolean isMine(Wallet wallet) {
        try {
            Script script = getScriptPubKey();
            if (script.isSentToRawPubKey()) {
                byte[] pubkey = script.getPubKey();
                return wallet.isPubKeyMine(pubkey);
            } else {
                byte[] pubkeyHash = script.getPubKeyHash();
                return wallet.isPubKeyHashMine(pubkeyHash);
            }
        } catch (ScriptException e) {
            // Just means we didn't understand the output of this transaction: ignore it.
            log.debug("Could not parse tx output script: {}", e.toString());
            return false;
        }
    }

    /**
     * Returns a human readable debug string.
     */
    public String toString() {
        try {
            return "TxOut of " + Utils.bitcoinValueToFriendlyString(value) + " to " + getScriptPubKey().getToAddress()
                    .toString() + " script:" + getScriptPubKey().toString();
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns the connected input.
     */
    public TransactionInput getSpentBy() {
        return spentBy;
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
}