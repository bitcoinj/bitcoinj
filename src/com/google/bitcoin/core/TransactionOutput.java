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
     * @param params NetworkParameters object.
     * @param msg Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first msg byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public TransactionOutput(NetworkParameters params, Transaction parent, byte[] msg, int offset, boolean parseLazy, boolean parseRetain)
            throws ProtocolException {
        super(params, msg, offset, parent, parseLazy, parseRetain, UNKNOWN_LENGTH);
        parentTransaction = parent;
        availableForSpending = true;
    }

    TransactionOutput(NetworkParameters params, Transaction parent, BigInteger value, Address to) {
        super(params);
        this.value = value;
        this.scriptBytes = Script.createOutputScript(to);
        parentTransaction = parent;
        availableForSpending = true;
        length = 8 + VarInt.sizeOf(scriptBytes.length) + scriptBytes.length;
    }

    public TransactionOutput(NetworkParameters params, Transaction parent, BigInteger value, byte[] scriptBytes) {
        super(params);
        this.value = value;
        this.scriptBytes = scriptBytes;
        parentTransaction = parent;
        availableForSpending = true;
        length = 8 + VarInt.sizeOf(scriptBytes.length) + scriptBytes.length;
    }

    /**
     * Used only in creation of the genesis blocks and in unit tests.
     */
    TransactionOutput(NetworkParameters params, Transaction parent, byte[] scriptBytes) {
        super(params);
        this.scriptBytes = scriptBytes;
        this.value = Utils.toNanoCoins(50, 0);
        parentTransaction = parent;
        availableForSpending = true;
    }

    public Script getScriptPubKey() throws ScriptException {
        if (scriptPubKey == null) {
            maybeParse();
            scriptPubKey = new Script(params, scriptBytes, 0, scriptBytes.length);
        }
        return scriptPubKey;
    }

    protected void parseLite() {
        value = readUint64();
        scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen;
    }

    void parse() throws ProtocolException {
        scriptBytes = readBytes(scriptLen);
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        assert scriptBytes != null;
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
        assert parentTransaction != null;
        for (int i = 0; i < parentTransaction.getOutputs().size(); i++) {
            if (parentTransaction.getOutputs().get(i) == this)
                return i;
        }
        // Should never happen.
        throw new RuntimeException("Output linked to wrong parent transaction?");
    }

    /**
     * Sets this objects availableToSpend flag to false and the spentBy pointer to the given input.
     * If the input is null, it means this output was signed over to somebody else rather than one of our own keys.
     */
    public void markAsSpent(TransactionInput input) {
        assert availableForSpending;
        availableForSpending = false;
        spentBy = input;
    }

    void markAsUnspent() {
        availableForSpending = true;
        spentBy = null;
    }

    boolean isAvailableForSpending() {
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
     * Returns true if this output is to an address we have the keys for in the wallet.
     */
    public boolean isMine(Wallet wallet) {
        try {
            byte[] pubkeyHash = getScriptPubKey().getPubKeyHash();
            return wallet.isPubKeyHashMine(pubkeyHash);
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