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
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;

/**
 * A TransactionOutput message contains a scriptPubKey that controls who is able to spend its value. It is a sub-part
 * of the Transaction message.
 */
public class TransactionOutput extends Message implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(TransactionOutput.class);
    private static final long serialVersionUID = -590332479859256824L;

    // A transaction output has some value and a script used for authenticating that the redeemer is allowed to spend
    // this output.
    private BigInteger value;
    private byte[] scriptBytes;

    // The script bytes are parsed and turned into a Script on demand.
    private transient Script scriptPubKey;

    // These fields are Java serialized but not BitCoin serialized. They are used for tracking purposes in our wallet
    // only. If set to true, this output is counted towards our balance. If false and spentBy is null the tx output
    // was owned by us and was sent to somebody else. If false and spentBy is true it means this output was owned by
    // us and used in one of our own transactions (eg, because it is a change output).
    private boolean availableForSpending;
    private TransactionInput spentBy;

    // A reference to the transaction which holds this output.
    Transaction parentTransaction;
    
    /** Deserializes a transaction output message. This is usually part of a transaction message. */
    public TransactionOutput(NetworkParameters params, Transaction parent, byte[] payload,
                             int offset) throws ProtocolException {
        super(params, payload, offset);
        parentTransaction = parent;
        availableForSpending = true;
    }

    TransactionOutput(NetworkParameters params, Transaction parent, BigInteger value, Address to) {
        super(params);
        this.value = value;
        this.scriptBytes = Script.createOutputScript(to);
        parentTransaction = parent;
        availableForSpending = true;
    }

    /** Used only in creation of the genesis blocks and in unit tests. */
    TransactionOutput(NetworkParameters params, Transaction parent, byte[] scriptBytes) {
        super(params);
        this.scriptBytes = scriptBytes;
        this.value = Utils.toNanoCoins(50, 0);
        parentTransaction = parent;
        availableForSpending = true;
    }

    public Script getScriptPubKey() throws ScriptException {
        if (scriptPubKey == null)
            scriptPubKey = new Script(params, scriptBytes, 0, scriptBytes.length);
        return scriptPubKey;
    }
    
    void parse() throws ProtocolException {
        value = readUint64();
        int scriptLen = (int) readVarInt();
        scriptBytes = readBytes(scriptLen);
    }
    
    @Override
    public void bitcoinSerializeToStream( OutputStream stream) throws IOException {
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
        return value;
    }

    int getIndex() {
        assert parentTransaction != null;
        for (int i = 0; i < parentTransaction.outputs.size(); i++) {
            if (parentTransaction.outputs.get(i) == this)
                return i;
        }
        // Should never happen.
        throw new RuntimeException("Output linked to wrong parent transaction?");
    }

    /**
     * Sets this objects availableToSpend flag to false and the spentBy pointer to the given input.
     * If the input is null, it means this output was signed over to somebody else rather than one of our own keys.
     */
    void markAsSpent(TransactionInput input) {
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

    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /** Returns true if this output is to an address we have the keys for in the wallet. */
    public boolean isMine(Wallet wallet) {
        try {
            byte[] pubkeyHash = getScriptPubKey().getPubKeyHash();
            return wallet.isPubKeyHashMine(pubkeyHash);
        } catch (ScriptException e) {
            log.error("Could not parse tx output script: {}", e.toString());
            return false;
        }
    }

    /** Returns a human readable debug string. */
    public String toString() {
        try {
            return "TxOut of " + Utils.bitcoinValueToFriendlyString(value) + " to " + getScriptPubKey().getToAddress()
                    .toString() + " script:" + getScriptPubKey().toString();
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns the connected input. */
    TransactionInput getSpentBy() {
        return spentBy;
    }
}