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

/**
 * This message is effectively a reference or pointer to a transaction output.
 */
public class TransactionOutPoint extends Message implements Serializable {
    // ID of the transaction to which we refer.

    byte[] hash;
    // Which output of that transaction we are talking about.
    long index;

    // This is not part of bitcoin serialization.
    Transaction fromTx;

    TransactionOutPoint(NetworkParameters params, long index,  Transaction fromTx) {
        super(params);
        this.index = index;
        if (fromTx != null) {
            this.hash = fromTx.getHash();
            this.fromTx = fromTx;
        } else {
            // This happens when constructing the genesis block.
            hash = new byte[32];  // All zeros.
        }
    }

    /** Deserializes the message. This is usually part of a transaction message. */
    public TransactionOutPoint(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
    }
    
    @Override
    void parse() throws ProtocolException {
        hash = readHash();
        index = readUint32();
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        assert hash.length == 32;
        stream.write(Utils.reverseBytes(hash));
        Utils.uint32ToByteStreamLE(index, stream);
    }

    /**
     * If this transaction was created using the explicit constructor rather than deserialized,
     * retrieves the connected output transaction. Asserts if there is no connected transaction.
     * @return
     */
    TransactionOutput getConnectedOutput() {
        assert fromTx != null;
        return fromTx.outputs.get((int)index);
    }

    /**
     * Returns the pubkey script from the connected output.
     */
    byte[] getConnectedPubKeyScript() {
        byte[] result = getConnectedOutput().getScriptBytes();
        assert result != null;
        assert result.length > 0;
        return result;
    }

    /**
     * Convenience method to get the connected outputs pubkey hash.
     */
    byte[] getConnectedPubKeyHash() throws ScriptException {
        return getConnectedOutput().getScriptPubKey().getPubKeyHash();
    }
}
