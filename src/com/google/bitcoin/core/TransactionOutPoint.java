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

// TODO: Fold this class into the TransactionInput class. It's not necessary.

/**
 * This message is a reference or pointer to an output of a different transaction.
 */
public class TransactionOutPoint extends Message implements Serializable {
    private static final long serialVersionUID = -6320880638344662579L;

    /** Hash of the transaction to which we refer. */
    Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    long index;

    // This is not part of Bitcoin serialization. It's included in Java serialization.
    // It points to the connected transaction.
    Transaction fromTx;

    TransactionOutPoint(NetworkParameters params, long index, Transaction fromTx) {
        super(params);
        this.index = index;
        if (fromTx != null) {
            this.hash = fromTx.getHash();
            this.fromTx = fromTx;
        } else {
            // This happens when constructing the genesis block.
            hash = Sha256Hash.ZERO_HASH;
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
        stream.write(Utils.reverseBytes(hash.getBytes()));
        Utils.uint32ToByteStreamLE(index, stream);
    }

    /**
     * If this transaction was created using the explicit constructor rather than deserialized,
     * retrieves the connected output transaction. Asserts if there is no connected transaction.
     */
    TransactionOutput getConnectedOutput() {
        if (fromTx == null) return null;
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
