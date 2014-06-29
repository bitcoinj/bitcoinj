/**
 * Copyright 2014 Kosta Korenkov
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
package com.google.bitcoin.signers;

import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.wallet.KeyBag;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

/**
 * <p>Implementations of this interface are intended to sign inputs of the given transaction. Given transaction may already
 * be partially signed or somehow altered by other signers.</p>
 * <p>To make use of the signer, you need to add it into the  wallet by
 * calling {@link com.google.bitcoin.core.Wallet#addTransactionSigner(TransactionSigner)}. Signer will be serialized
 * along with the wallet data. In order for wallet to recreate signer after deserialization, each signer
 * should have no-args constructor</p>
 */
public interface TransactionSigner {

    /**
     * Returns true if this signer is ready to be used.
     */
    boolean isReady();

    /**
     * Returns byte array of data representing state of this signer. It's used to serialize/deserialize this signer
     */
    byte[] serialize();

    /**
     * Uses given byte array of data to reconstruct internal state of this signer
     */
    void deserialize(byte[] data);

    /**
     * Signs given transaction's inputs.
     * Returns true if signer is compatible with given transaction (can do something meaningful with it).
     * Otherwise this method returns false
     */
    boolean signInputs(Transaction tx, KeyBag keyBag);

}
