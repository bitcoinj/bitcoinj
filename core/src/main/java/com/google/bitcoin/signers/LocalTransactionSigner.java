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

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.ScriptException;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.wallet.KeyBag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>{@link TransactionSigner} implementation for signing inputs using keys from provided {@link com.google.bitcoin.wallet.KeyBag}.
 * It always uses {@link com.google.bitcoin.core.Transaction.SigHash#ALL} signing mode.</p>
 * <p>At the moment it works for pay-to-address and pay-to-pubkey outputs only and will throw {@link RuntimeException} for
 * other script types</p>
 */
public class LocalTransactionSigner implements TransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(LocalTransactionSigner.class);

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public byte[] serialize() {
        return new byte[0];
    }

    @Override
    public void deserialize(byte[] data) {
    }

    @Override
    public boolean signInputs(Transaction tx, KeyBag keyBag) {
        int numInputs = tx.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            if (txIn.getConnectedOutput() == null) {
                log.warn("Missing connected output, assuming input {} is already signed.", i);
                continue;
            }

            Script scriptPubKey = txIn.getConnectedOutput().getScriptPubKey();

            // skip input if it spends not pay-to-address or pay-to-pubkey tx
            // we're not returning false here as this signer theoretically could still sign
            // some of the inputs (if someday it would be possible to have inputs mixed with multisig)
            if (!scriptPubKey.isSentToAddress() && !scriptPubKey.isSentToRawPubKey())
                continue;

            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard output types or a way to get processed signatures out of script execution)
                txIn.getScriptSig().correctlySpends(tx, i, txIn.getConnectedOutput().getScriptPubKey(), true);
                log.warn("Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                continue;
            } catch (ScriptException e) {
                // Expected.
            }

            ECKey key = txIn.getOutpoint().getConnectedKey(keyBag);
            // This assert should never fire. If it does, it means the wallet is inconsistent.
            checkNotNull(key, "Transaction exists in wallet that we cannot redeem: %s", txIn.getOutpoint().getHash());
            byte[] connectedPubKeyScript = txIn.getOutpoint().getConnectedPubKeyScript();
            TransactionSignature signature;
            try {
                signature = tx.calculateSignature(i, key, connectedPubKeyScript, Transaction.SigHash.ALL, false);
            } catch (ECKey.KeyIsEncryptedException e) {
                throw e;
            } catch (ECKey.MissingPrivateKeyException e) {
                // Create a dummy signature to ensure the transaction is of the correct size when we try to ensure
                // the right fee-per-kb is attached. If the wallet doesn't have the privkey, the user is assumed to
                // be doing something special and that they will replace the dummy signature with a real one later.
                signature = TransactionSignature.dummy();
                log.info("Used dummy signature for input {} due to failure during signing (most likely missing privkey)", i);
            }
            if (scriptPubKey.isSentToAddress()) {
                txIn.setScriptSig(ScriptBuilder.createInputScript(signature, key));
            } else if (scriptPubKey.isSentToRawPubKey()) {
                txIn.setScriptSig(ScriptBuilder.createInputScript(signature));
            }
            // if input spends not pay-to-address or pay-to-pubkey tx
            // we're not returning false here as this signer theoretically could still sign
            // some of the inputs (if someday it would be possible to have inputs mixed with multisig)

        }
        return true;
    }

}
