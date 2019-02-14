/*
 * Copyright 2014 Kosta Korenkov
 * Copyright 2019 Andreas Schildbach
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

package org.bitcoinj.signers;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>This signer may be used as a template for creating custom multisig transaction signers.</p>
 * <p>
 * Concrete implementations have to implement {@link #getSignature(Sha256Hash, List)}
 * method returning a signature and a public key of the keypair used to created that signature.
 * It's up to custom implementation where to locate signatures: it may be a network connection,
 * some local API or something else.
 * </p>
 */
public abstract class CustomTransactionSigner implements TransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(CustomTransactionSigner.class);

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public boolean signInputs(ProposedTransaction propTx, KeyBag keyBag) {
        Transaction tx = propTx.partialTx;
        int numInputs = tx.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = tx.getInput(i);
            TransactionOutput txOut = txIn.getConnectedOutput();
            if (txOut == null) {
                continue;
            }
            Script scriptPubKey = txOut.getScriptPubKey();
            if (!ScriptPattern.isP2SH(scriptPubKey)) {
                log.warn("CustomTransactionSigner works only with P2SH transactions");
                return false;
            }

            Script inputScript = checkNotNull(txIn.getScriptSig());

            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard output types or a way to get processed signatures out of script execution)
                txIn.getScriptSig().correctlySpends(tx, i, txIn.getWitness(), txOut.getValue(), txOut.getScriptPubKey(),
                        Script.ALL_VERIFY_FLAGS);
                log.warn("Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                continue;
            } catch (ScriptException e) {
                // Expected.
            }

            RedeemData redeemData = txIn.getConnectedRedeemData(keyBag);
            if (redeemData == null) {
                log.warn("No redeem data found for input {}", i);
                continue;
            }

            Sha256Hash sighash = tx.hashForSignature(i, redeemData.redeemScript, Transaction.SigHash.ALL, false);
            SignatureAndKey sigKey = getSignature(sighash, propTx.keyPaths.get(scriptPubKey));
            TransactionSignature txSig = new TransactionSignature(sigKey.sig, Transaction.SigHash.ALL, false);
            int sigIndex = inputScript.getSigInsertionIndex(sighash, sigKey.pubKey);
            inputScript = scriptPubKey.getScriptSigWithSignature(inputScript, txSig.encodeToBitcoin(), sigIndex);
            txIn.setScriptSig(inputScript);
        }
        return true;
    }

    protected abstract SignatureAndKey getSignature(Sha256Hash sighash, List<ChildNumber> derivationPath);

    public class SignatureAndKey {
        public final ECKey.ECDSASignature sig;
        public final ECKey pubKey;

        public SignatureAndKey(ECKey.ECDSASignature sig, ECKey pubKey) {
            this.sig = sig;
            this.pubKey = pubKey;
        }
    }

}


