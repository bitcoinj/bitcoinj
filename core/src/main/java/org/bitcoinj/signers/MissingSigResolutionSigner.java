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

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This transaction signer resolves missing signatures in accordance with the given {@link Wallet.MissingSigsMode}.
 * If missingSigsMode is USE_OP_ZERO this signer does nothing assuming missing signatures are already presented in
 * scriptSigs as OP_0.
 * In MissingSigsMode.THROW mode this signer will throw an exception. It would be MissingSignatureException
 * for P2SH or MissingPrivateKeyException for other transaction types.
 */
public class MissingSigResolutionSigner implements TransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(MissingSigResolutionSigner.class);

    public Wallet.MissingSigsMode missingSigsMode = Wallet.MissingSigsMode.USE_DUMMY_SIG;

    public MissingSigResolutionSigner() {
    }

    public MissingSigResolutionSigner(Wallet.MissingSigsMode missingSigsMode) {
        this.missingSigsMode = missingSigsMode;
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public boolean signInputs(ProposedTransaction propTx, KeyBag keyBag) {
        if (missingSigsMode == Wallet.MissingSigsMode.USE_OP_ZERO)
            return true;

        int numInputs = propTx.partialTx.getInputs().size();
        byte[] dummySig = TransactionSignature.dummy().encodeToBitcoin();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = propTx.partialTx.getInput(i);
            if (txIn.getConnectedOutput() == null) {
                log.warn("Missing connected output, assuming input {} is already signed.", i);
                continue;
            }

            Script scriptPubKey = txIn.getConnectedOutput().getScriptPubKey();
            Script inputScript = txIn.getScriptSig();
            if (ScriptPattern.isP2SH(scriptPubKey) || ScriptPattern.isSentToMultisig(scriptPubKey)) {
                int sigSuffixCount = ScriptPattern.isP2SH(scriptPubKey) ? 1 : 0;
                // all chunks except the first one (OP_0) and the last (redeem script) are signatures
                for (int j = 1; j < inputScript.getChunks().size() - sigSuffixCount; j++) {
                    ScriptChunk scriptChunk = inputScript.getChunks().get(j);
                    if (scriptChunk.equalsOpCode(0)) {
                        if (missingSigsMode == Wallet.MissingSigsMode.THROW) {
                            throw new MissingSignatureException();
                        } else if (missingSigsMode == Wallet.MissingSigsMode.USE_DUMMY_SIG) {
                            txIn.setScriptSig(scriptPubKey.getScriptSigWithSignature(inputScript, dummySig, j - 1));
                        }
                    }
                }
            } else if (ScriptPattern.isP2PK(scriptPubKey) || ScriptPattern.isP2PKH(scriptPubKey)) {
                if (inputScript.getChunks().get(0).equalsOpCode(0)) {
                    if (missingSigsMode == Wallet.MissingSigsMode.THROW) {
                        throw new ECKey.MissingPrivateKeyException();
                    } else if (missingSigsMode == Wallet.MissingSigsMode.USE_DUMMY_SIG) {
                        txIn.setScriptSig(scriptPubKey.getScriptSigWithSignature(inputScript, dummySig, 0));
                    }
                }
            } else if (ScriptPattern.isP2WPKH(scriptPubKey)) {
                if (txIn.getWitness() == null || txIn.getWitness().equals(TransactionWitness.EMPTY)
                        || txIn.getWitness().getPush(0).length == 0) {
                    if (missingSigsMode == Wallet.MissingSigsMode.THROW) {
                        throw new ECKey.MissingPrivateKeyException();
                    } else if (missingSigsMode == Wallet.MissingSigsMode.USE_DUMMY_SIG) {
                        ECKey key = keyBag.findKeyFromPubKeyHash(
                                ScriptPattern.extractHashFromP2WH(scriptPubKey), Script.ScriptType.P2WPKH);
                        txIn.setWitness(TransactionWitness.redeemP2WPKH(TransactionSignature.dummy(), key));
                    }
                }
            } else {
                throw new IllegalStateException("cannot handle: " + scriptPubKey);
            }
        }
        return true;
    }
}
