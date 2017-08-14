/*
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

package org.bitcoincashj.signers;

import org.bitcoincashj.core.ECKey;
import org.bitcoincashj.core.TransactionInput;
import org.bitcoincashj.crypto.TransactionSignature;
import org.bitcoincashj.script.Script;
import org.bitcoincashj.script.ScriptChunk;
import org.bitcoincashj.wallet.KeyBag;
import org.bitcoincashj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This transaction signer resolves missing signatures in accordance with the given {@link org.bitcoincashj.wallet.Wallet.MissingSigsMode}.
 * If missingSigsMode is USE_OP_ZERO this signer does nothing assuming missing signatures are already presented in
 * scriptSigs as OP_0.
 * In MissingSigsMode.THROW mode this signer will throw an exception. It would be MissingSignatureException
 * for P2SH or MissingPrivateKeyException for other transaction types.
 */
public class MissingSigResolutionSigner extends StatelessTransactionSigner {
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
            if (scriptPubKey.isPayToScriptHash() || scriptPubKey.isSentToMultiSig()) {
                int sigSuffixCount = scriptPubKey.isPayToScriptHash() ? 1 : 0;
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
            } else {
                if (inputScript.getChunks().get(0).equalsOpCode(0)) {
                    if (missingSigsMode == Wallet.MissingSigsMode.THROW) {
                        throw new ECKey.MissingPrivateKeyException();
                    } else if (missingSigsMode == Wallet.MissingSigsMode.USE_DUMMY_SIG) {
                        txIn.setScriptSig(scriptPubKey.getScriptSigWithSignature(inputScript, dummySig, 0));
                    }
                }
            }
            // TODO handle non-P2SH multisig
        }
        return true;
    }
}
