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

import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptChunk;
import com.google.bitcoin.wallet.KeyBag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This transaction signer fills up empty signatures in partial input scripts with a dummy signature.
 */
public class DummySigSigner extends StatelessTransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(DummySigSigner.class);

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public boolean signInputs(ProposedTransaction propTx, KeyBag keyBag) {
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
            if (scriptPubKey.isPayToScriptHash()) {
                // all chunks except the first one (OP_0) and the last (redeem script) are signatures
                for (int j = 1; j < inputScript.getChunks().size() - 1; j++) {
                    ScriptChunk scriptChunk = inputScript.getChunks().get(j);
                    if (scriptChunk.equalsOpCode(0)) {
                        txIn.setScriptSig(scriptPubKey.getScriptSigWithSignature(inputScript, dummySig, j - 1));
                    }
                }
            } else {
                if (inputScript.getChunks().get(0).equalsOpCode(0))
                    txIn.setScriptSig(scriptPubKey.getScriptSigWithSignature(inputScript, dummySig, 0));
            }
        }
        return true;
    }
}
