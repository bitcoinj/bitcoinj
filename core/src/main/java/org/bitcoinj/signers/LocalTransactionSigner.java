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
package org.bitcoinj.signers;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>{@link TransactionSigner} implementation for signing inputs using keys from provided {@link org.bitcoinj.wallet.KeyBag}.</p>
 * <p>This signer doesn't create input scripts for tx inputs. Instead it expects inputs to contain scripts with
 * empty sigs and replaces one of the empty sigs with calculated signature.
 * </p>
 * <p>This signer is always implicitly added into every wallet and it is the first signer to be executed during tx
 * completion. As the first signer to create a signature, it stores derivation path of the signing key in a given
 * {@link ProposedTransaction} object that will be also passed then to the next signer in chain. This allows other
 * signers to use correct signing key for P2SH inputs, because all the keys involved in a single P2SH address have
 * the same derivation path.</p>
 * <p>This signer always uses {@link org.bitcoinj.core.Transaction.SigHash#ALL} signing mode.</p>
 */
public class LocalTransactionSigner extends StatelessTransactionSigner {
    private static final Logger log = LoggerFactory.getLogger(LocalTransactionSigner.class);

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
            if (txIn.getConnectedOutput() == null) {
                log.warn("Missing connected output, assuming input {} is already signed.", i);
                continue;
            }

            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                // we sign missing pieces (to check this would require either assuming any signatures are signing
                // standard output types or a way to get processed signatures out of script execution)
                txIn.getScriptSig().correctlySpends(tx, i, txIn.getConnectedOutput().getScriptPubKey());
                log.warn("Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                continue;
            } catch (ScriptException e) {
                // Expected.
            }

            RedeemData redeemData = txIn.getConnectedRedeemData(keyBag);

            Script scriptPubKey = txIn.getConnectedOutput().getScriptPubKey();

            // For P2SH inputs we need to share derivation path of the signing key with other signers, so that they
            // use correct key to calculate their signatures.
            // Married keys all have the same derivation path, so we can safely just take first one here.
            ECKey pubKey = redeemData.keys.get(0);
            if (pubKey instanceof DeterministicKey)
                propTx.keyPaths.put(scriptPubKey, (((DeterministicKey) pubKey).getPath()));

            ECKey key;
            // locate private key in redeem data. For pay-to-address and pay-to-key inputs RedeemData will always contain
            // only one key (with private bytes). For P2SH inputs RedeemData will contain multiple keys, one of which MAY
            // have private bytes
            if ((key = redeemData.getFullKey()) == null) {
                log.warn("No local key found for input {}", i);
                continue;
            }

            Script inputScript = txIn.getScriptSig();
            // script here would be either a standard CHECKSIG program for pay-to-address or pay-to-pubkey inputs or
            // a CHECKMULTISIG program for P2SH inputs
            byte[] script = redeemData.redeemScript.getProgram();
            try {
                TransactionSignature signature = tx.calculateSignature(i, key, script, Transaction.SigHash.ALL, false);

                // at this point we have incomplete inputScript with OP_0 in place of one or more signatures. We already
                // have calculated the signature using the local key and now need to insert it in the correct place
                // within inputScript. For pay-to-address and pay-to-key script there is only one signature and it always
                // goes first in an inputScript (sigIndex = 0). In P2SH input scripts we need to figure out our relative
                // position relative to other signers.  Since we don't have that information at this point, and since
                // we always run first, we have to depend on the other signers rearranging the signatures as needed.
                // Therefore, always place as first signature.
                int sigIndex = 0;
                inputScript = scriptPubKey.getScriptSigWithSignature(inputScript, signature.encodeToBitcoin(), sigIndex);
                txIn.setScriptSig(inputScript);
            } catch (ECKey.KeyIsEncryptedException e) {
                throw e;
            } catch (ECKey.MissingPrivateKeyException e) {
                log.warn("No private key in keypair for input {}", i);
            }

        }
        return true;
    }

}
