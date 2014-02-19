/*
 * Copyright 2013 Google Inc.
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

package com.google.bitcoin.wallet;

import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.ScriptException;
import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionConfidence;
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptChunk;
import com.google.bitcoin.script.ScriptOpCodes;

import javax.annotation.Nullable;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Preconditions.checkState;

/**
 * The default risk analysis. Currently, it only is concerned with whether a tx/dependency is non-final or not. Outside
 * of specialised protocols you should not encounter non-final transactions.
 */
public class DefaultRiskAnalysis implements RiskAnalysis {
    protected final Transaction tx;
    protected final List<Transaction> dependencies;
    protected final Wallet wallet;

    private Transaction nonStandard;
    protected Transaction nonFinal;
    protected boolean analyzed;

    protected DefaultRiskAnalysis(Wallet wallet, Transaction tx, List<Transaction> dependencies) {
        this.tx = tx;
        this.dependencies = dependencies;
        this.wallet = wallet;
    }

    @Override
    public Result analyze() {
        checkState(!analyzed);
        analyzed = true;

        Result result = analyzeIsFinal();
        if (result != Result.OK)
            return result;

        return analyzeIsStandard();
    }

    private Result analyzeIsFinal() {
        // Transactions we create ourselves are, by definition, not at risk of double spending against us.
        if (tx.getConfidence().getSource() == TransactionConfidence.Source.SELF)
            return Result.OK;

        final int height = wallet.getLastBlockSeenHeight();
        final long time = wallet.getLastBlockSeenTimeSecs();
        // If the transaction has a lock time specified in blocks, we consider that if the tx would become final in the
        // next block it is not risky (as it would confirm normally).
        final int adjustedHeight = height + 1;

        if (!tx.isFinal(adjustedHeight, time)) {
            nonFinal = tx;
            return Result.NON_FINAL;
        }
        for (Transaction dep : dependencies) {
            if (!dep.isFinal(adjustedHeight, time)) {
                nonFinal = dep;
                return Result.NON_FINAL;
            }
        }
        return Result.OK;
    }

    private Result analyzeIsStandard() {
        if (!wallet.getNetworkParameters().getId().equals(NetworkParameters.ID_MAINNET))
            return Result.OK;

        Map<Sha256Hash, Transaction> depMap = new HashMap<Sha256Hash, Transaction>();
        for (Transaction transaction : dependencies)
            depMap.put(transaction.getHash(), transaction);

        nonStandard = isStandard(tx, depMap);
        if (nonStandard != null)
            return Result.NON_STANDARD;

        for (Transaction dep : dependencies) {
            nonStandard = isStandard(dep, depMap);
            if (nonStandard != null)
                return Result.NON_STANDARD;
        }

        return Result.OK;
    }

    private boolean isDataScript(Script scriptPubKey) {
        return scriptPubKey.getChunks().get(0).equalsOpCode(ScriptOpCodes.OP_RETURN) && (scriptPubKey.getChunks().size() == 1 ||
                (scriptPubKey.getChunks().size() == 2 && !scriptPubKey.getChunks().get(1).isOpCode() &&
                        scriptPubKey.getChunks().get(1).data.length <= 80));
    }

    private boolean isSentToStandardPayToPubKey(Script scriptPubKey) {
        return scriptPubKey.isSentToRawPubKey() && scriptPubKey.getChunks().get(0).data.length >= 33 &&
                scriptPubKey.getChunks().get(0).data.length <= 120;
    }

    private boolean isSentToValidMultisig(Script scriptPubKey) {
        if (!scriptPubKey.isSentToMultiSig())
            return false;

        List<ScriptChunk> scriptChunks = scriptPubKey.getChunks();
        // isSentToMultiSig() returns true for CHECKMULTISIGVERIFY, but that is non-standard
        if (!scriptChunks.get(scriptChunks.size() - 1).equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIG))
            return false;

        int n = Script.decodeFromOpN(scriptChunks.get(0).data[0]);
        for (int i = 0; i < n; i++) {
            if (scriptChunks.get(i).data.length < 33 || scriptChunks.get(i).data.length > 120)
                return false;
        }

        return true;
    }

    private int scriptArgsRequired(Script scriptPubKey, Script scriptSig) {
        if (scriptPubKey.isSentToAddress())
            return 2;

        if (isSentToStandardPayToPubKey(scriptPubKey))
            return 1;

        if (isSentToValidMultisig(scriptPubKey))
            return Script.decodeFromOpN(scriptPubKey.getChunks().get(scriptPubKey.getChunks().size() - 2).data[0]) + 1;

        if (scriptPubKey.isSentToP2SH()) {
            List<ScriptChunk> scriptSigChunks = scriptSig.getChunks();
            if (scriptSigChunks.isEmpty() || scriptSigChunks.get(scriptSigChunks.size() - 1).isOpCode())
                return -1;

            Script p2shScript;
            try {
                p2shScript = new Script(scriptSigChunks.get(scriptSigChunks.size()-1).data);
            } catch (ScriptException e) {
                return -1;
            }

            if (p2shScript.isSentToP2SH())
                return -1;

            return 1 + scriptArgsRequired(p2shScript, null);
        }

        return -1; // data scripts and non-standard scripts
    }

    /**
     * <p>Checks if a transaction is considered "standard" by the reference client's IsStandardTx and AreInputsStandard
     * functions.</p>
     *
     * <p>Note that dependencies is used only to verify the input scripts in tx are standard wrt the output scripts of
     * its dependencies, and are not checked for "standardness" themselves.</p>
     *
     * <p>Some non-standard transactions may be accepted by this function if any dependencies are missing.
     * </p>
     *
     * @return Either null if the transaction is standard, or the first transaction found which is considered nonstandard
     */
    public Transaction isStandard(Transaction tx, Map<Sha256Hash, Transaction> dependencyMap) {
        if (tx.getVersion() > 1 || tx.getVersion() < 1)
            return tx;

        byte[] originalSerialization = tx.unsafeBitcoinSerialize();
        Transaction reserializedTx = new Transaction(wallet.getParams(), originalSerialization, null, false, false,
                originalSerialization.length);
        byte[] reserializedBytes = reserializedTx.unsafeBitcoinSerialize();
        checkState(reserializedBytes != originalSerialization);
        if (originalSerialization.length != reserializedBytes.length)
            return tx;

        for (TransactionInput input : tx.getInputs()) {
            if (input.getScriptBytes().length > 500)
                return tx;

            if (input.getScriptSig().hasNonPushOpCodes())
                return tx;
        }

        boolean alreadyHadDataOut = false;
        for (TransactionOutput output : tx.getOutputs()) {
            Script scriptPubKey = output.getScriptPubKey();
            if (isSentToValidMultisig(scriptPubKey)) {
                List<ScriptChunk> scriptChunks = scriptPubKey.getChunks();
                int n = Script.decodeFromOpN(scriptChunks.get(0).data[0]);
                int m = Script.decodeFromOpN(scriptChunks.get(scriptChunks.size() - 2).data[0]);
                if (n < 1 || n > 3 || m < 1 || m > n)
                    return tx;
            } else if (isDataScript(scriptPubKey)) {
                // Note that we very explicitly do not have an isData() check in Script (and thus check them manually here).
                // Data outputs are not supported and should not be encouraged (use off-blockchain communication mechanisms
                // instead)
                if (alreadyHadDataOut)
                    return tx;
                alreadyHadDataOut = true;
                continue; // Skip dust output check for data outputs
            } else if (!scriptPubKey.isSentToAddress() && !scriptPubKey.isSentToP2SH() && !isSentToStandardPayToPubKey(scriptPubKey))
                return tx;
            if (output.getMinNonDustValue().compareTo(output.getValue()) > 0)
                return tx;
        }

        if (!tx.isCoinBase()) {
            for (TransactionInput input : tx.getInputs()) {
                Transaction dep = dependencyMap.get(input.getOutpoint().getHash());
                if (dep == null) // Just ignore non-standard inputs for missing prevouts
                    continue;
                TransactionOutput prevOut = dep.getOutput((int) input.getOutpoint().getIndex());
                if (prevOut == null)
                    continue;

                Script scriptPubKey = prevOut.getScriptPubKey();
                Script scriptSig = input.getScriptSig();
                int argsRequired = scriptArgsRequired(scriptPubKey, scriptSig);
                if (argsRequired == -1 || scriptSig.getChunks().size() != argsRequired)
                    return dep;
            }
        }

        return null;
    }

    /** Returns the transaction that was found to be non-standard, or null. */
    @Nullable
    public Transaction getNonStandard() {
        return nonStandard;
    }

    /** Returns the transaction that was found to be non-final, or null. */
    @Nullable
    public Transaction getNonFinal() {
        return nonFinal;
    }

    @Override
    public String toString() {
        if (!analyzed)
            return "Pending risk analysis for " + tx.getHashAsString();
        else if (nonFinal != null)
            return "Risky due to non-finality of " + nonFinal.getHashAsString();
        else
            return "Non-risky";
    }

    public static class Analyzer implements RiskAnalysis.Analyzer {
        @Override
        public DefaultRiskAnalysis create(Wallet wallet, Transaction tx, List<Transaction> dependencies) {
            return new DefaultRiskAnalysis(wallet, tx, dependencies);
        }
    }

    public static Analyzer FACTORY = new Analyzer();
}
