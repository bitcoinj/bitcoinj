/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionConfidence;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.Wallet;

import javax.annotation.Nullable;

import java.math.BigInteger;
import java.util.List;

import static com.google.common.base.Preconditions.checkState;

/**
 * The default risk analysis. Currently, it only is concerned with whether a tx/dependency is non-final or not. Outside
 * of specialised protocols you should not encounter non-final transactions.
 */
public class DefaultRiskAnalysis implements RiskAnalysis {
    /**
     * Any standard output smaller than this value (in satoshis) will be considered risky, as it's most likely be
     * rejected by the network. Currently it's 546 satoshis. This is different from {@link Transaction#MIN_NONDUST_OUTPUT}
     * because of an upcoming fee change in Bitcoin Core 0.9.
     */
    public static final BigInteger MIN_ANALYSIS_NONDUST_OUTPUT = BigInteger.valueOf(546);

    protected final Transaction tx;
    protected final List<Transaction> dependencies;
    protected final Wallet wallet;

    private Transaction nonStandard;
    protected Transaction nonFinal;
    protected boolean analyzed;

    private DefaultRiskAnalysis(Wallet wallet, Transaction tx, List<Transaction> dependencies) {
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

        nonStandard = isStandard(tx);
        if (nonStandard != null)
            return Result.NON_STANDARD;

        for (Transaction dep : dependencies) {
            nonStandard = isStandard(dep);
            if (nonStandard != null)
                return Result.NON_STANDARD;
        }

        return Result.OK;
    }

    /**
     * <p>Checks if a transaction is considered "standard" by the reference client's IsStandardTx and AreInputsStandard
     * functions.</p>
     *
     * <p>Note that this method currently only implements a minimum of checks. More to be added later.</p>
     *
     * @return Either null if the transaction is standard, or the first transaction found which is considered nonstandard
     */
    public Transaction isStandard(Transaction tx) {
        if (tx.getVersion() > 1 || tx.getVersion() < 1)
            return tx;

        for (TransactionOutput output : tx.getOutputs()) {
            if (MIN_ANALYSIS_NONDUST_OUTPUT.compareTo(output.getValue()) > 0)
                return tx;
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
        else if (nonStandard != null)
            return "Risky due to non-standard tx " + nonStandard.getHashAsString();
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
