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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import java.math.BigInteger;
import java.util.List;

import static com.google.common.base.Preconditions.checkState;

/**
 * <p>The default risk analysis. Currently, it only is concerned with whether a tx/dependency is non-final or not, and
 * whether a tx/dependency violates the dust rules. Outside of specialised protocols you should not encounter non-final
 * transactions.</p>
 */
public class DefaultRiskAnalysis implements RiskAnalysis {
    private static final Logger log = LoggerFactory.getLogger(DefaultRiskAnalysis.class);

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

    /**
     * The reason a transaction is considered non-standard, returned by
     * {@link #isStandard(com.google.bitcoin.core.Transaction)}.
     */
    public enum RuleViolation {
        NONE,
        VERSION,
        DUST
    }

    /**
     * <p>Checks if a transaction is considered "standard" by the reference client's IsStandardTx and AreInputsStandard
     * functions.</p>
     *
     * <p>Note that this method currently only implements a minimum of checks. More to be added later.</p>
     */
    public static RuleViolation isStandard(Transaction tx) {
        // TODO: Finish this function off.
        if (tx.getVersion() > 1 || tx.getVersion() < 1) {
            log.warn("TX considered non-standard due to unknown version number {}", tx.getVersion());
            return RuleViolation.VERSION;
        }

        final List<TransactionOutput> outputs = tx.getOutputs();
        for (int i = 0; i < outputs.size(); i++) {
            TransactionOutput output = outputs.get(i);
            if (MIN_ANALYSIS_NONDUST_OUTPUT.compareTo(output.getValue()) > 0) {
                log.warn("TX considered non-standard due to output {} being dusty", i);
                return RuleViolation.DUST;
            }
        }

        return RuleViolation.NONE;
    }

    private Result analyzeIsStandard() {
        // The IsStandard rules don't apply on testnet, because they're just a safety mechanism and we don't want to
        // crush innovation with valueless test coins.
        if (!wallet.getNetworkParameters().getId().equals(NetworkParameters.ID_MAINNET))
            return Result.OK;

        RuleViolation ruleViolation = isStandard(tx);
        if (ruleViolation != RuleViolation.NONE) {
            nonStandard = tx;
            return Result.NON_STANDARD;
        }

        for (Transaction dep : dependencies) {
            ruleViolation = isStandard(dep);
            if (ruleViolation != RuleViolation.NONE) {
                nonStandard = dep;
                return Result.NON_STANDARD;
            }
        }

        return Result.OK;
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
