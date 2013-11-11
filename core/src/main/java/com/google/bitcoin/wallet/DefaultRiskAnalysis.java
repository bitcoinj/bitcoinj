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

import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionConfidence;
import com.google.bitcoin.core.Wallet;

import javax.annotation.Nullable;
import java.util.List;

import static com.google.common.base.Preconditions.checkState;

/**
 * The default risk analysis. Currently, it only is concerned with whether a tx/dependency is non-final or not. Outside
 * of specialised protocols you should not encounter non-final transactions.
 */
public class DefaultRiskAnalysis implements RiskAnalysis {
    protected final Transaction tx;
    protected final List<Transaction> dependencies;
    protected final Wallet wallet;

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
