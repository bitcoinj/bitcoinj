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

package org.bitcoinj.wallet;

import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Wallet;

import java.util.List;

/**
 * <p>A RiskAnalysis represents an analysis of how likely it is that a transaction (and its dependencies) represents a
 * possible double spending attack. The wallet will create these to decide whether or not to accept a pending
 * transaction. Look at {@link DefaultRiskAnalysis} to see what is currently considered risky.</p>
 *
 * <p>The intention here is that implementing classes can expose more information and detail about the result, for
 * app developers. The core code needs only to know whether it's OK or not.</p>
 *
 * <p>A factory interface is provided. The wallet will use this to analyze new pending transactions.</p>
 */
public interface RiskAnalysis {
    public enum Result {
        OK,
        NON_FINAL,
        NON_STANDARD
    }

    public Result analyze();

    public interface Analyzer {
        public RiskAnalysis create(Wallet wallet, Transaction tx, List<Transaction> dependencies);
    }
}
