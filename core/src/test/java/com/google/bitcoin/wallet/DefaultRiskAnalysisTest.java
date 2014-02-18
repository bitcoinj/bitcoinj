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

import com.google.bitcoin.core.*;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.script.ScriptOpCodes;
import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

public class DefaultRiskAnalysisTest {
    // Uses mainnet because isStandard checks are disabled on testnet.
    private static final NetworkParameters params = MainNetParams.get();
    private Wallet wallet;
    private final int TIMESTAMP = 1384190189;
    private ECKey key1;
    private final ImmutableList<Transaction> NO_DEPS = ImmutableList.of();

    @Before
    public void setup() {
        wallet = new Wallet(params) {
            @Override
            public int getLastBlockSeenHeight() {
                return 1000;
            }

            @Override
            public long getLastBlockSeenTimeSecs() {
                return TIMESTAMP;
            }
        };
        key1 = new ECKey();
    }

    @Test
    public void nonFinal() throws Exception {
        // Verify that just having a lock time in the future is not enough to be considered risky (it's still final).
        Transaction tx = new Transaction(params);
        TransactionInput input = tx.addInput(params.getGenesisBlock().getTransactions().get(0).getOutput(0));
        tx.addOutput(Utils.COIN, key1);
        tx.setLockTime(TIMESTAMP + 86400);

        {
            DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
            assertEquals(RiskAnalysis.Result.OK, analysis.analyze());
            assertNull(analysis.getNonFinal());
            // Verify we can't re-use a used up risk analysis.
            try {
                analysis.analyze();
                fail();
            } catch (IllegalStateException e) {}
        }

        // Set a sequence number on the input to make it genuinely non-final. Verify it's risky.
        input.setSequenceNumber(1);
        {
            DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
            assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
            assertEquals(tx, analysis.getNonFinal());
        }

        // If the lock time is the current block, it's about to become final and we consider it non-risky.
        tx.setLockTime(1000);
        {
            DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
            assertEquals(RiskAnalysis.Result.OK, analysis.analyze());
        }
    }

    @Test
    public void selfCreatedAreNotRisky() {
        Transaction tx = new Transaction(params);
        tx.addInput(params.getGenesisBlock().getTransactions().get(0).getOutput(0)).setSequenceNumber(1);
        tx.addOutput(Utils.COIN, key1);
        tx.setLockTime(TIMESTAMP + 86400);

        {
            // Is risky ...
            DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
            assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
        }
        tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        {
            // Is no longer risky.
            DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
            assertEquals(RiskAnalysis.Result.OK, analysis.analyze());
        }
    }

    @Test
    public void nonFinalDependency() {
        // Final tx has a dependency that is non-final.
        Transaction tx1 = new Transaction(params);
        tx1.addInput(params.getGenesisBlock().getTransactions().get(0).getOutput(0)).setSequenceNumber(1);
        TransactionOutput output = tx1.addOutput(Utils.COIN, key1);
        tx1.setLockTime(TIMESTAMP + 86400);
        Transaction tx2 = new Transaction(params);
        tx2.addInput(output);
        tx2.addOutput(Utils.COIN, new ECKey());

        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx2, ImmutableList.of(tx1));
        assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
        assertEquals(tx1, analysis.getNonFinal());
    }

    @Test
    public void simpleStandardTransaction() {
        Transaction tx = new Transaction(params);
        tx.addInput(params.getGenesisBlock().getTransactions().get(0).getOutput(0));
        tx.addOutput(Utils.COIN, new ScriptBuilder().op(ScriptOpCodes.OP_TRUE).build());
        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.NON_STANDARD, analysis.analyze());
    }

    @Test
    public void simpleNonStandardDependency() {
        Transaction tx1 = new Transaction(params);
        tx1.addInput(params.getGenesisBlock().getTransactions().get(0).getOutput(0)).setSequenceNumber(1);
        TransactionOutput output = tx1.addOutput(Utils.COIN, new ScriptBuilder().op(ScriptOpCodes.OP_TRUE).build());
        Transaction tx2 = new Transaction(params);
        tx2.addInput(output);
        tx2.addOutput(Utils.COIN, key1);

        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx2, NO_DEPS);
        assertEquals(RiskAnalysis.Result.OK, analysis.analyze());

        analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx2, ImmutableList.of(tx1));
        assertEquals(RiskAnalysis.Result.NON_STANDARD, analysis.analyze());
        assertEquals(tx1, analysis.getNonStandard());
    }
}
