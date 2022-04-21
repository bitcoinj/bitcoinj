/*
 * Copyright by the original author or authors.
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

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.utils.BriefLogFormatter;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Comparator;

import static org.bitcoinj.core.Coin.COIN;
import static org.junit.Assert.assertEquals;

/**
 * Test/demonstrate lambda-based coin selection
 */
public class CoinSelectorTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final Address myAddress = SegwitAddress.fromKey(UNITTEST, new ECKey());


    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.init();
        Context.propagate(new Context(UNITTEST, 100, Coin.ZERO, false));
    }

    @Test
    public void simpleTest() {
        // Add four outputs to a transaction with same value and destination. Select them all.
        Transaction t = new Transaction(UNITTEST);
        java.util.List<TransactionOutput> outputs = Arrays.asList(
                new TransactionOutput(UNITTEST, t, Coin.valueOf(1), myAddress),
                new TransactionOutput(UNITTEST, t, Coin.valueOf(2), myAddress),
                new TransactionOutput(UNITTEST, t, Coin.valueOf(3), myAddress),
                new TransactionOutput(UNITTEST, t, Coin.valueOf(4), myAddress)
        );
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.BUILDING);

        CoinSelector selector = (target, candidates) -> CoinSelector.select(target, candidates,
                out -> (out.getValue().value > 2)   // Select all coins with value > 2 satoshis
        );
        CoinSelection selection = selector.select(COIN.multiply(2), outputs);

        assertEquals(2, selection.gathered.size());
        assertEquals(7, selection.valueGathered.value);
    }


    @Test
    public void simpleTestWithSort() {
        // Add four outputs to a transaction with same value and destination. Select them all.
        Transaction t = new Transaction(UNITTEST);
        // Reverse order
        java.util.List<TransactionOutput> outputs = Arrays.asList(
                new TransactionOutput(UNITTEST, t, Coin.valueOf(4), myAddress),
                new TransactionOutput(UNITTEST, t, Coin.valueOf(3), myAddress),
                new TransactionOutput(UNITTEST, t, Coin.valueOf(2), myAddress),
                new TransactionOutput(UNITTEST, t, Coin.valueOf(1), myAddress)
        );
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.BUILDING);

        CoinSelector selector = (target, candidates) -> CoinSelector.sortSelect(target, candidates,
                Comparator.comparing(TransactionOutput::getValue),  // Sort in ascending order
                out -> (out.getValue().value > 2)                   // Select all coins with value > 2 satoshis
        );
        CoinSelection selection = selector.select(COIN.multiply(2), outputs);

        assertEquals(2, selection.gathered.size());
        // Should have been sorted into ascending order.
        assertEquals( Coin.valueOf(3), selection.gathered.get(0).getValue());
        assertEquals( Coin.valueOf(4), selection.gathered.get(1).getValue());
        assertEquals(7, selection.valueGathered.value);
    }
}
