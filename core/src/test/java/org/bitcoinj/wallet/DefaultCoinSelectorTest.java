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

import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.testing.TestWithWallet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.bitcoinj.base.Coin.CENT;
import static org.bitcoinj.base.Coin.COIN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DefaultCoinSelectorTest extends TestWithWallet {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters REGTEST = RegTestParams.get();

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        Utils.setMockClock(); // Use mock clock
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void selectable() throws Exception {
        Transaction t;
        t = new Transaction(UNITTEST);
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.PENDING);
        assertFalse(DefaultCoinSelector.isSelectable(t));
        t.getConfidence().setSource(TransactionConfidence.Source.SELF);
        assertFalse(DefaultCoinSelector.isSelectable(t));
        t.getConfidence().markBroadcastBy(new PeerAddress(UNITTEST, InetAddress.getByName("1.2.3.4")));
        assertTrue(DefaultCoinSelector.isSelectable(t));
        t.getConfidence().markBroadcastBy(new PeerAddress(UNITTEST, InetAddress.getByName("5.6.7.8")));
        assertTrue(DefaultCoinSelector.isSelectable(t));
        t = new Transaction(UNITTEST);
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.BUILDING);
        assertTrue(DefaultCoinSelector.isSelectable(t));
        t = new Transaction(REGTEST);
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.PENDING);
        t.getConfidence().setSource(TransactionConfidence.Source.SELF);
        assertTrue(DefaultCoinSelector.isSelectable(t));
    }

    @Test
    public void depthOrdering() {
        // Send two transactions in two blocks on top of each other.
        Transaction t1 = checkNotNull(sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN));
        Transaction t2 = checkNotNull(sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN));

        // Check we selected just the oldest one.
        DefaultCoinSelector selector = DefaultCoinSelector.get();
        CoinSelection selection = selector.select(COIN, wallet.calculateAllSpendCandidates());
        assertTrue(selection.gathered.contains(t1.getOutputs().get(0)));
        assertEquals(COIN, selection.valueGathered);

        // Check we ordered them correctly (by depth).
        ArrayList<TransactionOutput> candidates = new ArrayList<>();
        candidates.add(t2.getOutput(0));
        candidates.add(t1.getOutput(0));
        DefaultCoinSelector.sortOutputs(candidates);
        assertEquals(t1.getOutput(0), candidates.get(0));
        assertEquals(t2.getOutput(0), candidates.get(1));
    }

    @Test
    public void coinAgeOrdering() {
        // Send three transactions in four blocks on top of each other. Coin age of t1 is 1*4=4, coin age of t2 = 2*2=4
        // and t3=0.01.
        Transaction t1 = checkNotNull(sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN));
        // Padding block.
        wallet.notifyNewBestBlock(FakeTxBuilder.createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).storedBlock);
        final Coin TWO_COINS = COIN.multiply(2);
        Transaction t2 = checkNotNull(sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, TWO_COINS));
        Transaction t3 = checkNotNull(sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT));

        // Should be ordered t2, t1, t3.
        ArrayList<TransactionOutput> candidates = new ArrayList<>();
        candidates.add(t3.getOutput(0));
        candidates.add(t2.getOutput(0));
        candidates.add(t1.getOutput(0));
        DefaultCoinSelector.sortOutputs(candidates);
        assertEquals(t2.getOutput(0), candidates.get(0));
        assertEquals(t1.getOutput(0), candidates.get(1));
        assertEquals(t3.getOutput(0), candidates.get(2));
    }

    @Test
    public void identicalInputs() {
        // Add four outputs to a transaction with same value and destination. Select them all.
        Transaction t = new Transaction(UNITTEST);
        List<TransactionOutput> outputs = Arrays.asList(
            new TransactionOutput(UNITTEST, t, Coin.valueOf(30302787), myAddress),
            new TransactionOutput(UNITTEST, t, Coin.valueOf(30302787), myAddress),
            new TransactionOutput(UNITTEST, t, Coin.valueOf(30302787), myAddress),
            new TransactionOutput(UNITTEST, t, Coin.valueOf(30302787), myAddress)
        );
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.BUILDING);

        DefaultCoinSelector selector = DefaultCoinSelector.get();
        CoinSelection selection = selector.select(COIN.multiply(2), outputs);

        assertTrue(selection.gathered.size() == 4);
    }
}
