/**
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
import com.google.bitcoin.params.RegTestParams;
import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.utils.TestUtils;
import com.google.bitcoin.utils.TestWithWallet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class DefaultCoinSelectorTest extends TestWithWallet {
    private static final NetworkParameters params = UnitTestParams.get();

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
        t = new Transaction(params);
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.PENDING);
        assertFalse(DefaultCoinSelector.isSelectable(t));
        t.getConfidence().setSource(TransactionConfidence.Source.SELF);
        assertFalse(DefaultCoinSelector.isSelectable(t));
        t.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByName("1.2.3.4")));
        assertFalse(DefaultCoinSelector.isSelectable(t));
        t.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByName("5.6.7.8")));
        assertTrue(DefaultCoinSelector.isSelectable(t));
        t = new Transaction(params);
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.BUILDING);
        assertTrue(DefaultCoinSelector.isSelectable(t));
        t = new Transaction(RegTestParams.get());
        t.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.PENDING);
        t.getConfidence().setSource(TransactionConfidence.Source.SELF);
        assertTrue(DefaultCoinSelector.isSelectable(t));
    }

    @Test
    public void depthOrdering() throws Exception {
        // Send two transactions in two blocks on top of each other.
        Transaction t1 = checkNotNull(sendMoneyToWallet(Utils.COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN));
        Transaction t2 = checkNotNull(sendMoneyToWallet(Utils.COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN));

        // Check we selected just the oldest one.
        DefaultCoinSelector selector = new DefaultCoinSelector();
        CoinSelection selection = selector.select(Utils.COIN, wallet.calculateAllSpendCandidates(true));
        assertTrue(selection.gathered.contains(t1.getOutputs().get(0)));
        assertEquals(Utils.COIN, selection.valueGathered);

        // Check we ordered them correctly (by depth).
        ArrayList<TransactionOutput> candidates = new ArrayList<TransactionOutput>();
        candidates.add(t2.getOutput(0));
        candidates.add(t1.getOutput(0));
        DefaultCoinSelector.sortOutputs(candidates);
        assertEquals(t1.getOutput(0), candidates.get(0));
        assertEquals(t2.getOutput(0), candidates.get(1));
    }

    @Test
    public void coinAgeOrdering() throws Exception {
        // Send three transactions in four blocks on top of each other. Coin age of t1 is 1*4=4, coin age of t2 = 2*2=4
        // and t3=0.01.
        Transaction t1 = checkNotNull(sendMoneyToWallet(Utils.COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN));
        // Padding block.
        wallet.notifyNewBestBlock(TestUtils.createFakeBlock(blockStore).storedBlock);
        final BigInteger TWO_COINS = Utils.COIN.multiply(BigInteger.valueOf(2));
        Transaction t2 = checkNotNull(sendMoneyToWallet(TWO_COINS, AbstractBlockChain.NewBlockType.BEST_CHAIN));
        Transaction t3 = checkNotNull(sendMoneyToWallet(Utils.CENT, AbstractBlockChain.NewBlockType.BEST_CHAIN));

        // Should be ordered t2, t1, t3.
        ArrayList<TransactionOutput> candidates = new ArrayList<TransactionOutput>();
        candidates.add(t3.getOutput(0));
        candidates.add(t2.getOutput(0));
        candidates.add(t1.getOutput(0));
        DefaultCoinSelector.sortOutputs(candidates);
        assertEquals(t2.getOutput(0), candidates.get(0));
        assertEquals(t1.getOutput(0), candidates.get(1));
        assertEquals(t3.getOutput(0), candidates.get(2));
    }
}
