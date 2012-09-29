/*
 * Copyright 2012 Google Inc.
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

package com.google.bitcoin.core;

import com.google.bitcoin.core.TransactionConfidence.ConfidenceType;
import com.google.bitcoin.store.MemoryBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;

import static org.junit.Assert.*;

public class ChainSplitTest {
    private static final Logger log = LoggerFactory.getLogger(ChainSplitTest.class);

    private NetworkParameters unitTestParams;
    private Wallet wallet;
    private BlockChain chain;
    private Address coinsTo;
    private Address coinsTo2;
    private Address someOtherGuy;

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.init();
        unitTestParams = NetworkParameters.unitTests();
        wallet = new Wallet(unitTestParams);
        wallet.addKey(new ECKey());
        wallet.addKey(new ECKey());
        chain = new BlockChain(unitTestParams, wallet, new MemoryBlockStore(unitTestParams));
        coinsTo = wallet.keychain.get(0).toAddress(unitTestParams);
        coinsTo2 = wallet.keychain.get(1).toAddress(unitTestParams);
        someOtherGuy = new ECKey().toAddress(unitTestParams);
    }

    @Test
    public void testForking1() throws Exception {
        // Check that if the block chain forks, we end up using the right chain. Only tests inbound transactions
        // (receiving coins). Checking that we understand reversed spends is in testForking2.
        final boolean[] reorgHappened = new boolean[1];
        final int[] walletChanged = new int[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onReorganize(Wallet wallet) {
                reorgHappened[0] = true;
            }

            @Override
            public void onWalletChanged(Wallet wallet) {
                walletChanged[0]++;
            }
        });

        // Start by building a couple of blocks on top of the genesis block.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        Block b2 = b1.createNextBlock(coinsTo);
        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));
        assertFalse(reorgHappened[0]);
        assertEquals(2, walletChanged[0]);
        // We got two blocks which generated 50 coins each, to us.
        assertEquals("100.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // We now have the following chain:
        //     genesis -> b1 -> b2
        //
        // so fork like this:
        //
        //     genesis -> b1 -> b2
        //                  \-> b3
        //
        // Nothing should happen at this point. We saw b2 first so it takes priority.
        Block b3 = b1.createNextBlock(someOtherGuy);
        assertTrue(chain.add(b3));
        assertFalse(reorgHappened[0]);  // No re-org took place.
        assertEquals(2, walletChanged[0]);
        assertEquals("100.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // Now we add another block to make the alternative chain longer.
        assertTrue(chain.add(b3.createNextBlock(someOtherGuy)));
        assertTrue(reorgHappened[0]);  // Re-org took place.
        assertEquals(3, walletChanged[0]);
        reorgHappened[0] = false;
        //
        //     genesis -> b1 -> b2
        //                  \-> b3 -> b4
        //
        // We lost some coins! b2 is no longer a part of the best chain so our available balance should drop to 50.
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // ... and back to the first chain.
        Block b5 = b2.createNextBlock(coinsTo);
        Block b6 = b5.createNextBlock(coinsTo);
        assertTrue(chain.add(b5));
        assertTrue(chain.add(b6));
        //
        //     genesis -> b1 -> b2 -> b5 -> b6
        //                  \-> b3 -> b4
        //
        assertTrue(reorgHappened[0]);
        assertEquals(4, walletChanged[0]);
        assertEquals("200.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
    }

    @Test
    public void testForking2() throws Exception {
        // Check that if the chain forks and new coins are received in the alternate chain our balance goes up
        // after the re-org takes place.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(someOtherGuy);
        Block b2 = b1.createNextBlock(someOtherGuy);
        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));
        //     genesis -> b1 -> b2
        //                  \-> b3 -> b4
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        Block b3 = b1.createNextBlock(coinsTo);
        Block b4 = b3.createNextBlock(someOtherGuy);
        assertTrue(chain.add(b3));
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertTrue(chain.add(b4));
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
    }

    @Test
    public void testForking3() throws Exception {
        // Check that we can handle our own spends being rolled back by a fork.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        chain.add(b1);
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        Address dest = new ECKey().toAddress(unitTestParams);
        Transaction spend = wallet.createSend(dest, Utils.toNanoCoins(10, 0));
        wallet.commitTx(spend);
        // Waiting for confirmation ...
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        Block b2 = b1.createNextBlock(someOtherGuy);
        b2.addTransaction(spend);
        b2.solve();
        chain.add(b2);
        assertEquals(Utils.toNanoCoins(40, 0), wallet.getBalance());
        // genesis -> b1 (receive coins) -> b2 (spend coins)
        //                               \-> b3 -> b4
        Block b3 = b1.createNextBlock(someOtherGuy);
        Block b4 = b3.createNextBlock(someOtherGuy);
        chain.add(b3);
        chain.add(b4);
        // b4 causes a re-org that should make our spend go inactive. Because the inputs are already spent our
        // available balance drops to zero again.
        assertEquals(BigInteger.ZERO, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        // We estimate that it'll make it back into the block chain (we know we won't double spend).
        // assertEquals(Utils.toNanoCoins(40, 0), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void testForking4() throws Exception {
        // Check that we can handle external spends on an inactive chain becoming active. An external spend is where
        // we see a transaction that spends our own coins but we did not broadcast it ourselves. This happens when
        // keys are being shared between wallets.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        chain.add(b1);
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        Address dest = new ECKey().toAddress(unitTestParams);
        Transaction spend = wallet.createSend(dest, Utils.toNanoCoins(50, 0));
        // We do NOT confirm the spend here. That means it's not considered to be pending because createSend is
        // stateless. For our purposes it is as if some other program with our keys created the tx.
        //
        // genesis -> b1 (receive 50) --> b2
        //                            \-> b3 (external spend) -> b4
        Block b2 = b1.createNextBlock(someOtherGuy);
        chain.add(b2);
        Block b3 = b1.createNextBlock(someOtherGuy);
        b3.addTransaction(spend);
        b3.solve();
        chain.add(b3);
        // The external spend is not active yet.
        assertEquals(Utils.toNanoCoins(50, 0), wallet.getBalance());
        Block b4 = b3.createNextBlock(someOtherGuy);
        chain.add(b4);
        // The external spend is now active.
        assertEquals(Utils.toNanoCoins(0, 0), wallet.getBalance());
    }

    @Test
    public void testForking5() throws Exception {
        // Test the standard case in which a block containing identical transactions appears on a side chain.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        chain.add(b1);
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // genesis -> b1
        //         -> b2
        Block b2 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        Transaction b2coinbase = b2.transactions.get(0);
        b2.transactions.clear();
        b2.addTransaction(b2coinbase);
        b2.addTransaction(b1.transactions.get(1));
        b2.solve();
        chain.add(b2);
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        assertTrue(wallet.isConsistent());
    }

    @Test
    public void testForking6() throws Exception {
        // Test the case in which a side chain block contains a tx, and then it appears in the main chain too.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(someOtherGuy);
        chain.add(b1);
        // genesis -> b1
        //         -> b2
        Block b2 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        chain.add(b2);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        // genesis -> b1 -> b3
        //         -> b2
        Block b3 = b1.createNextBlock(someOtherGuy);
        b3.addTransaction(b2.transactions.get(1));
        b3.solve();
        chain.add(b3);
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
    }

    @Test
    public void testDoubleSpendOnFork() throws Exception {
        // Check what happens when a re-org happens and one of our confirmed transactions becomes invalidated by a
        // double spend on the new best chain.

        final boolean[] eventCalled = new boolean[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
                super.onTransactionConfidenceChanged(wallet, tx);
                if (tx.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.DEAD)
                    eventCalled[0] = true;
            }
        });

        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        chain.add(b1);

        Transaction t1 = wallet.createSend(someOtherGuy, Utils.toNanoCoins(10, 0));
        Address yetAnotherGuy = new ECKey().toAddress(unitTestParams);
        Transaction t2 = wallet.createSend(yetAnotherGuy, Utils.toNanoCoins(20, 0));
        wallet.commitTx(t1);
        // Receive t1 as confirmed by the network.
        Block b2 = b1.createNextBlock(new ECKey().toAddress(unitTestParams));
        b2.addTransaction(t1);
        b2.solve();
        chain.add(b2);

        // Now we make a double spend become active after a re-org.
        Block b3 = b1.createNextBlock(new ECKey().toAddress(unitTestParams));
        b3.addTransaction(t2);
        b3.solve();
        chain.add(b3);  // Side chain.
        Block b4 = b3.createNextBlock(new ECKey().toAddress(unitTestParams));
        chain.add(b4);  // New best chain.

        // Should have seen a double spend.
        assertTrue(eventCalled[0]);
        assertEquals(Utils.toNanoCoins(30, 0), wallet.getBalance());
    }

    @Test
    public void testDoubleSpendOnForkPending() throws Exception {
        // Check what happens when a re-org happens and one of our UNconfirmed transactions becomes invalidated by a
        // double spend on the new best chain.
        final Transaction[] eventDead = new Transaction[1];
        final Transaction[] eventReplacement = new Transaction[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
                super.onTransactionConfidenceChanged(wallet, tx);
                if (tx.getConfidence().getConfidenceType() ==
                        TransactionConfidence.ConfidenceType.DEAD) {
                    eventDead[0] = tx;
                    eventReplacement[0] = tx.getConfidence().getOverridingTransaction();
                }
            }
        });

        // Start with 50 coins.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        chain.add(b1);

        Transaction t1 = wallet.createSend(someOtherGuy, Utils.toNanoCoins(10, 0));
        Address yetAnotherGuy = new ECKey().toAddress(unitTestParams);
        Transaction t2 = wallet.createSend(yetAnotherGuy, Utils.toNanoCoins(20, 0));
        wallet.commitTx(t1);
        // t1 is still pending ...
        Block b2 = b1.createNextBlock(new ECKey().toAddress(unitTestParams));
        chain.add(b2);
        assertEquals(Utils.toNanoCoins(0, 0), wallet.getBalance());
        assertEquals(Utils.toNanoCoins(40, 0), wallet.getBalance(Wallet.BalanceType.ESTIMATED));

        // Now we make a double spend become active after a re-org.
        // genesis -> b1 -> b2 [t1 pending]
        //              \-> b3 (t2) -> b4
        Block b3 = b1.createNextBlock(new ECKey().toAddress(unitTestParams));
        b3.addTransaction(t2);
        b3.solve();
        chain.add(b3);  // Side chain.
        Block b4 = b3.createNextBlock(new ECKey().toAddress(unitTestParams));
        chain.add(b4);  // New best chain.

        // Should have seen a double spend against the pending pool.
        assertEquals(t1, eventDead[0]);
        assertEquals(t2, eventReplacement[0]);
        assertEquals(Utils.toNanoCoins(30, 0), wallet.getBalance());

        // ... and back to our own parallel universe.
        Block b5 = b2.createNextBlock(new ECKey().toAddress(unitTestParams));
        chain.add(b5);
        Block b6 = b5.createNextBlock(new ECKey().toAddress(unitTestParams));
        chain.add(b6);
        // genesis -> b1 -> b2 -> b5 -> b6 [t1 pending]
        //              \-> b3 [t2 inactive] -> b4
        assertEquals(Utils.toNanoCoins(0, 0), wallet.getBalance());
        assertEquals(Utils.toNanoCoins(40, 0), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void txConfidenceLevels() throws Exception {
        // Check that as the chain forks and re-orgs, the confidence data associated with each transaction is
        // maintained correctly.
        final ArrayList<Transaction> txns = new ArrayList<Transaction>(3);
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                txns.add(tx);
            }
        });

        // Start by building three blocks on top of the genesis block. All send to us.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        BigInteger work1 = b1.getWork();
        Block b2 = b1.createNextBlock(coinsTo2);
        BigInteger work2 = b2.getWork();
        Block b3 = b2.createNextBlock(coinsTo2);
        BigInteger work3 = b3.getWork();

        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));
        assertTrue(chain.add(b3));

        // Check the transaction confidence levels are correct.
        assertEquals(3, txns.size());

        assertEquals(1, txns.get(0).getConfidence().getAppearedAtChainHeight());
        assertEquals(2, txns.get(1).getConfidence().getAppearedAtChainHeight());
        assertEquals(3, txns.get(2).getConfidence().getAppearedAtChainHeight());

        assertEquals(3, txns.get(0).getConfidence().getDepthInBlocks());
        assertEquals(2, txns.get(1).getConfidence().getDepthInBlocks());
        assertEquals(1, txns.get(2).getConfidence().getDepthInBlocks());

        assertEquals(work1.add(work2).add(work3), txns.get(0).getConfidence().getWorkDone());
        assertEquals(work2.add(work3),  txns.get(1).getConfidence().getWorkDone());
        assertEquals(work3,  txns.get(2).getConfidence().getWorkDone());

        // We now have the following chain:
        //     genesis -> b1 -> b2 -> b3
        //
        // so fork like this:
        //
        //     genesis -> b1 -> b2 -> b3
        //                  \-> b4 -> b5
        //
        // Nothing should happen at this point. We saw b2 and b3 first so it takes priority.
        Block b4 = b1.createNextBlock(someOtherGuy);
        BigInteger work4 = b4.getWork();

        Block b5 = b4.createNextBlock(someOtherGuy);
        BigInteger work5 = b5.getWork();

        assertTrue(chain.add(b4));
        assertTrue(chain.add(b5));
        assertEquals(3, txns.size());

        assertEquals(1, txns.get(0).getConfidence().getAppearedAtChainHeight());
        assertEquals(2, txns.get(1).getConfidence().getAppearedAtChainHeight());
        assertEquals(3, txns.get(2).getConfidence().getAppearedAtChainHeight());

        assertEquals(3, txns.get(0).getConfidence().getDepthInBlocks());
        assertEquals(2, txns.get(1).getConfidence().getDepthInBlocks());
        assertEquals(1, txns.get(2).getConfidence().getDepthInBlocks());

        assertEquals(work1.add(work2).add(work3), txns.get(0).getConfidence().getWorkDone());
        assertEquals(work2.add(work3),  txns.get(1).getConfidence().getWorkDone());
        assertEquals(work3,  txns.get(2).getConfidence().getWorkDone());

        // Now we add another block to make the alternative chain longer.
        Block b6 = b5.createNextBlock(someOtherGuy);
        BigInteger work6 = b6.getWork();
        assertTrue(chain.add(b6));
        //
        //     genesis -> b1 -> b2 -> b3
        //                  \-> b4 -> b5 -> b6
        //

        assertEquals(3, txns.size());
        assertEquals(1, txns.get(0).getConfidence().getAppearedAtChainHeight());
        assertEquals(4, txns.get(0).getConfidence().getDepthInBlocks());
        assertEquals(work1.add(work4).add(work5).add(work6), txns.get(0).getConfidence().getWorkDone());

        // Transaction 1 (in block b2) is now on a side chain.
        assertEquals(TransactionConfidence.ConfidenceType.NOT_IN_BEST_CHAIN, txns.get(1).getConfidence().getConfidenceType());
        try {
            txns.get(1).getConfidence().getAppearedAtChainHeight();
            fail();
        } catch (IllegalStateException e) {}
        try {
            txns.get(1).getConfidence().getDepthInBlocks();
            fail();
        } catch (IllegalStateException e) {}
        try {
            txns.get(1).getConfidence().getWorkDone();
            fail();
        } catch (IllegalStateException e) {}

        // ... and back to the first chain.
        Block b7 = b3.createNextBlock(coinsTo);
        BigInteger work7 = b7.getWork();
        Block b8 = b7.createNextBlock(coinsTo);
        BigInteger work8 = b7.getWork();

        assertTrue(chain.add(b7));
        assertTrue(chain.add(b8));
        //
        //     genesis -> b1 -> b2 -> b3 -> b7 -> b8
        //                  \-> b4 -> b5 -> b6
        //

        // This should be enabled, once we figure out the best way to inform the user of how the wallet is changing
        // during the re-org.
        //assertEquals(5, txns.size());

        assertEquals(1, txns.get(0).getConfidence().getAppearedAtChainHeight());
        assertEquals(2, txns.get(1).getConfidence().getAppearedAtChainHeight());
        assertEquals(3, txns.get(2).getConfidence().getAppearedAtChainHeight());

        assertEquals(5, txns.get(0).getConfidence().getDepthInBlocks());
        assertEquals(4, txns.get(1).getConfidence().getDepthInBlocks());
        assertEquals(3, txns.get(2).getConfidence().getDepthInBlocks());

        BigInteger newWork1 = work1.add(work2).add(work3).add(work7).add(work8);
        assertEquals(newWork1, txns.get(0).getConfidence().getWorkDone());
        BigInteger newWork2 = work2.add(work3).add(work7).add(work8);
        assertEquals(newWork2, txns.get(1).getConfidence().getWorkDone());
        BigInteger newWork3 = work3.add(work7).add(work8);
        assertEquals(newWork3, txns.get(2).getConfidence().getWorkDone());

        assertEquals("250.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));

        // Now add two more blocks that don't send coins to us. Despite being irrelevant the wallet should still update.
        Block b9 = b8.createNextBlock(someOtherGuy);
        Block b10 = b9.createNextBlock(someOtherGuy);
        chain.add(b9);
        chain.add(b10);
        BigInteger extraWork = b9.getWork().add(b10.getWork());
        assertEquals(7, txns.get(0).getConfidence().getDepthInBlocks());
        assertEquals(6, txns.get(1).getConfidence().getDepthInBlocks());
        assertEquals(5, txns.get(2).getConfidence().getDepthInBlocks());
        assertEquals(newWork1.add(extraWork), txns.get(0).getConfidence().getWorkDone());
        assertEquals(newWork2.add(extraWork), txns.get(1).getConfidence().getWorkDone());
        assertEquals(newWork3.add(extraWork), txns.get(2).getConfidence().getWorkDone());
    }

    @Test
    public void coinbaseDeath() throws Exception {
        // Check that a coinbase tx is marked as dead after a reorg rather than inactive as normal non-double-spent transactions would be.
        // Also check that a dead coinbase on a sidechain is resurrected if the sidechain becomes the best chain once more.
        final ArrayList<Transaction> txns = new ArrayList<Transaction>(3);
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                txns.add(tx);
            }
        });

        // Start by building three blocks on top of the genesis block.
        // The first block contains a normal transaction that spends to coinTo.
        // The second block contains a coinbase transaction that spends to coinTo2.
        // The third block contains a normal transaction that spends to coinTo.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinsTo);
        Block b2 = b1.createNextBlockWithCoinbase(wallet.keychain.get(1).getPubKey());
        Block b3 = b2.createNextBlock(coinsTo);

        log.debug("Adding block b1");
        assertTrue(chain.add(b1));
        log.debug("Adding block b2");
        assertTrue(chain.add(b2));
        log.debug("Adding block b3");
        assertTrue(chain.add(b3));

        // We now have the following chain:
        //     genesis -> b1 -> b2 -> b3
        //

        // Check we have seen the three transactions.
        assertEquals(3, txns.size());

        // Check the coinbase transaction is building and in the unspent pool only.
        assertEquals(ConfidenceType.BUILDING, txns.get(1).getConfidence().getConfidenceType());
        assertTrue(!wallet.pending.containsKey(txns.get(1).getHash()));
        assertTrue(wallet.unspent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.spent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.inactive.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.dead.containsKey(txns.get(1).getHash()));

        // Fork like this:
        //
        //     genesis -> b1 -> b2 -> b3
        //                  \-> b4 -> b5 -> b6
        //
        // The b4/ b5/ b6 is now the best chain
        Block b4 = b1.createNextBlock(someOtherGuy);
        Block b5 = b4.createNextBlock(someOtherGuy);
        Block b6 = b5.createNextBlock(someOtherGuy);

        log.debug("Adding block b4");
        assertTrue(chain.add(b4));
        log.debug("Adding block b5");
        assertTrue(chain.add(b5));
        log.debug("Adding block b6");
        assertTrue(chain.add(b6));

        // Transaction 1 (in block b2) is now on a side chain and should have confidence type of dead and be in the dead pool only
        assertEquals(TransactionConfidence.ConfidenceType.DEAD, txns.get(1).getConfidence().getConfidenceType());
        assertTrue(!wallet.pending.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.unspent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.spent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.inactive.containsKey(txns.get(1).getHash()));
        assertTrue(wallet.dead.containsKey(txns.get(1).getHash()));

        // ... and back to the first chain.
        Block b7 = b3.createNextBlock(coinsTo);
        Block b8 = b7.createNextBlock(coinsTo);

        log.debug("Adding block b7");
        assertTrue(chain.add(b7));
        log.debug("Adding block b8");
        assertTrue(chain.add(b8));

        //
        //     genesis -> b1 -> b2 -> b3 -> b7 -> b8
        //                  \-> b4 -> b5 -> b6
        //

        // The coinbase transaction should now have confidence type of building once more and in the unspent pool only.
        assertEquals(TransactionConfidence.ConfidenceType.BUILDING, txns.get(1).getConfidence().getConfidenceType());
        assertTrue(!wallet.pending.containsKey(txns.get(1).getHash()));
        assertTrue(wallet.unspent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.spent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.inactive.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.dead.containsKey(txns.get(1).getHash()));

        // ... make the side chain dominant again.
        Block b9 = b6.createNextBlock(coinsTo);
        Block b10 = b9.createNextBlock(coinsTo);

        log.debug("Adding block b9");
        assertTrue(chain.add(b9));
        log.debug("Adding block b10");
        assertTrue(chain.add(b10));
        //
        //     genesis -> b1 -> b2 -> b3 -> b7 -> b8
        //                  \-> b4 -> b5 -> b6 -> b9 -> b10
        //

        // The coinbase transaction should now have the confidence type of dead and be in the dead pool only.
        assertEquals(TransactionConfidence.ConfidenceType.DEAD, txns.get(1).getConfidence().getConfidenceType());
        assertTrue(!wallet.pending.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.unspent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.spent.containsKey(txns.get(1).getHash()));
        assertTrue(!wallet.inactive.containsKey(txns.get(1).getHash()));
        assertTrue(wallet.dead.containsKey(txns.get(1).getHash()));
    }
}
