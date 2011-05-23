/**
 * Copyright 2011 Google Inc.
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

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static com.google.bitcoin.core.Utils.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WalletTest {
    static final NetworkParameters params = NetworkParameters.unitTests();

    private Address myAddress;
    private Wallet wallet;
    private BlockStore blockStore;

    @Before
    public void setUp() throws Exception {
        ECKey myKey = new ECKey();
        myAddress = myKey.toAddress(params);
        wallet = new Wallet(params);
        wallet.addKey(myKey);
        blockStore = new MemoryBlockStore(params);
    }

    private Transaction createFakeTx(BigInteger nanocoins,  Address to) {
        Transaction t = new Transaction(params);
        TransactionOutput o1 = new TransactionOutput(params, t, nanocoins, to);
        t.addOutput(o1);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, nanocoins, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut);
        return t;
    }

    class BlockPair {
        StoredBlock storedBlock;
        Block block;
    }

    // Emulates receiving a valid block that builds on top of the chain.
    private BlockPair createFakeBlock(Transaction... transactions) {
        try {
            Block b = blockStore.getChainHead().getHeader().createNextBlock(new ECKey().toAddress(params));
            for (Transaction tx : transactions)
                b.addTransaction(tx);
            b.solve();
            BlockPair pair = new BlockPair();
            pair.block = b;
            pair.storedBlock = blockStore.getChainHead().build(b);
            blockStore.put(pair.storedBlock);
            blockStore.setChainHead(pair.storedBlock);
            return pair;
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Test
    public void testBasicSpending() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(v1, myAddress);

        wallet.receive(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());

        ECKey k2 = new ECKey();
        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t2 = wallet.createSend(k2.toAddress(params), v2);

        // Do some basic sanity checks.
        assertEquals(1, t2.inputs.size());
        assertEquals(myAddress, t2.inputs.get(0).getScriptSig().getFromAddress());

        // We have NOT proven that the signature is correct!
    }

    @Test
    public void testSideChain() throws Exception {
        // The wallet receives a coin on the main chain, then on a side chain. Only main chain counts towards balance.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(v1, myAddress);

        wallet.receive(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());

        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t2 = createFakeTx(v2, myAddress);
        wallet.receive(t2, null, BlockChain.NewBlockType.SIDE_CHAIN);

        assertEquals(v1, wallet.getBalance());
    }

    @Test
    public void testListener() throws Exception {
        final Transaction fakeTx = createFakeTx(Utils.toNanoCoins(1, 0), myAddress);
        final boolean[] didRun = new boolean[1];
        WalletEventListener listener = new WalletEventListener() {
            public void onCoinsReceived(Wallet w, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                assertTrue(prevBalance.equals(BigInteger.ZERO));
                assertTrue(newBalance.equals(Utils.toNanoCoins(1, 0)));
                assertEquals(tx, fakeTx);  // Same object.
                assertEquals(w, wallet);   // Same object.
                didRun[0] = true;
            }
        };
        wallet.addEventListener(listener);
        wallet.receive(fakeTx, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertTrue(didRun[0]);
    }

    @Test
    public void testBalance() throws Exception {
        // Receive 5 coins then half a coin.
        BigInteger v1 = toNanoCoins(5, 0);
        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t1 = createFakeTx(v1, myAddress);
        Transaction t2 = createFakeTx(v2, myAddress);
        StoredBlock b1 = createFakeBlock(t1).storedBlock;
        StoredBlock b2 = createFakeBlock(t2).storedBlock;
        BigInteger expected = toNanoCoins(5, 50);
        wallet.receive(t1, b1, BlockChain.NewBlockType.BEST_CHAIN);
        wallet.receive(t2, b2, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(expected, wallet.getBalance());

        // Now spend one coin.
        BigInteger v3 = toNanoCoins(1, 0);
        Transaction spend = wallet.createSend(new ECKey().toAddress(params), v3);
        wallet.confirmSend(spend);

        // Available and estimated balances should not be the same. We don't check the exact available balance here
        // because it depends on the coin selection algorithm.
        assertEquals(toNanoCoins(4, 50), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertFalse(wallet.getBalance(Wallet.BalanceType.AVAILABLE).equals(
                    wallet.getBalance(Wallet.BalanceType.ESTIMATED)));

        // Now confirm the transaction by including it into a block.
        StoredBlock b3 = createFakeBlock(spend).storedBlock;
        wallet.receive(spend, b3, BlockChain.NewBlockType.BEST_CHAIN);

        // Change is confirmed. We started with 5.50 so we should have 4.50 left.
        BigInteger v4 = toNanoCoins(4, 50);
        assertEquals(v4, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
    }

    // Intuitively you'd expect to be able to create a transaction with identical inputs and outputs and get an
    // identical result to the official client. However the signatures are not deterministic - signing the same data
    // with the same key twice gives two different outputs. So we cannot prove bit-for-bit compatibility in this test
    // suite.

    @Test
    public void testBlockChainCatchup() throws Exception {
        Transaction tx1 = createFakeTx(Utils.toNanoCoins(1, 0), myAddress);
        StoredBlock b1 = createFakeBlock(tx1).storedBlock;
        wallet.receive(tx1, b1, BlockChain.NewBlockType.BEST_CHAIN);
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10), myAddress);
        // Pretend it makes it into the block chain, our wallet state is cleared but we still have the keys, and we
        // want to get back to our previous state. We can do this by just not confirming the transaction as
        // createSend is stateless.
        StoredBlock b2 = createFakeBlock(send1).storedBlock;
        wallet.receive(send1, b2, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(bitcoinValueToFriendlyString(wallet.getBalance()), "0.90");
        // And we do it again after the catchup.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10), myAddress);
        // What we'd really like to do is prove the official client would accept it .... no such luck unfortunately.
        wallet.confirmSend(send2);
        StoredBlock b3 = createFakeBlock(send2).storedBlock;
        wallet.receive(send2, b3, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(bitcoinValueToFriendlyString(wallet.getBalance()), "0.80");
    }

    @Test
    public void testBalances() throws Exception {
        BigInteger nanos = Utils.toNanoCoins(1, 0);
        Transaction tx1 = createFakeTx(nanos, myAddress);
        wallet.receive(tx1, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(nanos, tx1.getValueSentToMe(wallet, true));
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10), myAddress);
        // Reserialize.
        Transaction send2 = new Transaction(params, send1.bitcoinSerialize());
        assertEquals(nanos, send2.getValueSentFromMe(wallet));
    }

    @Test
    public void testFinneyAttack() throws Exception {
        // A Finney attack is where a miner includes a transaction spending coins to themselves but does not
        // broadcast it. When they find a solved block, they hold it back temporarily whilst they buy something with
        // those same coins. After purchasing, they broadcast the block thus reversing the transaction. It can be
        // done by any miner for products that can be bought at a chosen time and very quickly (as every second you
        // withold your block means somebody else might find it first, invalidating your work).
        //
        // Test that we handle ourselves performing the attack correctly: a double spend on the chain moves
        // transactions from pending to dead.
        //
        // Note that the other way around, where a pending transaction sending us coins becomes dead,
        // isn't tested because today BitCoinJ only learns about such transactions when they appear in the chain.
        final Transaction[] eventDead = new Transaction[1];
        final Transaction[] eventReplacement = new Transaction[1];
        wallet.addEventListener(new WalletEventListener() {
            @Override
            public void onDeadTransaction(Transaction deadTx, Transaction replacementTx) {
                eventDead[0] = deadTx;
                eventReplacement[0] = replacementTx;
            }
        });

        // Receive 1 BTC.
        BigInteger nanos = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(nanos, myAddress);
        wallet.receive(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        // Create a send to a merchant.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 50));
        // Create a double spend.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 50));
        // Broadcast send1.
        wallet.confirmSend(send1);
        // Receive a block that overrides it.
        wallet.receive(send2, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(send1, eventDead[0]);
        assertEquals(send2, eventReplacement[0]);
    }
}
