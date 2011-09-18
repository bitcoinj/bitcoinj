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

import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.MemoryBlockStore;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.List;

import static com.google.bitcoin.core.TestUtils.createFakeBlock;
import static com.google.bitcoin.core.TestUtils.createFakeTx;
import static com.google.bitcoin.core.Utils.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WalletTest {
    static final NetworkParameters params = NetworkParameters.unitTests();

    private Address myAddress;
    private Wallet wallet;
    private BlockStore blockStore;
    private ECKey myKey;

    @Before
    public void setUp() throws Exception {
        myKey = new ECKey();
        myAddress = myKey.toAddress(params);
        wallet = new Wallet(params);
        wallet.addKey(myKey);
        blockStore = new MemoryBlockStore(params);
    }

    @Test
    public void basicSpending() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(params, v1, myAddress);

        wallet.receive(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.ALL));

        ECKey k2 = new ECKey();
        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t2 = wallet.createSend(k2.toAddress(params), v2);
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.ALL));

        // Do some basic sanity checks.
        assertEquals(1, t2.inputs.size());
        assertEquals(myAddress, t2.inputs.get(0).getScriptSig().getFromAddress());

        // We have NOT proven that the signature is correct!

        wallet.confirmSend(t2);
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.PENDING));
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.SPENT));
        assertEquals(2, wallet.getPoolSize(Wallet.Pool.ALL));
    }

    @Test
    public void sideChain() throws Exception {
        // The wallet receives a coin on the main chain, then on a side chain. Only main chain counts towards balance.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(params, v1, myAddress);

        wallet.receive(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.ALL));

        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t2 = createFakeTx(params, v2, myAddress);
        wallet.receive(t2, null, BlockChain.NewBlockType.SIDE_CHAIN);
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.INACTIVE));
        assertEquals(2, wallet.getPoolSize(Wallet.Pool.ALL));

        assertEquals(v1, wallet.getBalance());
    }

    @Test
    public void listeners() throws Exception {
        final Transaction fakeTx = createFakeTx(params, Utils.toNanoCoins(1, 0), myAddress);
        final boolean[] didRun = new boolean[1];
        WalletEventListener listener = new AbstractWalletEventListener() {
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
    public void balance() throws Exception {
        // Receive 5 coins then half a coin.
        BigInteger v1 = toNanoCoins(5, 0);
        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t1 = createFakeTx(params, v1, myAddress);
        Transaction t2 = createFakeTx(params, v2, myAddress);
        StoredBlock b1 = createFakeBlock(params, blockStore, t1).storedBlock;
        StoredBlock b2 = createFakeBlock(params, blockStore, t2).storedBlock;
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
        StoredBlock b3 = createFakeBlock(params, blockStore, spend).storedBlock;
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
    public void blockChainCatchup() throws Exception {
        Transaction tx1 = createFakeTx(params, Utils.toNanoCoins(1, 0), myAddress);
        StoredBlock b1 = createFakeBlock(params, blockStore, tx1).storedBlock;
        wallet.receive(tx1, b1, BlockChain.NewBlockType.BEST_CHAIN);
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10), myAddress);
        // Pretend it makes it into the block chain, our wallet state is cleared but we still have the keys, and we
        // want to get back to our previous state. We can do this by just not confirming the transaction as
        // createSend is stateless.
        StoredBlock b2 = createFakeBlock(params, blockStore, send1).storedBlock;
        wallet.receive(send1, b2, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(bitcoinValueToFriendlyString(wallet.getBalance()), "0.90");
        // And we do it again after the catchup.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10), myAddress);
        // What we'd really like to do is prove the official client would accept it .... no such luck unfortunately.
        wallet.confirmSend(send2);
        StoredBlock b3 = createFakeBlock(params, blockStore, send2).storedBlock;
        wallet.receive(send2, b3, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(bitcoinValueToFriendlyString(wallet.getBalance()), "0.80");
    }

    @Test
    public void balances() throws Exception {
        BigInteger nanos = Utils.toNanoCoins(1, 0);
        Transaction tx1 = createFakeTx(params, nanos, myAddress);
        wallet.receive(tx1, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(nanos, tx1.getValueSentToMe(wallet, true));
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10), myAddress);
        // Reserialize.
        Transaction send2 = new Transaction(params, send1.bitcoinSerialize());
        assertEquals(nanos, send2.getValueSentFromMe(wallet));
    }

    @Test
    public void transactions() throws Exception {
        // This test covers a bug in which Transaction.getValueSentFromMe was calculating incorrectly.
        Transaction tx = createFakeTx(params, Utils.toNanoCoins(1, 0), myAddress);
        // Now add another output (ie, change) that goes to some other address.
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, Utils.toNanoCoins(0, 5), someOtherGuy);
        tx.addOutput(output);
        // Note that tx is no longer valid: it spends more than it imports. However checking transactions balance
        // correctly isn't possible in SPV mode because value is a property of outputs not inputs. Without all
        // transactions you can't check they add up.
        wallet.receive(tx, null, BlockChain.NewBlockType.BEST_CHAIN);
        // Now the other guy creates a transaction which spends that change.
        Transaction tx2 = new Transaction(params);
        tx2.addInput(output);
        tx2.addOutput(new TransactionOutput(params, tx2, Utils.toNanoCoins(0, 5), myAddress));
        // tx2 doesn't send any coins from us, even though the output is in the wallet.
        assertEquals(Utils.toNanoCoins(0, 0), tx2.getValueSentFromMe(wallet));
    }

    @Test
    public void bounce() throws Exception {
        // This test covers bug 64 (False double spends). Check that if we create a spend and it's immediately sent
        // back to us, this isn't considered as a double spend.
        BigInteger coin1 = Utils.toNanoCoins(1, 0);
        BigInteger coinHalf = Utils.toNanoCoins(0, 50);
        // Start by giving us 1 coin.
        Transaction inbound1 = createFakeTx(params, coin1, myAddress);
        wallet.receive(inbound1, null, BlockChain.NewBlockType.BEST_CHAIN);
        // Send half to some other guy. Sending only half then waiting for a confirm is important to ensure the tx is
        // in the unspent pool, not pending or spent.
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(Wallet.Pool.ALL));
        Address someOtherGuy = new ECKey().toAddress(params);
        Transaction outbound1 = wallet.createSend(someOtherGuy, coinHalf);
        wallet.confirmSend(outbound1);
        wallet.receive(outbound1, null, BlockChain.NewBlockType.BEST_CHAIN);
        // That other guy gives us the coins right back.
        Transaction inbound2 = new Transaction(params);
        inbound2.addOutput(new TransactionOutput(params, inbound2, coinHalf, myAddress));
        inbound2.addInput(outbound1.outputs.get(0));
        wallet.receive(inbound2, null, BlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(coin1, wallet.getBalance());
    }

    @Test
    public void finneyAttack() throws Exception {
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
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onDeadTransaction(Transaction deadTx, Transaction replacementTx) {
                eventDead[0] = deadTx;
                eventReplacement[0] = replacementTx;
            }
        });

        // Receive 1 BTC.
        BigInteger nanos = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(params, nanos, myAddress);
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

    @Test
    public void transactionsList() throws Exception {
        // Check the wallet can give us an ordered list of all received transactions.
        long time = System.currentTimeMillis() / 1000;
        // Receive a coin.
        Transaction tx1 = createFakeTx(params, Utils.toNanoCoins(1, 0), myAddress);
        StoredBlock b1 = createFakeBlock(params, blockStore, time, tx1).storedBlock;
        wallet.receive(tx1, b1, BlockChain.NewBlockType.BEST_CHAIN);
        // Receive half a coin 10 minutes later.
        time += 60 * 10;
        Transaction tx2 = createFakeTx(params, Utils.toNanoCoins(0, 5), myAddress);
        StoredBlock b2 = createFakeBlock(params, blockStore, time, tx1).storedBlock;
        wallet.receive(tx2, b2, BlockChain.NewBlockType.BEST_CHAIN);
        // Check we got them back in order.
        List<Transaction> transactions = wallet.getTransactionsByTime();
        assertEquals(tx2,  transactions.get(0));
        assertEquals(tx1,  transactions.get(1));
        assertEquals(2, transactions.size());
        // Check we get only the last transaction if we request a subrage.
        transactions = wallet.getRecentTransactions(1);
        assertEquals(1, transactions.size());
        assertEquals(tx2,  transactions.get(0));

        // Create a spend.
        Transaction tx3 = wallet.createSend(new ECKey().toAddress(params), Utils.toNanoCoins(0, 5));
        // Does not appear in list yet.
        assertEquals(2, wallet.getTransactionsByTime().size());
        wallet.confirmSend(tx3);
        // Now it does.
        transactions = wallet.getTransactionsByTime();
        assertEquals(3, transactions.size());
        assertEquals(tx3, transactions.get(0));

        // Verify we can handle the case of older wallets in which the timestamp is null (guessed from the
        // block appearances list).
        tx1.updatedAt = null;
        tx2.updatedAt = null;
        // Check we got them back in order.
        transactions = wallet.getTransactionsByTime();
        assertEquals(tx3,  transactions.get(0));
        assertEquals(tx2,  transactions.get(1));
        assertEquals(tx1,  transactions.get(2));
        assertEquals(3, transactions.size());
    }
}
