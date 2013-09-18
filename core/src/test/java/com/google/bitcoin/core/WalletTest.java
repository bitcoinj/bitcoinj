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

import com.google.bitcoin.core.Transaction.SigHash;
import com.google.bitcoin.core.Wallet.SendRequest;
import com.google.bitcoin.core.WalletTransaction.Pool;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterException;
import com.google.bitcoin.crypto.KeyCrypterScrypt;
import com.google.bitcoin.store.WalletProtobufSerializer;
import com.google.bitcoin.utils.TestUtils;
import com.google.bitcoin.utils.TestWithWallet;
import com.google.bitcoin.utils.Threading;
import com.google.bitcoin.wallet.KeyTimeCoinSelector;
import com.google.bitcoin.wallet.WalletFiles;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.bitcoinj.wallet.Protos;
import org.bitcoinj.wallet.Protos.ScryptParameters;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.File;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.bitcoin.utils.TestUtils.*;
import static com.google.bitcoin.core.Utils.*;
import static org.junit.Assert.*;

public class WalletTest extends TestWithWallet {
    private static final Logger log = LoggerFactory.getLogger(WalletTest.class);

    private Address myEncryptedAddress;
    private Address myEncryptedAddress2;

    private Wallet encryptedWallet;
    // A wallet with an initial unencrypted private key and an encrypted private key.
    private Wallet encryptedMixedWallet;

    private static CharSequence PASSWORD1 = "my helicopter contains eels";
    private static CharSequence WRONG_PASSWORD = "nothing noone nobody nowhere";

    private KeyParameter aesKey;
    private KeyParameter wrongAesKey;
    private KeyCrypter keyCrypter;
    private SecureRandom secureRandom = new SecureRandom();

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        byte[] salt = new byte[KeyCrypterScrypt.SALT_LENGTH];
        secureRandom.nextBytes(salt);
        Protos.ScryptParameters.Builder scryptParametersBuilder = Protos.ScryptParameters.newBuilder().setSalt(ByteString.copyFrom(salt));
        ScryptParameters scryptParameters = scryptParametersBuilder.build();
        keyCrypter = new KeyCrypterScrypt(scryptParameters);

        encryptedWallet = new Wallet(params, keyCrypter);
        encryptedMixedWallet = new Wallet(params, keyCrypter);

        aesKey = keyCrypter.deriveKey(PASSWORD1);
        wrongAesKey = keyCrypter.deriveKey(WRONG_PASSWORD);
        ECKey myEncryptedKey = encryptedWallet.addNewEncryptedKey(keyCrypter, aesKey);
        myEncryptedAddress = myEncryptedKey.toAddress(params);

        encryptedMixedWallet.addKey(new ECKey());
        ECKey myEncryptedKey2 = encryptedMixedWallet.addNewEncryptedKey(keyCrypter, aesKey);
        myEncryptedAddress2 = myEncryptedKey2.toAddress(params);
    }

	@After
	@Override
	public void tearDown() throws Exception {
		super.tearDown();
	}

	@Test
    public void basicSpending() throws Exception {
        basicSpendingCommon(wallet, myAddress, false);
    }

    @Test
    public void basicSpendingWithEncryptedWallet() throws Exception {
        basicSpendingCommon(encryptedWallet, myEncryptedAddress, true);
    }

    @Test
    public void basicSpendingWithEncryptedMixedWallet() throws Exception {
        basicSpendingCommon(encryptedMixedWallet, myEncryptedAddress2, true);
    }

    private void basicSpendingCommon(Wallet wallet, Address toAddress, boolean testEncryption) throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change. We
        // will attach a small fee. Because the Bitcoin protocol makes it difficult to determine the fee of an
        // arbitrary transaction in isolation, we'll check that the fee was set by examining the size of the change.

        // Receive some money as a pending transaction.
        receiveAPendingTransaction(wallet, toAddress);

        // Prepare to send.
        Address destination = new ECKey().toAddress(params);
        BigInteger v2 = toNanoCoins(0, 50);
        Wallet.SendRequest req = Wallet.SendRequest.to(destination, v2);
        req.fee = toNanoCoins(0, 1);

        if (testEncryption) {
            // Try to create a send with a fee but no password (this should fail).
            try {
                req.ensureMinRequiredFee = false;
                wallet.completeTx(req);
                fail("No exception was thrown trying to sign an encrypted key with no password supplied.");
            } catch (KeyCrypterException kce) {
                assertEquals("This ECKey is encrypted but no decryption key has been supplied.", kce.getMessage());
            }
            assertEquals("Wrong number of UNSPENT.1", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
            assertEquals("Wrong number of ALL.1", 1, wallet.getPoolSize(WalletTransaction.Pool.ALL));

            // Try to create a send with a fee but the wrong password (this should fail).
            req = Wallet.SendRequest.to(destination, v2);
            req.aesKey = wrongAesKey;
            req.fee = toNanoCoins(0, 1);
            req.ensureMinRequiredFee = false;

            try {
                wallet.completeTx(req);
                fail("No exception was thrown trying to sign an encrypted key with the wrong password supplied.");
            } catch (KeyCrypterException kce) {
                assertEquals("Could not decrypt bytes", kce.getMessage());
            }

            assertEquals("Wrong number of UNSPENT.2", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
            assertEquals("Wrong number of ALL.2", 1, wallet.getPoolSize(WalletTransaction.Pool.ALL));

            // Create a send with a fee with the correct password (this should succeed).
            req = Wallet.SendRequest.to(destination, v2);
            req.aesKey = aesKey;
            req.fee = toNanoCoins(0, 1);
            req.ensureMinRequiredFee = false;
        }

        // Complete the transaction successfully.
        wallet.completeTx(req);

        Transaction t2 = req.tx;
        assertEquals("Wrong number of UNSPENT.3", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL.3", 1, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        assertEquals(TransactionConfidence.Source.SELF, t2.getConfidence().getSource());
        assertEquals(Transaction.Purpose.USER_PAYMENT, t2.getPurpose());
        assertEquals(wallet.getChangeAddress(), t2.getOutput(1).getScriptPubKey().getToAddress(params));

        // Do some basic sanity checks.
        basicSanityChecks(wallet, t2, toAddress, destination);

        // Broadcast the transaction and commit.
        broadcastAndCommit(wallet, t2);

        // Now check that we can spend the unconfirmed change, with a new change address of our own selection.
        // (req.aesKey is null for unencrypted / the correct aesKey for encrypted.)
        spendUnconfirmedChange(wallet, t2, req.aesKey);
    }

    private void receiveAPendingTransaction(Wallet wallet, Address toAddress) throws Exception {
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        final ListenableFuture<BigInteger> availFuture = wallet.getBalanceFuture(v1, Wallet.BalanceType.AVAILABLE);
        final ListenableFuture<BigInteger> estimatedFuture = wallet.getBalanceFuture(v1, Wallet.BalanceType.ESTIMATED);
        assertFalse(availFuture.isDone());
        assertFalse(estimatedFuture.isDone());
        // Send some pending coins to the wallet.
        Transaction t1 = sendMoneyToWallet(wallet, v1, toAddress, null);
        Threading.waitForUserCode();
        final ListenableFuture<Transaction> depthFuture = t1.getConfidence().getDepthFuture(1);
        assertFalse(depthFuture.isDone());
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertEquals(v1, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertFalse(availFuture.isDone());
        // Our estimated balance has reached the requested level.
        assertTrue(estimatedFuture.isDone());
        assertEquals(1, wallet.getPoolSize(Pool.PENDING));
        assertEquals(0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        // Confirm the coins.
        sendMoneyToWallet(wallet, t1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals("Incorrect confirmed tx balance", v1, wallet.getBalance());
        assertEquals("Incorrect confirmed tx PENDING pool size", 0, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals("Incorrect confirmed tx UNSPENT pool size", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Incorrect confirmed tx ALL pool size", 1, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        Threading.waitForUserCode();
        assertTrue(availFuture.isDone());
        assertTrue(estimatedFuture.isDone());
        assertTrue(depthFuture.isDone());
    }

    private void basicSanityChecks(Wallet wallet, Transaction t, Address fromAddress, Address destination) throws VerificationException {
        assertEquals("Wrong number of tx inputs", 1, t.getInputs().size());
        assertEquals(fromAddress, t.getInputs().get(0).getScriptSig().getFromAddress(params));
        assertEquals("Wrong number of tx outputs",2, t.getOutputs().size());
        assertEquals(destination, t.getOutputs().get(0).getScriptPubKey().getToAddress(params));
        assertEquals(wallet.getChangeAddress(), t.getOutputs().get(1).getScriptPubKey().getToAddress(params));
        assertEquals(toNanoCoins(0, 49), t.getOutputs().get(1).getValue());
        // Check the script runs and signatures verify.
        t.getInputs().get(0).verify();
    }

    private static void broadcastAndCommit(Wallet wallet, Transaction t) throws Exception {
        final LinkedList<Transaction> txns = Lists.newLinkedList();
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                txns.add(tx);
            }
        });

        t.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByAddress(new byte[]{1,2,3,4})));
        t.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByAddress(new byte[]{10,2,3,4})));
        wallet.commitTx(t);
        Threading.waitForUserCode();
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.SPENT));
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        assertEquals(t, txns.getFirst());
        assertEquals(1, txns.size());
    }

    private void spendUnconfirmedChange(Wallet wallet, Transaction t2, KeyParameter aesKey) throws Exception {
        BigInteger v3 = toNanoCoins(0, 49);
        assertEquals(v3, wallet.getBalance());
        Wallet.SendRequest req = Wallet.SendRequest.to(new ECKey().toAddress(params), toNanoCoins(0, 48));
        req.aesKey = aesKey;
        Address a = req.changeAddress = new ECKey().toAddress(params);
        req.ensureMinRequiredFee = false;
        wallet.completeTx(req);
        Transaction t3 = req.tx;
        assertEquals(a, t3.getOutput(1).getScriptPubKey().getToAddress(params));
        assertNotNull(t3);
        wallet.commitTx(t3);
        assertTrue(wallet.isConsistent());
        // t2 and t3 gets confirmed in the same block.
        BlockPair bp = createFakeBlock(blockStore, t2, t3);
        wallet.receiveFromBlock(t2, bp.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        wallet.receiveFromBlock(t3, bp.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        wallet.notifyNewBestBlock(bp.storedBlock);
        assertTrue(wallet.isConsistent());
    }

    @Test
    public void customTransactionSpending() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        BigInteger v1 = Utils.toNanoCoins(3, 0);
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.ALL));

        ECKey k2 = new ECKey();
        Address a2 = k2.toAddress(params);
        BigInteger v2 = toNanoCoins(0, 50);
        BigInteger v3 = toNanoCoins(0, 75);
        BigInteger v4 = toNanoCoins(1, 25);

        Transaction t2 = new Transaction(params);
        t2.addOutput(v2, a2);
        t2.addOutput(v3, a2);
        t2.addOutput(v4, a2);
        SendRequest req = SendRequest.forTx(t2);
        req.ensureMinRequiredFee = false;
        boolean complete = wallet.completeTx(req);

        // Do some basic sanity checks.
        assertTrue(complete);
        assertEquals(1, t2.getInputs().size());
        assertEquals(myAddress, t2.getInputs().get(0).getScriptSig().getFromAddress(params));
        assertEquals(TransactionConfidence.ConfidenceType.UNKNOWN, t2.getConfidence().getConfidenceType());

        // We have NOT proven that the signature is correct!
        wallet.commitTx(t2);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.SPENT));
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.ALL));
    }

    @Test
    public void sideChain() throws Exception {
        // The wallet receives a coin on the main chain, then on a side chain. Balance is equal to both added together
        // as we assume the side chain tx is pending and will be included shortly.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.ALL));

        BigInteger v2 = toNanoCoins(0, 50);
        sendMoneyToWallet(v2, AbstractBlockChain.NewBlockType.SIDE_CHAIN);
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        assertEquals(v1, wallet.getBalance());
        assertEquals(v1.add(v2), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void balance() throws Exception {
        // Receive 5 coins then half a coin.
        BigInteger v1 = toNanoCoins(5, 0);
        BigInteger v2 = toNanoCoins(0, 50);
        BigInteger expected = toNanoCoins(5, 50);
        assertEquals(0, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        sendMoneyToWallet(v2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(expected, wallet.getBalance());

        // Now spend one coin.
        BigInteger v3 = toNanoCoins(1, 0);
        Transaction spend = wallet.createSend(new ECKey().toAddress(params), v3);
        wallet.commitTx(spend);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));

        // Available and estimated balances should not be the same. We don't check the exact available balance here
        // because it depends on the coin selection algorithm.
        assertEquals(toNanoCoins(4, 50), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertFalse(wallet.getBalance(Wallet.BalanceType.AVAILABLE).equals(
                    wallet.getBalance(Wallet.BalanceType.ESTIMATED)));

        // Now confirm the transaction by including it into a block.
        StoredBlock b3 = createFakeBlock(blockStore, spend).storedBlock;
        wallet.receiveFromBlock(spend, b3, BlockChain.NewBlockType.BEST_CHAIN, 0);

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
        // Test that we correctly process transactions arriving from the chain, with callbacks for inbound and outbound.
        final BigInteger bigints[] = new BigInteger[4];
        final Transaction txn[] = new Transaction[2];
        final LinkedList<Transaction> confTxns = new LinkedList<Transaction>();
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                super.onCoinsReceived(wallet, tx, prevBalance, newBalance);
                bigints[0] = prevBalance;
                bigints[1] = newBalance;
                txn[0] = tx;
            }

            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                super.onCoinsSent(wallet, tx, prevBalance, newBalance);
                bigints[2] = prevBalance;
                bigints[3] = newBalance;
                txn[1] = tx;
            }

            @Override
            public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
                super.onTransactionConfidenceChanged(wallet, tx);
                confTxns.add(tx);
            }
        });
        
        // Receive some money.
        BigInteger oneCoin = Utils.toNanoCoins(1, 0);
        Transaction tx1 = sendMoneyToWallet(oneCoin, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(null, txn[1]);  // onCoinsSent not called.
        assertEquals(tx1, confTxns.getFirst());   // onTransactionConfidenceChanged called
        assertEquals(txn[0].getHash(), tx1.getHash());
        assertEquals(BigInteger.ZERO, bigints[0]);
        assertEquals(oneCoin, bigints[1]);
        assertEquals(TransactionConfidence.ConfidenceType.BUILDING, tx1.getConfidence().getConfidenceType());
        assertEquals(1, tx1.getConfidence().getAppearedAtChainHeight());
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10));
        // Pretend it makes it into the block chain, our wallet state is cleared but we still have the keys, and we
        // want to get back to our previous state. We can do this by just not confirming the transaction as
        // createSend is stateless.
        txn[0] = txn[1] = null;
        confTxns.clear();
        sendMoneyToWallet(send1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(bitcoinValueToFriendlyString(wallet.getBalance()), "0.90");
        assertEquals(null, txn[0]);
        assertEquals(2, confTxns.size());
        assertEquals(txn[1].getHash(), send1.getHash());
        assertEquals(bitcoinValueToFriendlyString(bigints[2]), "1.00");
        assertEquals(bitcoinValueToFriendlyString(bigints[3]), "0.90");
        // And we do it again after the catchup.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10));
        // What we'd really like to do is prove the official client would accept it .... no such luck unfortunately.
        wallet.commitTx(send2);
        sendMoneyToWallet(send2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(bitcoinValueToFriendlyString(wallet.getBalance()), "0.80");
        Threading.waitForUserCode();
        BlockPair b4 = createFakeBlock(blockStore);
        confTxns.clear();
        wallet.notifyNewBestBlock(b4.storedBlock);
        Threading.waitForUserCode();
        assertEquals(3, confTxns.size());
    }

    @Test
    public void balances() throws Exception {
        BigInteger nanos = Utils.toNanoCoins(1, 0);
        Transaction tx1 = sendMoneyToWallet(nanos, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(nanos, tx1.getValueSentToMe(wallet, true));
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 10));
        // Reserialize.
        Transaction send2 = new Transaction(params, send1.bitcoinSerialize());
        assertEquals(nanos, send2.getValueSentFromMe(wallet));
        assertEquals(BigInteger.ZERO.subtract(toNanoCoins(0, 10)), send2.getValue(wallet));
    }

    @Test
    public void isConsistent_duplicates() throws Exception {
        // This test ensures that isConsistent catches duplicate transactions, eg, because we submitted the same block
        // twice (this is not allowed).
        Transaction tx = createFakeTx(params, Utils.toNanoCoins(1, 0), myAddress);
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, Utils.toNanoCoins(0, 5), someOtherGuy);
        tx.addOutput(output);
        wallet.receiveFromBlock(tx, null, BlockChain.NewBlockType.BEST_CHAIN, 0);
        
        assertTrue("Wallet is not consistent", wallet.isConsistent());
        
        Transaction txClone = new Transaction(params, tx.bitcoinSerialize());
        try {
            wallet.receiveFromBlock(txClone, null, BlockChain.NewBlockType.BEST_CHAIN, 0);
            fail("Illegal argument not thrown when it should have been.");
        } catch (IllegalStateException ex) {
            // expected
        }
    }

    @Test
    public void isConsistent_pools() throws Exception {
        // This test ensures that isConsistent catches transactions that are in incompatible pools.
        Transaction tx = createFakeTx(params, Utils.toNanoCoins(1, 0), myAddress);
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, Utils.toNanoCoins(0, 5), someOtherGuy);
        tx.addOutput(output);
        wallet.receiveFromBlock(tx, null, BlockChain.NewBlockType.BEST_CHAIN, 0);
        
        assertTrue(wallet.isConsistent());
        
        wallet.addWalletTransaction(new WalletTransaction(Pool.PENDING, tx));
        assertFalse(wallet.isConsistent());
    }

    @Test
    public void isConsistent_spent() throws Exception {
        // This test ensures that isConsistent catches transactions that are marked spent when
        // they aren't.
        Transaction tx = createFakeTx(params, Utils.toNanoCoins(1, 0), myAddress);
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, Utils.toNanoCoins(0, 5), someOtherGuy);
        tx.addOutput(output);
        assertTrue(wallet.isConsistent());
        
        wallet.addWalletTransaction(new WalletTransaction(Pool.SPENT, tx));
        assertFalse(wallet.isConsistent());
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
        sendMoneyToWallet(tx, AbstractBlockChain.NewBlockType.BEST_CHAIN);
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
        sendMoneyToWallet(coin1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Send half to some other guy. Sending only half then waiting for a confirm is important to ensure the tx is
        // in the unspent pool, not pending or spent.
        BigInteger coinHalf = Utils.toNanoCoins(0, 50);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        Address someOtherGuy = new ECKey().toAddress(params);
        Transaction outbound1 = wallet.createSend(someOtherGuy, coinHalf);
        wallet.commitTx(outbound1);
        sendMoneyToWallet(outbound1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // That other guy gives us the coins right back.
        Transaction inbound2 = new Transaction(params);
        inbound2.addOutput(new TransactionOutput(params, inbound2, coinHalf, myAddress));
        inbound2.addInput(outbound1.getOutputs().get(0));
        sendMoneyToWallet(inbound2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(coin1, wallet.getBalance());
    }

    @Test
    public void doubleSpendUnspendsOtherInputs() throws Exception {
        // Test another Finney attack, but this time the killed transaction was also spending some other outputs in
        // our wallet which were not themselves double spent. This test ensures the death of the pending transaction
        // frees up the other outputs and makes them spendable again.

        // Receive 1 coin and then 2 coins in separate transactions.
        sendMoneyToWallet(Utils.toNanoCoins(1, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(Utils.toNanoCoins(2, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Create a send to a merchant of all our coins.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(2, 90));
        // Create a double spend of just the first one.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(1, 0));
        send2 = new Transaction(params, send2.bitcoinSerialize());
        // Broadcast send1, it's now pending.
        wallet.commitTx(send1);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        // Receive a block that overrides the send1 using send2.
        sendMoneyToWallet(send2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // send1 got rolled back and replaced with a smaller send that only used one of our received coins, thus ...
        assertEquals(Utils.toNanoCoins(2, 0), wallet.getBalance());
        assertTrue(wallet.isConsistent());
    }

    @Test
    public void doubleSpendFinneyAttack() throws Exception {
        // A Finney attack is where a miner includes a transaction spending coins to themselves but does not
        // broadcast it. When they find a solved block, they hold it back temporarily whilst they buy something with
        // those same coins. After purchasing, they broadcast the block thus reversing the transaction. It can be
        // done by any miner for products that can be bought at a chosen time and very quickly (as every second you
        // withold your block means somebody else might find it first, invalidating your work).
        //
        // Test that we handle the attack correctly: a double spend on the chain moves transactions from pending to dead.
        // This needs to work both for transactions we create, and that we receive from others.
        final Transaction[] eventDead = new Transaction[1];
        final Transaction[] eventReplacement = new Transaction[1];
        final int[] eventWalletChanged = new int[1];
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

            @Override
            public void onWalletChanged(Wallet wallet) {
                eventWalletChanged[0]++;
            }
        });

        // Receive 1 BTC.
        BigInteger nanos = Utils.toNanoCoins(1, 0);
        sendMoneyToWallet(nanos, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Transaction received = wallet.getTransactions(false).iterator().next();
        // Create a send to a merchant.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 50));
        // Create a double spend.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), toNanoCoins(0, 50));
        send2 = new Transaction(params, send2.bitcoinSerialize());
        // Broadcast send1.
        wallet.commitTx(send1);
        assertEquals(send1, received.getOutput(0).getSpentBy().getParentTransaction());
        // Receive a block that overrides it.
        sendMoneyToWallet(send2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(send1, eventDead[0]);
        assertEquals(send2, eventReplacement[0]);
        assertEquals(TransactionConfidence.ConfidenceType.DEAD,
                     send1.getConfidence().getConfidenceType());
        assertEquals(send2, received.getOutput(0).getSpentBy().getParentTransaction());

        TestUtils.DoubleSpends doubleSpends = TestUtils.createFakeDoubleSpendTxns(params, myAddress);
        // t1 spends to our wallet. t2 double spends somewhere else.
        wallet.receivePending(doubleSpends.t1, null);
        assertEquals(TransactionConfidence.ConfidenceType.PENDING,
                doubleSpends.t1.getConfidence().getConfidenceType());
        sendMoneyToWallet(doubleSpends.t2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(TransactionConfidence.ConfidenceType.DEAD,
                     doubleSpends.t1.getConfidence().getConfidenceType());
        assertEquals(doubleSpends.t2, doubleSpends.t1.getConfidence().getOverridingTransaction());
        assertEquals(5, eventWalletChanged[0]);
    }

    @Test
    public void pending1() throws Exception {
        // Check that if we receive a pending transaction that is then confirmed, we are notified as appropriate.
        final BigInteger nanos = Utils.toNanoCoins(1, 0);
        final Transaction t1 = createFakeTx(params, nanos, myAddress);

        // First one is "called" second is "pending".
        final boolean[] flags = new boolean[2];
        final Transaction[] notifiedTx = new Transaction[1];
        final int[] walletChanged = new int[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                // Check we got the expected transaction.
                assertEquals(tx, t1);
                // Check that it's considered to be pending inclusion in the block chain.
                assertEquals(prevBalance, BigInteger.ZERO);
                assertEquals(newBalance, nanos);
                flags[0] = true;
                flags[1] = tx.isPending();
                notifiedTx[0] = tx;
            }

            @Override
            public void onWalletChanged(Wallet wallet) {
                walletChanged[0]++;
            }
        });

        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        Threading.waitForUserCode();
        assertTrue(flags[0]);
        assertTrue(flags[1]);   // is pending
        flags[0] = false;
        // Check we don't get notified if we receive it again.
        assertFalse(wallet.isPendingTransactionRelevant(t1));
        assertFalse(flags[0]);
        // Now check again, that we should NOT be notified when we receive it via a block (we were already notified).
        // However the confidence should be updated.
        // Make a fresh copy of the tx to ensure we're testing realistically.
        flags[0] = flags[1] = false;
        notifiedTx[0].getConfidence().addEventListener(new TransactionConfidence.Listener() {
            public void onConfidenceChanged(Transaction tx, TransactionConfidence.Listener.ChangeReason reason) {
                flags[1] = true;
            }
        });
        assertEquals(TransactionConfidence.ConfidenceType.PENDING,
                notifiedTx[0].getConfidence().getConfidenceType());
        final Transaction t1Copy = new Transaction(params, t1.bitcoinSerialize());
        sendMoneyToWallet(t1Copy, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertFalse(flags[0]);
        assertTrue(flags[1]);
        assertEquals(TransactionConfidence.ConfidenceType.BUILDING, notifiedTx[0].getConfidence().getConfidenceType());
        // Check we don't get notified about an irrelevant transaction.
        flags[0] = false;
        flags[1] = false;
        Transaction irrelevant = createFakeTx(params, nanos, new ECKey().toAddress(params));
        if (wallet.isPendingTransactionRelevant(irrelevant))
            wallet.receivePending(irrelevant, null);
        Threading.waitForUserCode();
        assertFalse(flags[0]);
        assertEquals(2, walletChanged[0]);
    }

    @Test
    public void pending2() throws Exception {
        // Check that if we receive a pending tx we did not send, it updates our spent flags correctly.
        final Transaction txn[] = new Transaction[1];
        final BigInteger bigints[] = new BigInteger[2];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                txn[0] = tx;
                bigints[0] = prevBalance;
                bigints[1] = newBalance;
            }
        });
        // Receive some coins.
        BigInteger nanos = Utils.toNanoCoins(1, 0);
        sendMoneyToWallet(nanos, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Create a spend with them, but don't commit it (ie it's from somewhere else but using our keys). This TX
        // will have change as we don't spend our entire balance.
        BigInteger halfNanos = Utils.toNanoCoins(0, 50);
        Transaction t2 = wallet.createSend(new ECKey().toAddress(params), halfNanos);
        // Now receive it as pending.
        if (wallet.isPendingTransactionRelevant(t2))
            wallet.receivePending(t2, null);
        // We received an onCoinsSent() callback.
        Threading.waitForUserCode();
        assertEquals(t2, txn[0]);
        assertEquals(nanos, bigints[0]);
        assertEquals(halfNanos, bigints[1]);
        // Our balance is now 0.50 BTC
        assertEquals(halfNanos, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void pending3() throws Exception {
        // Check that if we receive a pending tx, and it's overridden by a double spend from the main chain, we
        // are notified that it's dead. This should work even if the pending tx inputs are NOT ours, ie, they don't
        // connect to anything.
        BigInteger nanos = Utils.toNanoCoins(1, 0);

        // Create two transactions that share the same input tx.
        Address badGuy = new ECKey().toAddress(params);
        Transaction doubleSpentTx = new Transaction(params);
        TransactionOutput doubleSpentOut = new TransactionOutput(params, doubleSpentTx, nanos, badGuy);
        doubleSpentTx.addOutput(doubleSpentOut);
        Transaction t1 = new Transaction(params);
        TransactionOutput o1 = new TransactionOutput(params, t1, nanos, myAddress);
        t1.addOutput(o1);
        t1.addInput(doubleSpentOut);
        Transaction t2 = new Transaction(params);
        TransactionOutput o2 = new TransactionOutput(params, t2, nanos, badGuy);
        t2.addOutput(o2);
        t2.addInput(doubleSpentOut);

        final Transaction[] called = new Transaction[2];
        wallet.addEventListener(new AbstractWalletEventListener() {
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                called[0] = tx;
            }

            @Override
            public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
                super.onTransactionConfidenceChanged(wallet, tx);
                if (tx.getConfidence().getConfidenceType() ==
                        TransactionConfidence.ConfidenceType.DEAD) {
                    called[0] = tx;
                    called[1] = tx.getConfidence().getOverridingTransaction();
                }
            }
        });

        assertEquals(BigInteger.ZERO, wallet.getBalance());
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        Threading.waitForUserCode();
        assertEquals(t1, called[0]);
        assertEquals(nanos, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        // Now receive a double spend on the main chain.
        called[0] = called[1] = null;
        sendMoneyToWallet(t2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertEquals(t1, called[0]); // dead
        assertEquals(t2, called[1]); // replacement
    }

    @Test
    public void transactionsList() throws Exception {
        // Check the wallet can give us an ordered list of all received transactions.
        Utils.rollMockClock(0);
        Transaction tx1 = sendMoneyToWallet(Utils.toNanoCoins(1, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Utils.rollMockClock(60 * 10);
        Transaction tx2 = sendMoneyToWallet(Utils.toNanoCoins(0, 5), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Check we got them back in order.
        List<Transaction> transactions = wallet.getTransactionsByTime();
        assertEquals(tx2, transactions.get(0));
        assertEquals(tx1,  transactions.get(1));
        assertEquals(2, transactions.size());
        // Check we get only the last transaction if we request a subrage.
        transactions = wallet.getRecentTransactions(1, false);
        assertEquals(1, transactions.size());
        assertEquals(tx2,  transactions.get(0));

        // Create a spend five minutes later.
        Utils.rollMockClock(60 * 5);
        Transaction tx3 = wallet.createSend(new ECKey().toAddress(params), Utils.toNanoCoins(0, 5));
        // Does not appear in list yet.
        assertEquals(2, wallet.getTransactionsByTime().size());
        wallet.commitTx(tx3);
        // Now it does.
        transactions = wallet.getTransactionsByTime();
        assertEquals(3, transactions.size());
        assertEquals(tx3, transactions.get(0));

        // Verify we can handle the case of older wallets in which the timestamp is null (guessed from the
        // block appearances list).
        tx1.setUpdateTime(null);
        tx3.setUpdateTime(null);
        // Check we got them back in order.
        transactions = wallet.getTransactionsByTime();
        assertEquals(tx2,  transactions.get(0));
        assertEquals(3, transactions.size());
    }

    @Test
    public void keyCreationTime() throws Exception {
        wallet = new Wallet(params);
        long now = Utils.rollMockClock(0).getTime() / 1000;  // Fix the mock clock.
        // No keys returns current time.
        assertEquals(now, wallet.getEarliestKeyCreationTime());
        Utils.rollMockClock(60);
        wallet.addKey(new ECKey());
        assertEquals(now + 60, wallet.getEarliestKeyCreationTime());
        Utils.rollMockClock(60);
        wallet.addKey(new ECKey());
        assertEquals(now + 60, wallet.getEarliestKeyCreationTime());
    }

    @Test
    public void spendToSameWallet() throws Exception {
        // Test that a spend to the same wallet is dealt with correctly.
        // It should appear in the wallet and confirm.
        // This is a bit of a silly thing to do in the real world as all it does is burn a fee but it is perfectly valid.
        BigInteger coin1 = Utils.toNanoCoins(1, 0);
        BigInteger coinHalf = Utils.toNanoCoins(0, 50);
        // Start by giving us 1 coin.
        sendMoneyToWallet(coin1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Send half to ourselves. We should then have a balance available to spend of zero.
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        Transaction outbound1 = wallet.createSend(myAddress, coinHalf);
        wallet.commitTx(outbound1);
        // We should have a zero available balance before the next block.
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        sendMoneyToWallet(outbound1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // We should have a balance of 1 BTC after the block is received.
        assertEquals(coin1, wallet.getBalance());
    }

    @Test
    public void rememberLastBlockSeenHash() throws Exception {
        BigInteger v1 = toNanoCoins(5, 0);
        BigInteger v2 = toNanoCoins(0, 50);
        BigInteger v3 = toNanoCoins(0, 25);
        Transaction t1 = createFakeTx(params, v1, myAddress);
        Transaction t2 = createFakeTx(params, v2, myAddress);
        Transaction t3 = createFakeTx(params, v3, myAddress);

        Block genesis = blockStore.getChainHead().getHeader();
        Block b10 = makeSolvedTestBlock(genesis, t1);
        Block b11 = makeSolvedTestBlock(genesis, t2);
        Block b2 = makeSolvedTestBlock(b10, t3);
        Block b3 = makeSolvedTestBlock(b2);

        // Receive a block on the best chain - this should set the last block seen hash.
        chain.add(b10);
        assertEquals(b10.getHash(), wallet.getLastBlockSeenHash());
        // Receive a block on the side chain - this should not change the last block seen hash.
        chain.add(b11);
        assertEquals(b10.getHash(), wallet.getLastBlockSeenHash());
        // Receive block 2 on the best chain - this should change the last block seen hash.
        chain.add(b2);
        assertEquals(b2.getHash(), wallet.getLastBlockSeenHash());
        // Receive block 3 on the best chain - this should change the last block seen hash despite having no txns.
        chain.add(b3);
        assertEquals(b3.getHash(), wallet.getLastBlockSeenHash());
    }

    @Test
    public void pubkeyOnlyScripts() throws Exception {
        // Verify that we support outputs like OP_PUBKEY and the corresponding inputs.
        ECKey key1 = new ECKey();
        wallet.addKey(key1);
        BigInteger value = toNanoCoins(5, 0);
        Transaction t1 = createFakeTx(params, value, key1);
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        // TX should have been seen as relevant.
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertEquals(BigInteger.ZERO, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        Block b1 = createFakeBlock(blockStore, t1).block;
        chain.add(b1);
        // TX should have been seen as relevant, extracted and processed.
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        // Spend it and ensure we can spend the <key> OP_CHECKSIG output correctly.
        Transaction t2 = wallet.createSend(new ECKey().toAddress(params), value);
        assertNotNull(t2);
        // TODO: This code is messy, improve the Script class and fixinate!
        assertEquals(t2.toString(), 1, t2.getInputs().get(0).getScriptSig().getChunks().size());
        assertTrue(t2.getInputs().get(0).getScriptSig().getChunks().get(0).data.length > 50);
        log.info(t2.toString(chain));
    }

    @Test
    public void autosaveImmediate() throws Exception {
        // Test that the wallet will save itself automatically when it changes.
        File f = File.createTempFile("bitcoinj-unit-test", null);
        Sha256Hash hash1 = Sha256Hash.hashFileContents(f);
        // Start with zero delay and ensure the wallet file changes after adding a key.
        wallet.autosaveToFile(f, 0, TimeUnit.SECONDS, null);
        ECKey key = new ECKey();
        wallet.addKey(key);
        Sha256Hash hash2 = Sha256Hash.hashFileContents(f);
        assertFalse("Wallet not saved after addKey", hash1.equals(hash2));  // File has changed.

        Transaction t1 = createFakeTx(params, toNanoCoins(5, 0), key);
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        Sha256Hash hash3 = Sha256Hash.hashFileContents(f);
        assertFalse("Wallet not saved after receivePending", hash2.equals(hash3));  // File has changed again.

        Block b1 = createFakeBlock(blockStore, t1).block;
        chain.add(b1);
        Sha256Hash hash4 = Sha256Hash.hashFileContents(f);
        assertFalse("Wallet not saved after chain add.1", hash3.equals(hash4));  // File has changed again.

        // Check that receiving some block without any relevant transactions still triggers a save.
        Block b2 = b1.createNextBlock(new ECKey().toAddress(params));
        chain.add(b2);
        assertFalse("Wallet not saved after chain add.2", hash4.equals(Sha256Hash.hashFileContents(f)));  // File has changed again.
    }

    @Test
    public void autosaveDelayed() throws Exception {
        // Test that the wallet will save itself automatically when it changes, but not immediately and near-by
        // updates are coalesced together. This test is a bit racy, it assumes we can complete the unit test within
        // an auto-save cycle of 1 second.
        final File[] results = new File[2];
        final CountDownLatch latch = new CountDownLatch(3);
        File f = File.createTempFile("bitcoinj-unit-test", null);
        Sha256Hash hash1 = Sha256Hash.hashFileContents(f);
        wallet.autosaveToFile(f, 1, TimeUnit.SECONDS,
                new WalletFiles.Listener() {
                    public void onBeforeAutoSave(File tempFile) {
                        results[0] = tempFile;
                    }

                    public void onAfterAutoSave(File newlySavedFile) {
                        results[1] = newlySavedFile;
                        latch.countDown();
                    }
                }
        );
        ECKey key = new ECKey();
        wallet.addKey(key);
        Sha256Hash hash2 = Sha256Hash.hashFileContents(f);
        assertFalse(hash1.equals(hash2));  // File has changed immediately despite the delay, as keys are important.
        assertNotNull(results[0]);
        assertEquals(f, results[1]);
        results[0] = results[1] = null;

        Block b0 = createFakeBlock(blockStore).block;
        chain.add(b0);
        Sha256Hash hash3 = Sha256Hash.hashFileContents(f);
        assertEquals(hash2, hash3);  // File has NOT changed yet. Just new blocks with no txns - delayed.
        assertNull(results[0]);
        assertNull(results[1]);

        Transaction t1 = createFakeTx(params, toNanoCoins(5, 0), key);
        Block b1 = createFakeBlock(blockStore, t1).block;
        chain.add(b1);
        Sha256Hash hash4 = Sha256Hash.hashFileContents(f);
        assertFalse(hash3.equals(hash4));  // File HAS changed.
        results[0] = results[1] = null;

        // A block that contains some random tx we don't care about.
        Block b2 = b1.createNextBlock(new ECKey().toAddress(params));
        chain.add(b2);
        assertEquals(hash4, Sha256Hash.hashFileContents(f));  // File has NOT changed.
        assertNull(results[0]);
        assertNull(results[1]);

        // Wait for an auto-save to occur.
        latch.await();
        assertFalse(hash4.equals(Sha256Hash.hashFileContents(f)));  // File has now changed.
        assertNotNull(results[0]);
        assertEquals(f, results[1]);
    }
    
    @Test
    public void spendOutputFromPendingTransaction() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // First create our current transaction
        ECKey k2 = new ECKey();
        wallet.addKey(k2);
        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t2 = new Transaction(params);
        TransactionOutput o2 = new TransactionOutput(params, t2, v2, k2.toAddress(params));
        t2.addOutput(o2);
        SendRequest req = SendRequest.forTx(t2);
        req.ensureMinRequiredFee = false;
        boolean complete = wallet.completeTx(req);
        assertTrue(complete);
        
        // Commit t2, so it is placed in the pending pool
        wallet.commitTx(t2);
        assertEquals(0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        
        // Now try to the spend the output.
        ECKey k3 = new ECKey();
        BigInteger v3 = toNanoCoins(0, 25);
        Transaction t3 = new Transaction(params);
        t3.addOutput(v3, k3.toAddress(params));
        t3.addInput(o2);
        t3.signInputs(SigHash.ALL, wallet);
        
        // Commit t3, so the coins from the pending t2 are spent
        wallet.commitTx(t3);
        assertEquals(0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(3, wallet.getPoolSize(WalletTransaction.Pool.ALL));
        
        // Now the output of t2 must not be available for spending
        assertFalse(o2.isAvailableForSpending());
    }

    @Test
    public void replayWhilstPending() throws Exception {
        // Check that if a pending transaction spends outputs of chain-included transactions, we mark them as spent.
        // See bug 345. This can happen if there is a pending transaction floating around and then you replay the
        // chain without emptying the memory pool (or refilling it from a peer).
        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction tx1 = createFakeTx(params, value, myAddress);
        Transaction tx2 = new Transaction(params);
        tx2.addInput(tx1.getOutput(0));
        tx2.addOutput(Utils.toNanoCoins(0, 9), new ECKey());
        // Add a change address to ensure this tx is relevant.
        tx2.addOutput(Utils.toNanoCoins(0, 1), wallet.getChangeAddress());
        wallet.receivePending(tx2, null);
        BlockPair bp = createFakeBlock(blockStore, tx1);
        wallet.receiveFromBlock(tx1, bp.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        wallet.notifyNewBestBlock(bp.storedBlock);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(Pool.SPENT));
        assertEquals(1, wallet.getPoolSize(Pool.PENDING));
        assertEquals(0, wallet.getPoolSize(Pool.UNSPENT));
    }

    @Test
    public void encryptionDecryptionBasic() throws Exception {
        encryptionDecryptionBasicCommon(encryptedWallet);
        encryptionDecryptionBasicCommon(encryptedMixedWallet);
    }

    private void encryptionDecryptionBasicCommon(Wallet wallet) {
        // Check the wallet is initially of WalletType ENCRYPTED.
        assertTrue("Wallet is not an encrypted wallet", wallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);

        // Correct password should decrypt first encrypted private key.
        assertTrue("checkPassword result is wrong with correct password.2", wallet.checkPassword(PASSWORD1));

        // Incorrect password should not decrypt first encrypted private key.
        assertFalse("checkPassword result is wrong with incorrect password.3", wallet.checkPassword(WRONG_PASSWORD));

        // Decrypt wallet.
        assertTrue("The keyCrypter is missing but should not be", keyCrypter != null);
        wallet.decrypt(aesKey);

        // Wallet should now be unencrypted.
        assertTrue("Wallet is not an unencrypted wallet", wallet.getKeyCrypter() == null);

        // Correct password should not decrypt first encrypted private key as wallet is unencrypted.
        assertTrue("checkPassword result is wrong with correct password", !wallet.checkPassword(PASSWORD1));

        // Incorrect password should not decrypt first encrypted private key as wallet is unencrypted.
        assertTrue("checkPassword result is wrong with incorrect password", !wallet.checkPassword(WRONG_PASSWORD));

        // Encrypt wallet.
        wallet.encrypt(keyCrypter, aesKey);

        // Wallet should now be of type WalletType.ENCRYPTED_SCRYPT_AES.
        assertTrue("Wallet is not an encrypted wallet", wallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);
    }

    @Test
    public void encryptionDecryptionBadPassword() throws Exception {
        // Check the wallet is currently encrypted
        assertTrue("Wallet is not an encrypted wallet", encryptedWallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);

        // Chek that the wrong password does not decrypt the wallet.
        try {
            encryptedWallet.decrypt(wrongAesKey);
            fail("Incorrectly decoded wallet with wrong password");
        } catch (KeyCrypterException ede) {
            // Expected.
        }
    }

    @Test
    public void encryptionDecryptionCheckExceptions() throws Exception {
        // Check the wallet is currently encrypted
        assertTrue("Wallet is not an encrypted wallet", encryptedWallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);

        // Decrypt wallet.
        assertTrue("The keyCrypter is missing but should not be.1", keyCrypter != null);
        encryptedWallet.decrypt(aesKey);

        // Try decrypting it again
        try {
            assertTrue("The keyCrypter is missing but should not be.2", keyCrypter != null);
            encryptedWallet.decrypt(aesKey);
            fail("Should not be able to decrypt a decrypted wallet");
        } catch (IllegalStateException e) {
            assertTrue("Expected behaviour", true);
        }
        assertTrue("Wallet is not an unencrypted wallet.2", encryptedWallet.getKeyCrypter() == null);

        // Encrypt wallet.
        encryptedWallet.encrypt(keyCrypter, aesKey);

        assertTrue("Wallet is not an encrypted wallet.2", encryptedWallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);

        // Try encrypting it again
        try {
            encryptedWallet.encrypt(keyCrypter, aesKey);
            fail("Should not be able to encrypt an encrypted wallet");
        } catch (IllegalStateException e) {
            assertTrue("Expected behaviour", true);
        }
        assertTrue("Wallet is not an encrypted wallet.3", encryptedWallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);
    }

    @Test
    public void encryptionDecryptionHomogenousKeys() throws Exception {
        // Check the wallet is currently encrypted
        assertTrue("Wallet is not an encrypted wallet", encryptedWallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);

        // Try added an ECKey that was encrypted with a differenct ScryptParameters (i.e. a non-homogenous key).
        // This is not allowed as the ScryptParameters is stored at the Wallet level.
        byte[] salt = new byte[KeyCrypterScrypt.SALT_LENGTH];
        secureRandom.nextBytes(salt);
        Protos.ScryptParameters.Builder scryptParametersBuilder = Protos.ScryptParameters.newBuilder().setSalt(ByteString.copyFrom(salt));
        ScryptParameters scryptParameters = scryptParametersBuilder.build();

        KeyCrypter keyCrypterDifferent = new KeyCrypterScrypt(scryptParameters);

        ECKey ecKeyDifferent = new ECKey();
        ecKeyDifferent = ecKeyDifferent.encrypt(keyCrypterDifferent, aesKey);

        Iterable<ECKey> keys = encryptedWallet.getKeys();
        Iterator iterator = keys.iterator();
        boolean oneKey = iterator.hasNext();
        iterator.next();
        assertTrue("Wrong number of keys in wallet before key addition", oneKey && !iterator.hasNext());

        try {
            encryptedWallet.addKey(ecKeyDifferent);
            fail("AddKey should have thrown an EncrypterDecrypterException but did not.");
        } catch (KeyCrypterException ede) {
            // Expected behaviour.
        }

        keys = encryptedWallet.getKeys();
        iterator = keys.iterator();
        oneKey = iterator.hasNext();

        iterator.next();
        assertTrue("Wrong number of keys in wallet after key addition", oneKey && !iterator.hasNext());
    }

    @Test
    public void ageMattersDuringSelection() throws Exception {
        // Test that we prefer older coins to newer coins when building spends. This reduces required fees and improves
        // time to confirmation as the transaction will appear less spammy.
        final int ITERATIONS = 10;
        Transaction[] txns = new Transaction[ITERATIONS];
        for (int i = 0; i < ITERATIONS; i++) {
            txns[i] = sendMoneyToWallet(Utils.toNanoCoins(1, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        }
        // Check that we spend transactions in order of reception.
        for (int i = 0; i < ITERATIONS; i++) {
            Transaction spend = wallet.createSend(new ECKey().toAddress(params), Utils.toNanoCoins(1, 0));
            assertEquals(spend.getInputs().size(), 1);
            assertEquals("Failed on iteration " + i, spend.getInput(0).getOutpoint().getHash(), txns[i].getHash());
            wallet.commitTx(spend);
        }
    }

    @Test
    public void respectMaxStandardSize() throws Exception {
        // Check that we won't create txns > 100kb. Average tx size is ~220 bytes so this would have to be enormous.
        sendMoneyToWallet(Utils.toNanoCoins(100, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Transaction tx = new Transaction(params);
        byte[] bits = new byte[20];
        new Random().nextBytes(bits);
        BigInteger v = Utils.toNanoCoins(0, 1);
        // 3100 outputs to a random address.
        for (int i = 0; i < 3100; i++) {
            tx.addOutput(v, new Address(params, bits));
        }
        Wallet.SendRequest req = Wallet.SendRequest.forTx(tx);
        assertFalse(wallet.completeTx(req));
    }

    @Test
    public void feeSolverAndCoinSelectionTest() throws Exception {
        // Tests basic fee solving works

        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a few outputs to us that are far too small to spend reasonably
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx1 = createFakeTx(params, BigInteger.ONE, myAddress);
        wallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        Transaction tx2 = createFakeTx(params, BigInteger.ONE, myAddress);
        assertTrue(!tx1.getHash().equals(tx2.getHash()));
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        Transaction tx3 = createFakeTx(params, BigInteger.TEN, myAddress);
        wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 2);

        // No way we can add nearly enough fee
        assertNull(wallet.createSend(notMyAddr, BigInteger.ONE));
        // Spend it all without fee enforcement
        SendRequest req = SendRequest.to(notMyAddr, BigInteger.TEN.add(BigInteger.ONE.add(BigInteger.ONE)));
        req.ensureMinRequiredFee = false;
        assertNotNull(wallet.sendCoinsOffline(req));
        assertEquals(BigInteger.ZERO, wallet.getBalance());

        // Add some reasonable-sized outputs
        block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx4 = createFakeTx(params, Utils.COIN, myAddress);
        wallet.receiveFromBlock(tx4, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);

        // Simple test to make sure if we have an ouput < 0.01 we get a fee
        Transaction spend1 = wallet.createSend(notMyAddr, CENT.subtract(BigInteger.ONE));
        assertEquals(2, spend1.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        // We should have paid the default minfee.
        assertEquals(spend1.getOutput(0).getValue().add(spend1.getOutput(1).getValue()),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        // But not at exactly 0.01
        Transaction spend2 = wallet.createSend(notMyAddr, CENT);
        assertEquals(2, spend2.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(Utils.COIN, spend2.getOutput(0).getValue().add(spend2.getOutput(1).getValue()));

        // ...but not more fee than what we request
        SendRequest request3 = SendRequest.to(notMyAddr, CENT.subtract(BigInteger.ONE));
        request3.fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(BigInteger.ONE);
        assertTrue(wallet.completeTx(request3));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(BigInteger.ONE), request3.fee);
        Transaction spend3 = request3.tx;
        assertEquals(2, spend3.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend3.getOutput(0).getValue().add(spend3.getOutput(1).getValue()),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(BigInteger.ONE)));

        // ...unless we need it
        SendRequest request4 = SendRequest.to(notMyAddr, CENT.subtract(BigInteger.ONE));
        request4.fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.subtract(BigInteger.ONE);
        assertTrue(wallet.completeTx(request4));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request4.fee);
        Transaction spend4 = request4.tx;
        assertEquals(2, spend4.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend4.getOutput(0).getValue().add(spend4.getOutput(1).getValue()),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request5 = SendRequest.to(notMyAddr, Utils.COIN.subtract(CENT.subtract(BigInteger.ONE)));
        assertTrue(wallet.completeTx(request5));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request5.fee);
        Transaction spend5 = request5.tx;
        // If we would have a change output < 0.01, it should add the fee
        assertEquals(2, spend5.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend5.getOutput(0).getValue().add(spend5.getOutput(1).getValue()),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request6 = SendRequest.to(notMyAddr, Utils.COIN.subtract(CENT));
        assertTrue(wallet.completeTx(request6));
        assertEquals(BigInteger.ZERO, request6.fee);
        Transaction spend6 = request6.tx;
        // ...but not if change output == 0.01
        assertEquals(2, spend6.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(Utils.COIN, spend6.getOutput(0).getValue().add(spend6.getOutput(1).getValue()));

        SendRequest request7 = SendRequest.to(notMyAddr, Utils.COIN.subtract(CENT.subtract(BigInteger.valueOf(2)).multiply(BigInteger.valueOf(2))));
        request7.tx.addOutput(CENT.subtract(BigInteger.ONE), notMyAddr);
        assertTrue(wallet.completeTx(request7));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request7.fee);
        Transaction spend7 = request7.tx;
        // If change is 0.1-nanocoin and we already have a 0.1-nanocoin output, fee should be reference fee
        assertEquals(3, spend7.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend7.getOutput(0).getValue().add(spend7.getOutput(1).getValue()).add(spend7.getOutput(2).getValue()),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request8 = SendRequest.to(notMyAddr, Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));
        assertTrue(wallet.completeTx(request8));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request8.fee);
        Transaction spend8 = request8.tx;
        // If we would have a change output == REFERENCE_DEFAULT_MIN_TX_FEE that would cause a fee, throw it away and make it fee
        assertEquals(1, spend8.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(spend8.getOutput(0).getValue(), Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request9 = SendRequest.to(notMyAddr, Utils.COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)));
        assertTrue(wallet.completeTx(request9));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT), request9.fee);
        Transaction spend9 = request9.tx;
        // ...in fact, also add fee if we would get back less than MIN_NONDUST_OUTPUT
        assertEquals(1, spend9.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend9.getOutput(0).getValue(),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)));

        SendRequest request10 = SendRequest.to(notMyAddr, Utils.COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT).add(BigInteger.ONE)));
        assertTrue(wallet.completeTx(request10));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request10.fee);
        Transaction spend10 = request10.tx;
        // ...but if we get back any more than that, we should get a refund (but still pay fee)
        assertEquals(2, spend10.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(spend10.getOutput(0).getValue().add(spend10.getOutput(1).getValue()),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request11 = SendRequest.to(notMyAddr, Utils.COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT).add(BigInteger.valueOf(2))));
        request11.fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(BigInteger.ONE);
        assertTrue(wallet.completeTx(request11));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(BigInteger.ONE), request11.fee);
        Transaction spend11 = request11.tx;
        // ...of course fee should be min(request.fee, MIN_TX_FEE) so we should get MIN_TX_FEE.add(ONE) here
        assertEquals(2, spend11.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend11.getOutput(0).getValue().add(spend11.getOutput(1).getValue()),
                Utils.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(BigInteger.ONE)));

        // Remove the coin from our wallet
        wallet.commitTx(spend11);
        Transaction tx5 = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx5, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        assertEquals(CENT, wallet.getBalance());

        // Now test coin selection properly selects coin*depth
        for (int i = 0; i < 100; i++) {
            block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
            wallet.notifyNewBestBlock(block);
        }

        block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx6 = createFakeTx(params, Utils.COIN, myAddress);
        wallet.receiveFromBlock(tx6, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        assertTrue(tx5.getOutput(0).isMine(wallet) && tx5.getOutput(0).isAvailableForSpending() && tx5.getConfidence().getDepthInBlocks() == 100);
        assertTrue(tx6.getOutput(0).isMine(wallet) && tx6.getOutput(0).isAvailableForSpending() && tx6.getConfidence().getDepthInBlocks() == 1);

        // tx5 and tx6 have exactly the same coin*depth, so the larger should be selected...
        Transaction spend12 = wallet.createSend(notMyAddr, CENT);
        assertTrue(spend12.getOutputs().size() == 2 && spend12.getOutput(0).getValue().add(spend12.getOutput(1).getValue()).equals(Utils.COIN));

        wallet.notifyNewBestBlock(block);
        assertTrue(tx5.getOutput(0).isMine(wallet) && tx5.getOutput(0).isAvailableForSpending() && tx5.getConfidence().getDepthInBlocks() == 101);
        assertTrue(tx6.getOutput(0).isMine(wallet) && tx6.getOutput(0).isAvailableForSpending() && tx6.getConfidence().getDepthInBlocks() == 1);
        // Now tx5 has slightly higher coin*depth than tx6...
        Transaction spend13 = wallet.createSend(notMyAddr, CENT);
        assertTrue(spend13.getOutputs().size() == 1 && spend13.getOutput(0).getValue().equals(CENT));

        block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        wallet.notifyNewBestBlock(block);
        assertTrue(tx5.getOutput(0).isMine(wallet) && tx5.getOutput(0).isAvailableForSpending() && tx5.getConfidence().getDepthInBlocks() == 102);
        assertTrue(tx6.getOutput(0).isMine(wallet) && tx6.getOutput(0).isAvailableForSpending() && tx6.getConfidence().getDepthInBlocks() == 2);
        // Now tx6 has higher coin*depth than tx5...
        Transaction spend14 = wallet.createSend(notMyAddr, CENT);
        assertTrue(spend14.getOutputs().size() == 2 && spend14.getOutput(0).getValue().add(spend14.getOutput(1).getValue()).equals(Utils.COIN));

        // Now test feePerKb
        SendRequest request15 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 29; i++)
            request15.tx.addOutput(CENT, notMyAddr);
        assertTrue(request15.tx.bitcoinSerialize().length > 1000);
        request15.feePerKb = BigInteger.ONE;
        assertTrue(wallet.completeTx(request15));
        assertEquals(BigInteger.valueOf(2), request15.fee);
        Transaction spend15 = request15.tx;
        // If a transaction is over 1kb, 2 satoshis should be added.
        assertEquals(31, spend15.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        BigInteger outValue15 = BigInteger.ZERO;
        for (TransactionOutput out : spend15.getOutputs())
            outValue15 = outValue15.add(out.getValue());
        assertEquals(Utils.COIN.subtract(BigInteger.valueOf(2)), outValue15);

        SendRequest request16 = SendRequest.to(notMyAddr, CENT);
        request16.feePerKb = BigInteger.ZERO;
        for (int i = 0; i < 29; i++)
            request16.tx.addOutput(CENT, notMyAddr);
        assertTrue(request16.tx.bitcoinSerialize().length > 1000);
        assertTrue(wallet.completeTx(request16));
        // Of course the fee shouldn't be added if feePerKb == 0
        assertEquals(BigInteger.ZERO, request16.fee);
        Transaction spend16 = request16.tx;
        assertEquals(31, spend16.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        BigInteger outValue16 = BigInteger.ZERO;
        for (TransactionOutput out : spend16.getOutputs())
            outValue16 = outValue16.add(out.getValue());
        assertEquals(Utils.COIN, outValue16);

        // Create a transaction whose max size could be up to 999 (if signatures were maximum size)
        SendRequest request17 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 22; i++)
            request17.tx.addOutput(CENT, notMyAddr);
        request17.tx.addOutput(new TransactionOutput(params, request17.tx, CENT, new byte[15]));
        request17.feePerKb = BigInteger.ONE;
        assertTrue(wallet.completeTx(request17));
        assertEquals(BigInteger.ONE, request17.fee);
        assertEquals(1, request17.tx.getInputs().size());
        // Calculate its max length to make sure it is indeed 999
        int theoreticalMaxLength17 = request17.tx.bitcoinSerialize().length + myKey.getPubKey().length + 75;
        for (TransactionInput in : request17.tx.getInputs())
            theoreticalMaxLength17 -= in.getScriptBytes().length;
        assertEquals(999, theoreticalMaxLength17);
        Transaction spend17 = request17.tx;
        {
            // Its actual size must be between 996 and 999 (inclusive) as signatures have a 3-byte size range (almost always)
            final int length = spend17.bitcoinSerialize().length;
            assertTrue(Integer.toString(length), length >= 996 && length <= 999);
        }
        // Now check that it got a fee of 1 since its max size is 999 (1kb).
        assertEquals(25, spend17.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        BigInteger outValue17 = BigInteger.ZERO;
        for (TransactionOutput out : spend17.getOutputs())
            outValue17 = outValue17.add(out.getValue());
        assertEquals(Utils.COIN.subtract(BigInteger.ONE), outValue17);

        // Create a transaction who's max size could be up to 1001 (if signatures were maximum size)
        SendRequest request18 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 22; i++)
            request18.tx.addOutput(CENT, notMyAddr);
        request18.tx.addOutput(new TransactionOutput(params, request18.tx, CENT, new byte[17]));
        request18.feePerKb = BigInteger.ONE;
        assertTrue(wallet.completeTx(request18));
        assertEquals(BigInteger.valueOf(2), request18.fee);
        assertEquals(1, request18.tx.getInputs().size());
        // Calculate its max length to make sure it is indeed 1001
        Transaction spend18 = request18.tx;
        int theoreticalMaxLength18 = spend18.bitcoinSerialize().length + myKey.getPubKey().length + 75;
        for (TransactionInput in : spend18.getInputs())
            theoreticalMaxLength18 -= in.getScriptBytes().length;
        assertEquals(1001, theoreticalMaxLength18);
        // Its actual size must be between 998 and 1000 (inclusive) as signatures have a 3-byte size range (almost always)
        assertTrue(spend18.bitcoinSerialize().length >= 998);
        assertTrue(spend18.bitcoinSerialize().length <= 1001);
        // Now check that it did get a fee since its max size is 1000
        assertEquals(25, spend18.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        BigInteger outValue18 = BigInteger.ZERO;
        for (TransactionOutput out : spend18.getOutputs())
            outValue18 = outValue18.add(out.getValue());
        assertEquals(outValue18, Utils.COIN.subtract(BigInteger.valueOf(2)));

        // Now create a transaction that will spend COIN + fee, which makes it require both inputs
        assertEquals(wallet.getBalance(), CENT.add(Utils.COIN));
        SendRequest request19 = SendRequest.to(notMyAddr, CENT);
        request19.feePerKb = BigInteger.ZERO;
        for (int i = 0; i < 99; i++)
            request19.tx.addOutput(CENT, notMyAddr);
        // If we send now, we shouldn't need a fee and should only have to spend our COIN
        assertTrue(wallet.completeTx(request19));
        assertEquals(BigInteger.ZERO, request19.fee);
        assertEquals(1, request19.tx.getInputs().size());
        assertEquals(100, request19.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request19.tx.clearInputs();
        request19 = SendRequest.forTx(request19.tx);
        request19.feePerKb = BigInteger.ONE;
        assertTrue(wallet.completeTx(request19));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request19.fee);
        assertEquals(2, request19.tx.getInputs().size());
        BigInteger outValue19 = BigInteger.ZERO;
        for (TransactionOutput out : request19.tx.getOutputs())
            outValue19 = outValue19.add(out.getValue());
        // But now our change output is CENT-minfee, so we have to pay min fee
        // Change this assert when we eventually randomize output order
        assertEquals(request19.tx.getOutput(request19.tx.getOutputs().size() - 1).getValue(), CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));
        assertEquals(outValue19, Utils.COIN.add(CENT).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        // Create another transaction that will spend COIN + fee, which makes it require both inputs
        SendRequest request20 = SendRequest.to(notMyAddr, CENT);
        request20.feePerKb = BigInteger.ZERO;
        for (int i = 0; i < 99; i++)
            request20.tx.addOutput(CENT, notMyAddr);
        // If we send now, we shouldn't have a fee and should only have to spend our COIN
        assertTrue(wallet.completeTx(request20));
        assertEquals(BigInteger.ZERO, request20.fee);
        assertEquals(1, request20.tx.getInputs().size());
        assertEquals(100, request20.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request20.tx.clearInputs();
        request20 = SendRequest.forTx(request20.tx);
        request20.feePerKb = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;
        assertTrue(wallet.completeTx(request20));
        // 4kb tx.
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(BigInteger.valueOf(4)), request20.fee);
        assertEquals(2, request20.tx.getInputs().size());
        BigInteger outValue20 = BigInteger.ZERO;
        for (TransactionOutput out : request20.tx.getOutputs())
            outValue20 = outValue20.add(out.getValue());
        // This time the fee we wanted to pay was more, so that should be what we paid
        assertEquals(outValue20, Utils.COIN.add(CENT).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(BigInteger.valueOf(4))));

        // Same as request 19, but make the change 0 (so it doesnt force fee) and make us require min fee as a
        // result of an output < CENT.
        SendRequest request21 = SendRequest.to(notMyAddr, CENT);
        request21.feePerKb = BigInteger.ZERO;
        for (int i = 0; i < 99; i++)
            request21.tx.addOutput(CENT, notMyAddr);
        request21.tx.addOutput(CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), notMyAddr);
        // If we send without a feePerKb, we should still require REFERENCE_DEFAULT_MIN_TX_FEE because we have an output < 0.01
        assertTrue(wallet.completeTx(request21));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request21.fee);
        assertEquals(2, request21.tx.getInputs().size());
        BigInteger outValue21 = BigInteger.ZERO;
        for (TransactionOutput out : request21.tx.getOutputs())
            outValue21 = outValue21.add(out.getValue());
        assertEquals(outValue21, Utils.COIN.add(CENT).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        // Test feePerKb when we aren't using ensureMinRequiredFee
        // Same as request 19
        SendRequest request25 = SendRequest.to(notMyAddr, CENT);
        request25.feePerKb = BigInteger.ZERO;
        for (int i = 0; i < 70; i++)
            request25.tx.addOutput(CENT, notMyAddr);
        // If we send now, we shouldn't need a fee and should only have to spend our COIN
        assertTrue(wallet.completeTx(request25));
        assertEquals(BigInteger.ZERO, request25.fee);
        assertEquals(1, request25.tx.getInputs().size());
        assertEquals(72, request25.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request25.tx.clearInputs();
        request25 = SendRequest.forTx(request25.tx);
        request25.feePerKb = CENT.divide(BigInteger.valueOf(3));
        request25.ensureMinRequiredFee = false;
        assertTrue(wallet.completeTx(request25));
        assertEquals(CENT.subtract(BigInteger.ONE), request25.fee);
        assertEquals(2, request25.tx.getInputs().size());
        BigInteger outValue25 = BigInteger.ZERO;
        for (TransactionOutput out : request25.tx.getOutputs())
            outValue25 = outValue25.add(out.getValue());
        // Our change output should be one satoshi
        // Change this assert when we eventually randomize output order
        assertEquals(BigInteger.ONE, request25.tx.getOutput(request25.tx.getOutputs().size() - 1).getValue());
        // and our fee should be CENT-1 satoshi
        assertEquals(outValue25, Utils.COIN.add(BigInteger.ONE));

        // Spend our CENT output.
        Transaction spendTx5 = new Transaction(params);
        spendTx5.addOutput(CENT, notMyAddr);
        spendTx5.addInput(tx5.getOutput(0));
        spendTx5.signInputs(SigHash.ALL, wallet);
        wallet.receiveFromBlock(spendTx5, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 4);
        assertEquals(Utils.COIN, wallet.getBalance());

        // Ensure change is discarded if it results in a fee larger than the chain (same as 8 and 9 but with feePerKb)
        SendRequest request26 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 98; i++)
            request26.tx.addOutput(CENT, notMyAddr);
        request26.tx.addOutput(CENT.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)), notMyAddr);
        assertTrue(request26.tx.bitcoinSerialize().length > 1000);
        request26.feePerKb = BigInteger.ONE;
        assertTrue(wallet.completeTx(request26));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT), request26.fee);
        Transaction spend26 = request26.tx;
        // If a transaction is over 1kb, the set fee should be added
        assertEquals(100, spend26.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        BigInteger outValue26 = BigInteger.ZERO;
        for (TransactionOutput out : spend26.getOutputs())
            outValue26 = outValue26.add(out.getValue());
        assertEquals(outValue26, Utils.COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)));
    }

    @Test
    public void basicCategoryStepTest() throws Exception {
        // Creates spends that step through the possible fee solver categories
        SendRequest.DEFAULT_FEE_PER_KB = BigInteger.ZERO;
        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a ton of small outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        int i = 0;
        while (i <= CENT.divide(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).longValue()) {
            Transaction tx = createFakeTxWithChangeAddress(params, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, myAddress, notMyAddr);
            tx.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
            wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }

        // Create a spend that will throw away change (category 3 type 2 in which the change causes fee which is worth more than change)
        SendRequest request1 = SendRequest.to(notMyAddr, CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(BigInteger.ONE));
        assertTrue(wallet.completeTx(request1));
        assertEquals(BigInteger.ONE, request1.fee);
        assertEquals(request1.tx.getInputs().size(), i); // We should have spent all inputs

        // Give us one more input...
        Transaction tx1 = createFakeTxWithChangeAddress(params, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, myAddress, notMyAddr);
        tx1.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
        wallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);

        // ... and create a spend that will throw away change (category 3 type 1 in which the change causes dust output)
        SendRequest request2 = SendRequest.to(notMyAddr, CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(BigInteger.ONE));
        assertTrue(wallet.completeTx(request2));
        assertEquals(BigInteger.ONE, request2.fee);
        assertEquals(request2.tx.getInputs().size(), i - 1); // We should have spent all inputs - 1

        // Give us one more input...
        Transaction tx2 = createFakeTxWithChangeAddress(params, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, myAddress, notMyAddr);
        tx2.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);

        // ... and create a spend that will throw away change (category 3 type 1 in which the change causes dust output)
        // but that also could have been category 2 if it wanted
        SendRequest request3 = SendRequest.to(notMyAddr, CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(BigInteger.ONE));
        assertTrue(wallet.completeTx(request3));
        assertEquals(BigInteger.ONE, request3.fee);
        assertEquals(request3.tx.getInputs().size(), i - 2); // We should have spent all inputs - 2

        //
        SendRequest request4 = SendRequest.to(notMyAddr, CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(BigInteger.ONE));
        request4.feePerKb = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.divide(BigInteger.valueOf(request3.tx.bitcoinSerialize().length));
        assertTrue(wallet.completeTx(request4));
        assertEquals(BigInteger.ONE, request4.fee);
        assertEquals(request4.tx.getInputs().size(), i - 2); // We should have spent all inputs - 2

        // Give us a few more inputs...
        while (wallet.getBalance().compareTo(CENT.shiftLeft(1)) < 0) {
            Transaction tx3 = createFakeTxWithChangeAddress(params, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, myAddress, notMyAddr);
            tx3.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
            wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }

        // ...that is just slightly less than is needed for category 1
        SendRequest request5 = SendRequest.to(notMyAddr, CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(BigInteger.ONE));
        assertTrue(wallet.completeTx(request5));
        assertEquals(BigInteger.ONE, request5.fee);
        assertEquals(1, request5.tx.getOutputs().size()); // We should have no change output

        // Give us one more input...
        Transaction tx4 = createFakeTxWithChangeAddress(params, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, myAddress, notMyAddr);
        tx4.getInput(0).setSequenceNumber(i); // Keep every transaction unique
        wallet.receiveFromBlock(tx4, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);

        // ... that puts us in category 1 (no fee!)
        SendRequest request6 = SendRequest.to(notMyAddr, CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(BigInteger.ONE));
        assertTrue(wallet.completeTx(request6));
        assertEquals(BigInteger.ZERO, request6.fee);
        assertEquals(2, request6.tx.getOutputs().size()); // We should have a change output

        SendRequest.DEFAULT_FEE_PER_KB = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;
    }

    @Test
    public void testCategory2WithChange() throws Exception {
        // Specifically target case 2 with significant change

        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a ton of small outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        int i = 0;
        while (i <= CENT.divide(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(BigInteger.TEN)).longValue()) {
            Transaction tx = createFakeTxWithChangeAddress(params, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(BigInteger.TEN), myAddress, notMyAddr);
            tx.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
            wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }

        // The selector will choose 2 with MIN_TX_FEE fee
        SendRequest request1 = SendRequest.to(notMyAddr, CENT.add(BigInteger.ONE));
        assertTrue(wallet.completeTx(request1));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request1.fee);
        assertEquals(request1.tx.getInputs().size(), i); // We should have spent all inputs
        assertEquals(2, request1.tx.getOutputs().size()); // and gotten change back
    }

    @Test
    public void feePerKbCategoryJumpTest() throws Exception {
        // Simple test of boundary condition on fee per kb in category fee solver

        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a ton of small outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(params, Utils.COIN, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        Transaction tx2 = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        Transaction tx3 = createFakeTx(params, BigInteger.ONE, myAddress);
        wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 2);

        // Create a transaction who's max size could be up to 1000 (if signatures were maximum size)
        SendRequest request1 = SendRequest.to(notMyAddr, Utils.COIN.subtract(CENT.multiply(BigInteger.valueOf(17))));
        for (int i = 0; i < 16; i++)
            request1.tx.addOutput(CENT, notMyAddr);
        request1.tx.addOutput(new TransactionOutput(params, request1.tx, CENT, new byte[16]));
        request1.fee = BigInteger.ONE;
        request1.feePerKb = BigInteger.ONE;
        // We get a category 2 using COIN+CENT
        // It spends COIN + 1(fee) and because its output is thus < CENT, we have to pay MIN_TX_FEE
        // When it tries category 1, its too large and requires COIN + 2 (fee)
        // This adds the next input, but still has a < CENT output which means it cant reach category 1
        assertTrue(wallet.completeTx(request1));
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request1.fee);
        assertEquals(2, request1.tx.getInputs().size());

        // We then add one more satoshi output to the wallet
        Transaction tx4 = createFakeTx(params, BigInteger.ONE, myAddress);
        wallet.receiveFromBlock(tx4, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 3);

        // Create a transaction who's max size could be up to 1000 (if signatures were maximum size)
        SendRequest request2 = SendRequest.to(notMyAddr, Utils.COIN.subtract(CENT.multiply(BigInteger.valueOf(17))));
        for (int i = 0; i < 16; i++)
            request2.tx.addOutput(CENT, notMyAddr);
        request2.tx.addOutput(new TransactionOutput(params, request2.tx, CENT, new byte[16]));
        request2.feePerKb = BigInteger.ONE;
        // The process is the same as above, but now we can complete category 1 with one more input, and pay a fee of 2
        assertTrue(wallet.completeTx(request2));
        assertEquals(BigInteger.valueOf(2), request2.fee);
        assertEquals(4, request2.tx.getInputs().size());
    }

    @Test
    public void testCompleteTxWithExistingInputs() throws Exception {
        // Tests calling completeTx with a SendRequest that already has a few inputs in it
        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a few outputs to us
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx1 = createFakeTx(params, Utils.COIN, myAddress);
        wallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        Transaction tx2 = createFakeTx(params, Utils.COIN, myAddress); assertTrue(!tx1.getHash().equals(tx2.getHash()));
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        Transaction tx3 = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 2);

        SendRequest request1 = SendRequest.to(notMyAddr, CENT);
        // If we just complete as-is, we will use one of the COIN outputs to get higher priority,
        // resulting in a change output
        assertNotNull(wallet.completeTx(request1));
        assertEquals(1, request1.tx.getInputs().size());
        assertEquals(2, request1.tx.getOutputs().size());
        assertEquals(CENT, request1.tx.getOutput(0).getValue());
        assertEquals(Utils.COIN.subtract(CENT), request1.tx.getOutput(1).getValue());

        // Now create an identical request2 and add an unsigned spend of the CENT output
        SendRequest request2 = SendRequest.to(notMyAddr, CENT);
        request2.tx.addInput(tx3.getOutput(0));
        // Now completeTx will result in one input, one output
        assertTrue(wallet.completeTx(request2));
        assertEquals(1, request2.tx.getInputs().size());
        assertEquals(1, request2.tx.getOutputs().size());
        assertEquals(CENT, request2.tx.getOutput(0).getValue());
        // Make sure it was properly signed
        request2.tx.getInput(0).getScriptSig().correctlySpends(request2.tx, 0, tx3.getOutput(0).getScriptPubKey(), true);

        // However, if there is no connected output, we will grab a COIN output anyway and add the CENT to fee
        SendRequest request3 = SendRequest.to(notMyAddr, CENT);
        request3.tx.addInput(new TransactionInput(params, request3.tx, new byte[]{}, new TransactionOutPoint(params, 0, tx3.getHash())));
        // Now completeTx will result in two inputs, two outputs and a fee of a CENT
        // Note that it is simply assumed that the inputs are correctly signed, though in fact the first is not
        assertTrue(wallet.completeTx(request3));
        assertEquals(2, request3.tx.getInputs().size());
        assertEquals(2, request3.tx.getOutputs().size());
        assertEquals(CENT, request3.tx.getOutput(0).getValue());
        assertEquals(Utils.COIN.subtract(CENT), request3.tx.getOutput(1).getValue());

        SendRequest request4 = SendRequest.to(notMyAddr, CENT);
        request4.tx.addInput(tx3.getOutput(0));
        // Now if we manually sign it, completeTx will not replace our signature
        request4.tx.signInputs(SigHash.ALL, wallet);
        byte[] scriptSig = request4.tx.getInput(0).getScriptBytes();
        assertTrue(wallet.completeTx(request4));
        assertEquals(1, request4.tx.getInputs().size());
        assertEquals(1, request4.tx.getOutputs().size());
        assertEquals(CENT, request4.tx.getOutput(0).getValue());
        assertArrayEquals(scriptSig, request4.tx.getInput(0).getScriptBytes());
    }

    // There is a test for spending a coinbase transaction as it matures in BlockChainTest#coinbaseTransactionAvailability

    // Support for offline spending is tested in PeerGroupTest

    @Test
    public void exceptionsDoNotBlockAllListeners() throws Exception {
        // Check that if a wallet listener throws an exception, the others still run.
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                throw new RuntimeException("barf");
            }
        });
        final AtomicInteger flag = new AtomicInteger();
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                flag.incrementAndGet();
            }
        });

        sendMoneyToWallet(Utils.toNanoCoins(1, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(1, flag.get());
    }

    @Test
    public void testEmptyRandomWallet() throws Exception {
        // Add a random set of outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, new ECKey().toAddress(params)), BigInteger.ONE, 1);
        Random rng = new Random();
        for (int i = 0; i < rng.nextInt(100) + 1; i++) {
            Transaction tx = createFakeTx(params, BigInteger.valueOf(rng.nextInt((int) Utils.COIN.longValue())), myAddress);
            wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }
        SendRequest request = SendRequest.emptyWallet(new ECKey().toAddress(params));
        assertTrue(wallet.completeTx(request));
        wallet.commitTx(request.tx);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
    }

    @Test
    public void testEmptyWallet() throws Exception {
        Address outputKey = new ECKey().toAddress(params);
        // Add exactly 0.01
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, outputKey), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        SendRequest request = SendRequest.emptyWallet(outputKey);
        assertTrue(wallet.completeTx(request));
        wallet.commitTx(request.tx);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertEquals(CENT, request.tx.getOutput(0).getValue());

        // Add 1 confirmed cent and 1 unconfirmed cent. Verify only one cent is emptied because of the coin selection
        // policies that are in use by default.
        block = new StoredBlock(makeSolvedTestBlock(blockStore, outputKey), BigInteger.ONE, 1);
        tx = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        tx = createFakeTx(params, CENT, myAddress);
        wallet.receivePending(tx, null);
        request = SendRequest.emptyWallet(outputKey);
        assertTrue(wallet.completeTx(request));
        wallet.commitTx(request.tx);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertEquals(CENT, request.tx.getOutput(0).getValue());

        // Add just under 0.01
        StoredBlock block2 = new StoredBlock(block.getHeader().createNextBlock(outputKey), BigInteger.ONE, 2);
        tx = createFakeTx(params, CENT.subtract(BigInteger.ONE), myAddress);
        wallet.receiveFromBlock(tx, block2, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        request = SendRequest.emptyWallet(outputKey);
        assertTrue(wallet.completeTx(request));
        wallet.commitTx(request.tx);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertEquals(CENT.subtract(BigInteger.ONE).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), request.tx.getOutput(0).getValue());

        // Add an unsendable value
        StoredBlock block3 = new StoredBlock(block2.getHeader().createNextBlock(outputKey), BigInteger.ONE, 3);
        BigInteger outputValue = Transaction.MIN_NONDUST_OUTPUT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(BigInteger.ONE);
        tx = createFakeTx(params, outputValue, myAddress);
        wallet.receiveFromBlock(tx, block3, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        request = SendRequest.emptyWallet(outputKey);
        assertFalse(wallet.completeTx(request));
        request.ensureMinRequiredFee = false;
        assertTrue(wallet.completeTx(request));
        wallet.commitTx(request.tx);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        assertEquals(outputValue, request.tx.getOutput(0).getValue());
    }

    @Test
    public void keyRotation() throws Exception {
        // Watch out for wallet-initiated broadcasts.
        MockTransactionBroadcaster broadcaster = new MockTransactionBroadcaster(wallet);
        wallet.setTransactionBroadcaster(broadcaster);
        wallet.setKeyRotationEnabled(true);
        // Send three cents to two different keys, then add a key and mark the initial keys as compromised.
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();
        wallet.addKey(key1);
        wallet.addKey(key2);
        sendMoneyToWallet(wallet, CENT, key1.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(wallet, CENT, key2.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(wallet, CENT, key2.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Utils.rollMockClock(86400);
        Date compromiseTime = Utils.now();
        assertEquals(0, broadcaster.broadcasts.size());
        assertFalse(wallet.isKeyRotating(key1));

        // Rotate the wallet.
        ECKey key3 = new ECKey();
        wallet.addKey(key3);
        // We see a broadcast triggered by setting the rotation time.
        wallet.setKeyRotationTime(compromiseTime);
        assertTrue(wallet.isKeyRotating(key1));
        Transaction tx = broadcaster.broadcasts.take();
        final BigInteger THREE_CENTS = CENT.add(CENT).add(CENT);
        assertEquals(THREE_CENTS, tx.getValueSentFromMe(wallet));
        assertEquals(THREE_CENTS.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), tx.getValueSentToMe(wallet));
        // TX is a raw pay to pubkey.
        assertArrayEquals(key3.getPubKey(), tx.getOutput(0).getScriptPubKey().getPubKey());
        assertEquals(3, tx.getInputs().size());
        // It confirms.
        sendMoneyToWallet(tx, AbstractBlockChain.NewBlockType.BEST_CHAIN);

        // Now receive some more money to key3 (secure) via a new block and check that nothing happens.
        sendMoneyToWallet(wallet, CENT, key3.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertTrue(broadcaster.broadcasts.isEmpty());

        // Receive money via a new block on key1 and ensure it's immediately moved.
        sendMoneyToWallet(wallet, CENT, key1.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        tx = broadcaster.broadcasts.take();
        assertArrayEquals(key3.getPubKey(), tx.getOutput(0).getScriptPubKey().getPubKey());
        assertEquals(1, tx.getInputs().size());
        assertEquals(1, tx.getOutputs().size());
        assertEquals(CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), tx.getOutput(0).getValue());

        assertEquals(Transaction.Purpose.KEY_ROTATION, tx.getPurpose());

        // We don't attempt to race an attacker against unconfirmed transactions.

        // Now round-trip the wallet and check the protobufs are storing the data correctly.
        Protos.Wallet protos = new WalletProtobufSerializer().walletToProto(wallet);
        wallet = new Wallet(params);
        new WalletProtobufSerializer().readWallet(protos, wallet);

        tx = wallet.getTransaction(tx.getHash());
        assertEquals(Transaction.Purpose.KEY_ROTATION, tx.getPurpose());
        // Have to divide here to avoid mismatch due to second-level precision in serialisation.
        assertEquals(compromiseTime.getTime() / 1000, wallet.getKeyRotationTime().getTime() / 1000);

        // Make a normal spend and check it's all ok.
        final Address address = new ECKey().toAddress(params);
        wallet.sendCoins(broadcaster, address, wallet.getBalance());
        tx = broadcaster.broadcasts.take();
        assertArrayEquals(address.getHash160(), tx.getOutput(0).getScriptPubKey().getPubKeyHash());
        // We have to race here because we're checking for the ABSENCE of a broadcast, and if there were to be one,
        // it'd be happening in parallel.
        assertEquals(null, broadcaster.broadcasts.poll(1, TimeUnit.SECONDS));
    }

    @Test
    public void fragmentedReKeying() throws Exception {
        // Send lots of small coins and check the fee is correct.
        ECKey key = new ECKey();
        wallet.addKey(key);
        Address address = key.toAddress(params);
        Utils.rollMockClock(86400);
        for (int i = 0; i < 800; i++) {
            sendMoneyToWallet(wallet, Utils.CENT, address, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        }

        MockTransactionBroadcaster broadcaster = new MockTransactionBroadcaster(wallet);
        wallet.setTransactionBroadcaster(broadcaster);
        wallet.setKeyRotationEnabled(true);

        Date compromise = Utils.now();
        Utils.rollMockClock(86400);
        wallet.addKey(new ECKey());
        wallet.setKeyRotationTime(compromise);

        Transaction tx = broadcaster.broadcasts.take();
        final BigInteger valueSentToMe = tx.getValueSentToMe(wallet);
        BigInteger fee = tx.getValueSentFromMe(wallet).subtract(valueSentToMe);
        assertEquals(BigInteger.valueOf(900000), fee);
        assertEquals(KeyTimeCoinSelector.MAX_SIMULTANEOUS_INPUTS, tx.getInputs().size());
        assertEquals(BigInteger.valueOf(599100000), valueSentToMe);

        tx = broadcaster.broadcasts.take();
        assertNotNull(tx);
        assertEquals(200, tx.getInputs().size());
    }
}
