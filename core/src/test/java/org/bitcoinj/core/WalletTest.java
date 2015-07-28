/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.core;

import org.bitcoinj.core.Wallet.SendRequest;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.signers.StatelessTransactionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.store.UnreadableWalletException;
import org.bitcoinj.store.WalletProtobufSerializer;
import org.bitcoinj.testing.*;
import org.bitcoinj.utils.ExchangeRate;
import org.bitcoinj.utils.Fiat;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.*;
import org.bitcoinj.wallet.WalletTransaction.Pool;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.bitcoinj.core.Coin.*;
import static org.bitcoinj.core.Utils.HEX;
import static org.bitcoinj.testing.FakeTxBuilder.*;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class WalletTest extends TestWithWallet {
    private static final Logger log = LoggerFactory.getLogger(WalletTest.class);

    private static final CharSequence PASSWORD1 = "my helicopter contains eels";
    private static final CharSequence WRONG_PASSWORD = "nothing noone nobody nowhere";

    private SecureRandom secureRandom = new SecureRandom();

    private ECKey someOtherKey = new ECKey();
    private Address someOtherAddress = someOtherKey.toAddress(params);

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    private void createMarriedWallet(int threshold, int numKeys) throws BlockStoreException {
        createMarriedWallet(threshold, numKeys, true);
    }

    private void createMarriedWallet(int threshold, int numKeys, boolean addSigners) throws BlockStoreException {
        wallet = new Wallet(params);
        blockStore = new MemoryBlockStore(params);
        chain = new BlockChain(params, wallet, blockStore);

        List<DeterministicKey> followingKeys = Lists.newArrayList();
        for (int i = 0; i < numKeys - 1; i++) {
            final DeterministicKeyChain keyChain = new DeterministicKeyChain(new SecureRandom());
            DeterministicKey partnerKey = DeterministicKey.deserializeB58(null, keyChain.getWatchingKey().serializePubB58(params), params);
            followingKeys.add(partnerKey);
            if (addSigners && i < threshold - 1)
                wallet.addTransactionSigner(new KeyChainTransactionSigner(keyChain));
        }

        MarriedKeyChain chain = MarriedKeyChain.builder()
                .random(new SecureRandom())
                .followingKeys(followingKeys)
                .threshold(threshold).build();
        wallet.addAndActivateHDChain(chain);
    }

    @Test
    public void getSeedAsWords1() {
        // Can't verify much here as the wallet is random each time. We could fix the RNG for the unit tests and solve.
        assertEquals(12, wallet.getKeyChainSeed().getMnemonicCode().size());
    }

    @Test
    public void checkSeed() throws MnemonicException {
        wallet.getKeyChainSeed().check();
    }

    @Test
    public void basicSpending() throws Exception {
        basicSpendingCommon(wallet, myAddress, new ECKey().toAddress(params), null);
    }

    @Test
    public void basicSpendingToP2SH() throws Exception {
        Address destination = new Address(params, params.getP2SHHeader(), HEX.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        basicSpendingCommon(wallet, myAddress, destination, null);
    }

    @Test
    public void basicSpendingWithEncryptedWallet() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);
        Address myEncryptedAddress = encryptedWallet.freshReceiveKey().toAddress(params);
        basicSpendingCommon(encryptedWallet, myEncryptedAddress, new ECKey().toAddress(params), encryptedWallet);
    }

    @Test
    public void basicSpendingFromP2SH() throws Exception {
        createMarriedWallet(2, 2);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        basicSpendingCommon(wallet, myAddress, new ECKey().toAddress(params), null);

        createMarriedWallet(2, 3);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        basicSpendingCommon(wallet, myAddress, new ECKey().toAddress(params), null);

        createMarriedWallet(3, 3);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        basicSpendingCommon(wallet, myAddress, new ECKey().toAddress(params), null);
    }

    @Test (expected = IllegalArgumentException.class)
    public void thresholdShouldNotExceedNumberOfKeys() throws Exception {
        createMarriedWallet(3, 2);
    }

    @Test
    public void spendingWithIncompatibleSigners() throws Exception {
        wallet.addTransactionSigner(new NopTransactionSigner(true));
        basicSpendingCommon(wallet, myAddress, new ECKey().toAddress(params), null);
    }

    static class TestRiskAnalysis implements RiskAnalysis {
        private final boolean risky;

        public TestRiskAnalysis(boolean risky) {
            this.risky = risky;
        }

        @Override
        public Result analyze() {
            return risky ? Result.NON_FINAL : Result.OK;
        }

        public static class Analyzer implements RiskAnalysis.Analyzer {
            private final Transaction riskyTx;

            Analyzer(Transaction riskyTx) {
                this.riskyTx = riskyTx;
            }

            @Override
            public RiskAnalysis create(Wallet wallet, Transaction tx, List<Transaction> dependencies) {
                return new TestRiskAnalysis(tx == riskyTx);
            }
        }
    }

    static class TestCoinSelector extends DefaultCoinSelector {
        @Override
        protected boolean shouldSelect(Transaction tx) {
            return true;
        }
    }

    private Transaction cleanupCommon(Address destination) throws Exception {
        receiveATransaction(wallet, myAddress);

        Coin v2 = valueOf(0, 50);
        SendRequest req = SendRequest.to(destination, v2);
        req.fee = CENT;
        wallet.completeTx(req);

        Transaction t2 = req.tx;

        // Broadcast the transaction and commit.
        broadcastAndCommit(wallet, t2);

        // At this point we have one pending and one spent

        Coin v1 = valueOf(0, 10);
        Transaction t = sendMoneyToWallet(wallet, v1, myAddress, null);
        Threading.waitForUserCode();
        sendMoneyToWallet(wallet, t, null);
        assertEquals("Wrong number of PENDING.4", 2, wallet.getPoolSize(Pool.PENDING));
        assertEquals("Wrong number of UNSPENT.4", 0, wallet.getPoolSize(Pool.UNSPENT));
        assertEquals("Wrong number of ALL.4", 3, wallet.getTransactions(true).size());
        assertEquals(valueOf(0, 59), wallet.getBalance(Wallet.BalanceType.ESTIMATED));

        // Now we have another incoming pending
        return t;
    }

    @Test
    public void cleanup() throws Exception {
        Address destination = new ECKey().toAddress(params);
        Transaction t = cleanupCommon(destination);

        // Consider the new pending as risky and remove it from the wallet
        wallet.setRiskAnalyzer(new TestRiskAnalysis.Analyzer(t));

        wallet.cleanup();
        assertTrue(wallet.isConsistent());
        assertEquals("Wrong number of PENDING.5", 1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals("Wrong number of UNSPENT.5", 0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL.5", 2, wallet.getTransactions(true).size());
        assertEquals(valueOf(0, 49), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void cleanupFailsDueToSpend() throws Exception {
        Address destination = new ECKey().toAddress(params);
        Transaction t = cleanupCommon(destination);

        // Now we have another incoming pending.  Spend everything.
        Coin v3 = valueOf(0, 58);
        SendRequest req = SendRequest.to(destination, v3);

        // Force selection of the incoming coin so that we can spend it
        req.coinSelector = new TestCoinSelector();

        req.fee = CENT;
        wallet.completeTx(req);
        wallet.commitTx(req.tx);

        assertEquals("Wrong number of PENDING.5", 3, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals("Wrong number of UNSPENT.5", 0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL.5", 4, wallet.getTransactions(true).size());

        // Consider the new pending as risky and try to remove it from the wallet
        wallet.setRiskAnalyzer(new TestRiskAnalysis.Analyzer(t));

        wallet.cleanup();
        assertTrue(wallet.isConsistent());

        // The removal should have failed
        assertEquals("Wrong number of PENDING.5", 3, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals("Wrong number of UNSPENT.5", 0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL.5", 4, wallet.getTransactions(true).size());
        assertEquals(ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    private void basicSpendingCommon(Wallet wallet, Address toAddress, Address destination, Wallet encryptedWallet) throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change. We
        // will attach a small fee. Because the Bitcoin protocol makes it difficult to determine the fee of an
        // arbitrary transaction in isolation, we'll check that the fee was set by examining the size of the change.

        // Receive some money as a pending transaction.
        receiveATransaction(wallet, toAddress);

        // Try to send too much and fail.
        Coin vHuge = valueOf(10, 0);
        Wallet.SendRequest req = Wallet.SendRequest.to(destination, vHuge);
        try {
            wallet.completeTx(req);
            fail();
        } catch (InsufficientMoneyException e) {
            assertEquals(valueOf(9, 0), e.missing);
        }

        // Prepare to send.
        Coin v2 = valueOf(0, 50);
        req = Wallet.SendRequest.to(destination, v2);
        req.fee = CENT;

        if (encryptedWallet != null) {
            KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
            KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);
            KeyParameter wrongAesKey = keyCrypter.deriveKey(WRONG_PASSWORD);

            // Try to create a send with a fee but no password (this should fail).
            try {
                req.ensureMinRequiredFee = false;
                wallet.completeTx(req);
                fail();
            } catch (ECKey.MissingPrivateKeyException kce) {
            }
            assertEquals("Wrong number of UNSPENT.1", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
            assertEquals("Wrong number of ALL.1", 1, wallet.getTransactions(true).size());

            // Try to create a send with a fee but the wrong password (this should fail).
            req = Wallet.SendRequest.to(destination, v2);
            req.aesKey = wrongAesKey;
            req.fee = CENT;
            req.ensureMinRequiredFee = false;

            try {
                wallet.completeTx(req);
                fail("No exception was thrown trying to sign an encrypted key with the wrong password supplied.");
            } catch (KeyCrypterException kce) {
                assertEquals("Could not decrypt bytes", kce.getMessage());
            }

            assertEquals("Wrong number of UNSPENT.2", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
            assertEquals("Wrong number of ALL.2", 1, wallet.getTransactions(true).size());

            // Create a send with a fee with the correct password (this should succeed).
            req = Wallet.SendRequest.to(destination, v2);
            req.aesKey = aesKey;
            req.fee = CENT;
            req.ensureMinRequiredFee = false;
        }

        // Complete the transaction successfully.
        req.shuffleOutputs = false;
        wallet.completeTx(req);

        Transaction t2 = req.tx;
        assertEquals("Wrong number of UNSPENT.3", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL.3", 1, wallet.getTransactions(true).size());
        assertEquals(TransactionConfidence.Source.SELF, t2.getConfidence().getSource());
        assertEquals(Transaction.Purpose.USER_PAYMENT, t2.getPurpose());

        // Do some basic sanity checks.
        basicSanityChecks(wallet, t2, destination);

        // Broadcast the transaction and commit.
        List<TransactionOutput> unspents1 = wallet.getUnspents();
        assertEquals(1, unspents1.size());
        broadcastAndCommit(wallet, t2);
        List<TransactionOutput> unspents2 = wallet.getUnspents();
        assertNotEquals(unspents1, unspents2.size());

        // Now check that we can spend the unconfirmed change, with a new change address of our own selection.
        // (req.aesKey is null for unencrypted / the correct aesKey for encrypted.)
        wallet = spendUnconfirmedChange(wallet, t2, req.aesKey);
        assertNotEquals(unspents2, wallet.getUnspents());
    }

    private void receiveATransaction(Wallet wallet, Address toAddress) throws Exception {
        receiveATransactionAmount(wallet, toAddress, COIN);
    }

    private void receiveATransactionAmount(Wallet wallet, Address toAddress, Coin amount) {
        final ListenableFuture<Coin> availFuture = wallet.getBalanceFuture(amount, Wallet.BalanceType.AVAILABLE);
        final ListenableFuture<Coin> estimatedFuture = wallet.getBalanceFuture(amount, Wallet.BalanceType.ESTIMATED);
        assertFalse(availFuture.isDone());
        assertFalse(estimatedFuture.isDone());
        // Send some pending coins to the wallet.
        Transaction t1 = sendMoneyToWallet(wallet, amount, toAddress, null);
        Threading.waitForUserCode();
        final ListenableFuture<TransactionConfidence> depthFuture = t1.getConfidence().getDepthFuture(1);
        assertFalse(depthFuture.isDone());
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(amount, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertFalse(availFuture.isDone());
        // Our estimated balance has reached the requested level.
        assertTrue(estimatedFuture.isDone());
        assertEquals(1, wallet.getPoolSize(Pool.PENDING));
        assertEquals(0, wallet.getPoolSize(Pool.UNSPENT));
        // Confirm the coins.
        sendMoneyToWallet(wallet, t1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals("Incorrect confirmed tx balance", amount, wallet.getBalance());
        assertEquals("Incorrect confirmed tx PENDING pool size", 0, wallet.getPoolSize(Pool.PENDING));
        assertEquals("Incorrect confirmed tx UNSPENT pool size", 1, wallet.getPoolSize(Pool.UNSPENT));
        assertEquals("Incorrect confirmed tx ALL pool size", 1, wallet.getTransactions(true).size());
        Threading.waitForUserCode();
        assertTrue(availFuture.isDone());
        assertTrue(estimatedFuture.isDone());
        assertTrue(depthFuture.isDone());
    }

    private void basicSanityChecks(Wallet wallet, Transaction t, Address destination) throws VerificationException {
        assertEquals("Wrong number of tx inputs", 1, t.getInputs().size());
        assertEquals("Wrong number of tx outputs",2, t.getOutputs().size());
        assertEquals(destination, t.getOutput(0).getScriptPubKey().getToAddress(params));
        assertEquals(wallet.getChangeAddress(), t.getOutputs().get(1).getScriptPubKey().getToAddress(params));
        assertEquals(valueOf(0, 49), t.getOutputs().get(1).getValue());
        // Check the script runs and signatures verify.
        t.getInputs().get(0).verify();
    }

    private static void broadcastAndCommit(Wallet wallet, Transaction t) throws Exception {
        final LinkedList<Transaction> txns = Lists.newLinkedList();
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                txns.add(tx);
            }
        });

        t.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByAddress(new byte[]{1,2,3,4})));
        t.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByAddress(new byte[]{10,2,3,4})));
        wallet.commitTx(t);
        Threading.waitForUserCode();
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.SPENT));
        assertEquals(2, wallet.getTransactions(true).size());
        assertEquals(t, txns.getFirst());
        assertEquals(1, txns.size());
    }

    private Wallet spendUnconfirmedChange(Wallet wallet, Transaction t2, KeyParameter aesKey) throws Exception {
        if (wallet.getTransactionSigners().size() == 1)   // don't bother reconfiguring the p2sh wallet
            wallet = roundTrip(wallet);
        Coin v3 = valueOf(0, 49);
        assertEquals(v3, wallet.getBalance());
        Wallet.SendRequest req = Wallet.SendRequest.to(new ECKey().toAddress(params), valueOf(0, 48));
        req.aesKey = aesKey;
        req.ensureMinRequiredFee = false;
        req.shuffleOutputs = false;
        wallet.completeTx(req);
        Transaction t3 = req.tx;
        assertNotEquals(t2.getOutput(1).getScriptPubKey().getToAddress(params),
                        t3.getOutput(1).getScriptPubKey().getToAddress(params));
        assertNotNull(t3);
        wallet.commitTx(t3);
        assertTrue(wallet.isConsistent());
        // t2 and t3 gets confirmed in the same block.
        BlockPair bp = createFakeBlock(blockStore, t2, t3);
        wallet.receiveFromBlock(t2, bp.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        wallet.receiveFromBlock(t3, bp.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        wallet.notifyNewBestBlock(bp.storedBlock);
        assertTrue(wallet.isConsistent());
        return wallet;
    }

    @Test
    @SuppressWarnings("deprecation")
    // Having a test for deprecated method getFromAddress() is no evil so we suppress the warning here.
    public void customTransactionSpending() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        Coin v1 = valueOf(3, 0);
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());

        ECKey k2 = new ECKey();
        Address a2 = k2.toAddress(params);
        Coin v2 = valueOf(0, 50);
        Coin v3 = valueOf(0, 75);
        Coin v4 = valueOf(1, 25);

        Transaction t2 = new Transaction(params);
        t2.addOutput(v2, a2);
        t2.addOutput(v3, a2);
        t2.addOutput(v4, a2);
        SendRequest req = SendRequest.forTx(t2);
        req.ensureMinRequiredFee = false;
        wallet.completeTx(req);

        // Do some basic sanity checks.
        assertEquals(1, t2.getInputs().size());
        assertEquals(myAddress, t2.getInput(0).getScriptSig().getFromAddress(params));
        assertEquals(TransactionConfidence.ConfidenceType.UNKNOWN, t2.getConfidence().getConfidenceType());

        // We have NOT proven that the signature is correct!
        wallet.commitTx(t2);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.SPENT));
        assertEquals(2, wallet.getTransactions(true).size());
    }

    @Test
    public void sideChain() throws Exception {
        // The wallet receives a coin on the main chain, then on a side chain. Balance is equal to both added together
        // as we assume the side chain tx is pending and will be included shortly.
        Coin v1 = COIN;
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());

        Coin v2 = valueOf(0, 50);
        sendMoneyToWallet(v2, AbstractBlockChain.NewBlockType.SIDE_CHAIN);
        assertEquals(2, wallet.getTransactions(true).size());
        assertEquals(v1, wallet.getBalance());
        assertEquals(v1.add(v2), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void balance() throws Exception {
        // Receive 5 coins then half a coin.
        Coin v1 = valueOf(5, 0);
        Coin v2 = valueOf(0, 50);
        Coin expected = valueOf(5, 50);
        assertEquals(0, wallet.getTransactions(true).size());
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        sendMoneyToWallet(v2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(expected, wallet.getBalance());

        // Now spend one coin.
        Coin v3 = COIN;
        Transaction spend = wallet.createSend(new ECKey().toAddress(params), v3);
        wallet.commitTx(spend);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));

        // Available and estimated balances should not be the same. We don't check the exact available balance here
        // because it depends on the coin selection algorithm.
        assertEquals(valueOf(4, 50), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertFalse(wallet.getBalance(Wallet.BalanceType.AVAILABLE).equals(
                    wallet.getBalance(Wallet.BalanceType.ESTIMATED)));

        // Now confirm the transaction by including it into a block.
        StoredBlock b3 = createFakeBlock(blockStore, spend).storedBlock;
        wallet.receiveFromBlock(spend, b3, BlockChain.NewBlockType.BEST_CHAIN, 0);

        // Change is confirmed. We started with 5.50 so we should have 4.50 left.
        Coin v4 = valueOf(4, 50);
        assertEquals(v4, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
    }

    // Intuitively you'd expect to be able to create a transaction with identical inputs and outputs and get an
    // identical result to the official client. However the signatures are not deterministic - signing the same data
    // with the same key twice gives two different outputs. So we cannot prove bit-for-bit compatibility in this test
    // suite.

    @Test
    public void blockChainCatchup() throws Exception {
        // Test that we correctly process transactions arriving from the chain, with callbacks for inbound and outbound.
        final Coin[] bigints = new Coin[4];
        final Transaction[] txn = new Transaction[2];
        final LinkedList<Transaction> confTxns = new LinkedList<Transaction>();
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                super.onCoinsReceived(wallet, tx, prevBalance, newBalance);
                bigints[0] = prevBalance;
                bigints[1] = newBalance;
                txn[0] = tx;
            }

            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
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
        Coin oneCoin = COIN;
        Transaction tx1 = sendMoneyToWallet(oneCoin, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(null, txn[1]);  // onCoinsSent not called.
        assertEquals(tx1, confTxns.getFirst());   // onTransactionConfidenceChanged called
        assertEquals(txn[0].getHash(), tx1.getHash());
        assertEquals(ZERO, bigints[0]);
        assertEquals(oneCoin, bigints[1]);
        assertEquals(TransactionConfidence.ConfidenceType.BUILDING, tx1.getConfidence().getConfidenceType());
        assertEquals(1, tx1.getConfidence().getAppearedAtChainHeight());
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), valueOf(0, 10));
        // Pretend it makes it into the block chain, our wallet state is cleared but we still have the keys, and we
        // want to get back to our previous state. We can do this by just not confirming the transaction as
        // createSend is stateless.
        txn[0] = txn[1] = null;
        confTxns.clear();
        sendMoneyToWallet(send1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(Coin.valueOf(0, 90), wallet.getBalance());
        assertEquals(null, txn[0]);
        assertEquals(2, confTxns.size());
        assertEquals(txn[1].getHash(), send1.getHash());
        assertEquals(Coin.COIN, bigints[2]);
        assertEquals(Coin.valueOf(0, 90), bigints[3]);
        // And we do it again after the catchup.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), valueOf(0, 10));
        // What we'd really like to do is prove the official client would accept it .... no such luck unfortunately.
        wallet.commitTx(send2);
        sendMoneyToWallet(send2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(Coin.valueOf(0, 80), wallet.getBalance());
        Threading.waitForUserCode();
        BlockPair b4 = createFakeBlock(blockStore);
        confTxns.clear();
        wallet.notifyNewBestBlock(b4.storedBlock);
        Threading.waitForUserCode();
        assertEquals(3, confTxns.size());
    }

    @Test
    public void balances() throws Exception {
        Coin nanos = COIN;
        Transaction tx1 = sendMoneyToWallet(nanos, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(nanos, tx1.getValueSentToMe(wallet, true));
        assertTrue(tx1.getWalletOutputs(wallet).size() >= 1);
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), valueOf(0, 10));
        // Reserialize.
        Transaction send2 = new Transaction(params, send1.bitcoinSerialize());
        assertEquals(nanos, send2.getValueSentFromMe(wallet));
        assertEquals(ZERO.subtract(valueOf(0, 10)), send2.getValue(wallet));
    }

    @Test
    public void isConsistent_duplicates() throws Exception {
        // This test ensures that isConsistent catches duplicate transactions, eg, because we submitted the same block
        // twice (this is not allowed).
        Transaction tx = createFakeTx(params, COIN, myAddress);
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, valueOf(0, 5), someOtherGuy);
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
        Transaction tx = createFakeTx(params, COIN, myAddress);
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, valueOf(0, 5), someOtherGuy);
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
        Transaction tx = createFakeTx(params, COIN, myAddress);
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, valueOf(0, 5), someOtherGuy);
        tx.addOutput(output);
        assertTrue(wallet.isConsistent());

        wallet.addWalletTransaction(new WalletTransaction(Pool.SPENT, tx));
        assertFalse(wallet.isConsistent());
    }

    @Test
    public void transactions() throws Exception {
        // This test covers a bug in which Transaction.getValueSentFromMe was calculating incorrectly.
        Transaction tx = createFakeTx(params, COIN, myAddress);
        // Now add another output (ie, change) that goes to some other address.
        Address someOtherGuy = new ECKey().toAddress(params);
        TransactionOutput output = new TransactionOutput(params, tx, valueOf(0, 5), someOtherGuy);
        tx.addOutput(output);
        // Note that tx is no longer valid: it spends more than it imports. However checking transactions balance
        // correctly isn't possible in SPV mode because value is a property of outputs not inputs. Without all
        // transactions you can't check they add up.
        sendMoneyToWallet(tx, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Now the other guy creates a transaction which spends that change.
        Transaction tx2 = new Transaction(params);
        tx2.addInput(output);
        tx2.addOutput(new TransactionOutput(params, tx2, valueOf(0, 5), myAddress));
        // tx2 doesn't send any coins from us, even though the output is in the wallet.
        assertEquals(ZERO, tx2.getValueSentFromMe(wallet));
    }

    @Test
    public void bounce() throws Exception {
        // This test covers bug 64 (False double spends). Check that if we create a spend and it's immediately sent
        // back to us, this isn't considered as a double spend.
        Coin coin1 = COIN;
        sendMoneyToWallet(coin1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Send half to some other guy. Sending only half then waiting for a confirm is important to ensure the tx is
        // in the unspent pool, not pending or spent.
        Coin coinHalf = valueOf(0, 50);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());
        Address someOtherGuy = new ECKey().toAddress(params);
        Transaction outbound1 = wallet.createSend(someOtherGuy, coinHalf);
        wallet.commitTx(outbound1);
        sendMoneyToWallet(outbound1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertTrue(outbound1.getWalletOutputs(wallet).size() <= 1); //the change address at most
        // That other guy gives us the coins right back.
        Transaction inbound2 = new Transaction(params);
        inbound2.addOutput(new TransactionOutput(params, inbound2, coinHalf, myAddress));
        assertTrue(outbound1.getWalletOutputs(wallet).size() >= 1);
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
        sendMoneyToWallet(COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(valueOf(2, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Create a send to a merchant of all our coins.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), valueOf(2, 90));
        // Create a double spend of just the first one.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), COIN);
        send2 = new Transaction(params, send2.bitcoinSerialize());
        // Broadcast send1, it's now pending.
        wallet.commitTx(send1);
        assertEquals(ZERO, wallet.getBalance());
        // Receive a block that overrides the send1 using send2.
        sendMoneyToWallet(send2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // send1 got rolled back and replaced with a smaller send that only used one of our received coins, thus ...
        assertEquals(valueOf(2, 0), wallet.getBalance());
        assertTrue(wallet.isConsistent());
    }

    @Test
    public void doubleSpends() throws Exception {
        // Test the case where two semantically identical but bitwise different transactions double spend each other.
        // We call the second transaction a "mutant" of the first.
        //
        // This can (and has!) happened when a wallet is cloned between devices, and both devices decide to make the
        // same spend simultaneously - for example due a re-keying operation. It can also happen if there are malicious
        // nodes in the P2P network that are mutating transactions on the fly as occurred during Feb 2014.
        final Coin value = COIN;
        final Coin value2 = valueOf(2, 0);
        // Give us three coins and make sure we have some change.
        sendMoneyToWallet(value.add(value2), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        final Address address = new ECKey().toAddress(params);
        Transaction send1 = checkNotNull(wallet.createSend(address, value2));
        Transaction send2 = checkNotNull(wallet.createSend(address, value2));
        byte[] buf = send1.bitcoinSerialize();
        buf[43] = 0;  // Break the signature: bitcoinj won't check in SPV mode and this is easier than other mutations.
        send1 = new Transaction(params, buf);
        wallet.commitTx(send2);
        wallet.allowSpendingUnconfirmedTransactions();
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        // Now spend the change. This transaction should die permanently when the mutant appears in the chain.
        Transaction send3 = checkNotNull(wallet.createSend(address, value));
        wallet.commitTx(send3);
        assertEquals(ZERO, wallet.getBalance());
        final LinkedList<TransactionConfidence> dead = new LinkedList<TransactionConfidence>();
        final TransactionConfidence.Listener listener = new TransactionConfidence.Listener() {
            @Override
            public void onConfidenceChanged(TransactionConfidence confidence, ChangeReason reason) {
                final TransactionConfidence.ConfidenceType type = confidence.getConfidenceType();
                if (reason == ChangeReason.TYPE && type == TransactionConfidence.ConfidenceType.DEAD)
                    dead.add(confidence);
            }
        };
        send2.getConfidence().addEventListener(listener, Threading.SAME_THREAD);
        send3.getConfidence().addEventListener(listener, Threading.SAME_THREAD);
        // Double spend!
        sendMoneyToWallet(send1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Back to having one coin.
        assertEquals(value, wallet.getBalance());
        assertEquals(send2.getHash(), dead.poll().getTransactionHash());
        assertEquals(send3.getHash(), dead.poll().getTransactionHash());
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
        Coin nanos = COIN;
        sendMoneyToWallet(nanos, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Transaction received = wallet.getTransactions(false).iterator().next();
        // Create a send to a merchant.
        Transaction send1 = wallet.createSend(new ECKey().toAddress(params), valueOf(0, 50));
        // Create a double spend.
        Transaction send2 = wallet.createSend(new ECKey().toAddress(params), valueOf(0, 50));
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

        FakeTxBuilder.DoubleSpends doubleSpends = FakeTxBuilder.createFakeDoubleSpendTxns(params, myAddress);
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
        final Coin nanos = COIN;
        final Transaction t1 = createFakeTx(params, nanos, myAddress);

        // First one is "called" second is "pending".
        final boolean[] flags = new boolean[2];
        final Transaction[] notifiedTx = new Transaction[1];
        final int[] walletChanged = new int[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                // Check we got the expected transaction.
                assertEquals(tx, t1);
                // Check that it's considered to be pending inclusion in the block chain.
                assertEquals(prevBalance, ZERO);
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
        final TransactionConfidence.Listener.ChangeReason[] reasons = new TransactionConfidence.Listener.ChangeReason[1];
        notifiedTx[0].getConfidence().addEventListener(new TransactionConfidence.Listener() {
            @Override
            public void onConfidenceChanged(TransactionConfidence confidence, TransactionConfidence.Listener.ChangeReason reason) {
                flags[1] = true;
                reasons[0] = reason;
            }
        });
        assertEquals(TransactionConfidence.ConfidenceType.PENDING,
                notifiedTx[0].getConfidence().getConfidenceType());
        // Send a block with nothing interesting. Verify we don't get a callback.
        wallet.notifyNewBestBlock(createFakeBlock(blockStore).storedBlock);
        Threading.waitForUserCode();
        assertNull(reasons[0]);
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
        assertEquals(3, walletChanged[0]);
    }

    @Test
    public void pending2() throws Exception {
        // Check that if we receive a pending tx we did not send, it updates our spent flags correctly.
        final Transaction[] txn = new Transaction[1];
        final Coin[] bigints = new Coin[2];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                txn[0] = tx;
                bigints[0] = prevBalance;
                bigints[1] = newBalance;
            }
        });
        // Receive some coins.
        Coin nanos = COIN;
        sendMoneyToWallet(nanos, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Create a spend with them, but don't commit it (ie it's from somewhere else but using our keys). This TX
        // will have change as we don't spend our entire balance.
        Coin halfNanos = valueOf(0, 50);
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
        Coin nanos = COIN;

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
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
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

        assertEquals(ZERO, wallet.getBalance());
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        Threading.waitForUserCode();
        assertEquals(t1, called[0]);
        assertEquals(nanos, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        // Now receive a double spend on the main chain.
        called[0] = called[1] = null;
        sendMoneyToWallet(t2, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(t1, called[0]); // dead
        assertEquals(t2, called[1]); // replacement
    }

    @Test
    public void transactionsList() throws Exception {
        // Check the wallet can give us an ordered list of all received transactions.
        Utils.setMockClock();
        Transaction tx1 = sendMoneyToWallet(COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Utils.rollMockClock(60 * 10);
        Transaction tx2 = sendMoneyToWallet(valueOf(0, 5), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Check we got them back in order.
        List<Transaction> transactions = wallet.getTransactionsByTime();
        assertEquals(tx2, transactions.get(0));
        assertEquals(tx1, transactions.get(1));
        assertEquals(2, transactions.size());
        // Check we get only the last transaction if we request a subrage.
        transactions = wallet.getRecentTransactions(1, false);
        assertEquals(1, transactions.size());
        assertEquals(tx2,  transactions.get(0));

        // Create a spend five minutes later.
        Utils.rollMockClock(60 * 5);
        Transaction tx3 = wallet.createSend(new ECKey().toAddress(params), valueOf(0, 5));
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
        Utils.setMockClock();
        long now = Utils.currentTimeSeconds();
        wallet = new Wallet(params);
        assertEquals(now, wallet.getEarliestKeyCreationTime());
        Utils.rollMockClock(60);
        wallet.freshReceiveKey();
        assertEquals(now, wallet.getEarliestKeyCreationTime());
    }

    @Test
    public void scriptCreationTime() throws Exception {
        Utils.setMockClock();
        long now = Utils.currentTimeSeconds();
        wallet = new Wallet(params);
        assertEquals(now, wallet.getEarliestKeyCreationTime());
        Utils.rollMockClock(-120);
        wallet.addWatchedAddress(new ECKey().toAddress(params));
        wallet.freshReceiveKey();
        assertEquals(now - 120, wallet.getEarliestKeyCreationTime());
    }

    @Test
    public void spendToSameWallet() throws Exception {
        // Test that a spend to the same wallet is dealt with correctly.
        // It should appear in the wallet and confirm.
        // This is a bit of a silly thing to do in the real world as all it does is burn a fee but it is perfectly valid.
        Coin coin1 = COIN;
        Coin coinHalf = valueOf(0, 50);
        // Start by giving us 1 coin.
        sendMoneyToWallet(coin1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // Send half to ourselves. We should then have a balance available to spend of zero.
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());
        Transaction outbound1 = wallet.createSend(myAddress, coinHalf);
        wallet.commitTx(outbound1);
        // We should have a zero available balance before the next block.
        assertEquals(ZERO, wallet.getBalance());
        sendMoneyToWallet(outbound1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // We should have a balance of 1 BTC after the block is received.
        assertEquals(coin1, wallet.getBalance());
    }

    @Test
    public void lastBlockSeen() throws Exception {
        Coin v1 = valueOf(5, 0);
        Coin v2 = valueOf(0, 50);
        Coin v3 = valueOf(0, 25);
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
        assertEquals(b10.getTimeSeconds(), wallet.getLastBlockSeenTimeSecs());
        assertEquals(1, wallet.getLastBlockSeenHeight());
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
        ECKey key1 = wallet.freshReceiveKey();
        Coin value = valueOf(5, 0);
        Transaction t1 = createFakeTx(params, value, key1);
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        // TX should have been seen as relevant.
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertEquals(ZERO, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
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
    public void isWatching() {
        assertFalse(wallet.isWatching());
        Wallet watchingWallet = Wallet.fromWatchingKey(params, wallet.getWatchingKey().dropPrivateBytes().dropParent());
        assertTrue(watchingWallet.isWatching());
        wallet.encrypt(PASSWORD1);
        assertFalse(wallet.isWatching());
    }

    @Test
    public void watchingWallet() throws Exception {
        DeterministicKey watchKey = wallet.getWatchingKey();
        String serialized = watchKey.serializePubB58(params);

        // Construct watching wallet.
        Wallet watchingWallet = Wallet.fromWatchingKey(params, DeterministicKey.deserializeB58(null, serialized, params));
        DeterministicKey key2 = watchingWallet.freshReceiveKey();
        assertEquals(myKey, key2);

        ECKey key = wallet.freshKey(KeyChain.KeyPurpose.CHANGE);
        key2 = watchingWallet.freshKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key, key2);
        key.sign(Sha256Hash.ZERO_HASH);
        try {
            key2.sign(Sha256Hash.ZERO_HASH);
            fail();
        } catch (ECKey.MissingPrivateKeyException e) {
            // Expected
        }

        receiveATransaction(watchingWallet, myKey.toAddress(params));
        assertEquals(COIN, watchingWallet.getBalance());
        assertEquals(COIN, watchingWallet.getBalance(Wallet.BalanceType.AVAILABLE));
        assertEquals(ZERO, watchingWallet.getBalance(Wallet.BalanceType.AVAILABLE_SPENDABLE));
    }

    @Test(expected = ECKey.MissingPrivateKeyException.class)
    public void watchingWalletWithCreationTime() throws Exception {
        DeterministicKey watchKey = wallet.getWatchingKey();
        String serialized = watchKey.serializePubB58(params);
        watchKey = DeterministicKey.deserializeB58(null, serialized, params);
        Wallet watchingWallet = Wallet.fromWatchingKey(params, watchKey, 1415282801);
        DeterministicKey key2 = watchingWallet.freshReceiveKey();
        assertEquals(myKey, key2);

        ECKey key = wallet.freshKey(KeyChain.KeyPurpose.CHANGE);
        key2 = watchingWallet.freshKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key, key2);
        key.sign(Sha256Hash.ZERO_HASH);
        key2.sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void watchingScripts() throws Exception {
        // Verify that pending transactions to watched addresses are relevant
        ECKey key = new ECKey();
        Address watchedAddress = key.toAddress(params);
        wallet.addWatchedAddress(watchedAddress);
        Coin value = valueOf(5, 0);
        Transaction t1 = createFakeTx(params, value, watchedAddress);
        assertTrue(t1.getWalletOutputs(wallet).size() >= 1);
        assertTrue(wallet.isPendingTransactionRelevant(t1));
    }

    @Test(expected = InsufficientMoneyException.class)
    public void watchingScriptsConfirmed() throws Exception {
        ECKey key = new ECKey();
        Address watchedAddress = key.toAddress(params);
        wallet.addWatchedAddress(watchedAddress);
        Transaction t1 = createFakeTx(params, CENT, watchedAddress);
        StoredBlock b3 = createFakeBlock(blockStore, t1).storedBlock;
        wallet.receiveFromBlock(t1, b3, BlockChain.NewBlockType.BEST_CHAIN, 0);
        assertEquals(CENT, wallet.getBalance());

        // We can't spend watched balances
        Address notMyAddr = new ECKey().toAddress(params);
        wallet.createSend(notMyAddr, CENT);
    }

    @Test
    public void watchingScriptsSentFrom() throws Exception {
        int baseElements = wallet.getBloomFilterElementCount();

        ECKey key = new ECKey();
        ECKey notMyAddr = new ECKey();
        Address watchedAddress = key.toAddress(params);
        wallet.addWatchedAddress(watchedAddress);
        assertEquals(baseElements + 1, wallet.getBloomFilterElementCount());

        Transaction t1 = createFakeTx(params, CENT, watchedAddress);
        Transaction t2 = createFakeTx(params, COIN, notMyAddr);
        StoredBlock b1 = createFakeBlock(blockStore, t1).storedBlock;
        Transaction st2 = new Transaction(params);
        st2.addOutput(CENT, notMyAddr);
        st2.addOutput(COIN, notMyAddr);
        st2.addInput(t1.getOutput(0));
        st2.addInput(t2.getOutput(0));
        wallet.receiveFromBlock(t1, b1, BlockChain.NewBlockType.BEST_CHAIN, 0);
        assertEquals(baseElements + 2, wallet.getBloomFilterElementCount());
        wallet.receiveFromBlock(st2, b1, BlockChain.NewBlockType.BEST_CHAIN, 0);
        assertEquals(baseElements + 2, wallet.getBloomFilterElementCount());
        assertEquals(CENT, st2.getValueSentFromMe(wallet));
    }

    @Test
    public void watchingScriptsBloomFilter() throws Exception {
        assertFalse(wallet.isRequiringUpdateAllBloomFilter());

        ECKey key = new ECKey();
        Address watchedAddress = key.toAddress(params);
        wallet.addWatchedAddress(watchedAddress);

        assertTrue(wallet.isRequiringUpdateAllBloomFilter());
        Transaction t1 = createFakeTx(params, CENT, watchedAddress);
        StoredBlock b1 = createFakeBlock(blockStore, t1).storedBlock;

        TransactionOutPoint outPoint = new TransactionOutPoint(params, 0, t1);

        // Note that this has a 1e-12 chance of failing this unit test due to a false positive
        assertFalse(wallet.getBloomFilter(1e-12).contains(outPoint.bitcoinSerialize()));

        wallet.receiveFromBlock(t1, b1, BlockChain.NewBlockType.BEST_CHAIN, 0);
        assertTrue(wallet.getBloomFilter(1e-12).contains(outPoint.bitcoinSerialize()));
    }

    @Test
    public void getWatchedAddresses() throws Exception {
        Address watchedAddress = new ECKey().toAddress(params);
        wallet.addWatchedAddress(watchedAddress);
        List<Address> watchedAddresses = wallet.getWatchedAddresses();
        assertEquals(1, watchedAddresses.size());
        assertEquals(watchedAddress, watchedAddresses.get(0));
    }

    @Test
    public void removeWatchedAddresses() {
        List<Address> addressesForRemoval = new ArrayList<Address>();
        for (int i = 0; i < 10; i++) {
            ECKey key = new ECKey();
            Address watchedAddress = key.toAddress(params);
            addressesForRemoval.add(watchedAddress);
            wallet.addWatchedAddress(watchedAddress);
        }

        wallet.removeWatchedAddresses(addressesForRemoval);
        for (Address addr : addressesForRemoval)
            assertFalse(wallet.isAddressWatched(addr));

        assertFalse(wallet.isRequiringUpdateAllBloomFilter());
    }

    @Test
    public void removeWatchedAddress() {
        Address watchedAddress = new ECKey().toAddress(params);
        wallet.addWatchedAddress(watchedAddress);
        wallet.removeWatchedAddress(watchedAddress);
        assertFalse(wallet.isAddressWatched(watchedAddress));
        assertFalse(wallet.isRequiringUpdateAllBloomFilter());
    }

    @Test
    public void removeScriptsBloomFilter() throws Exception {
        List<Address> addressesForRemoval = new ArrayList<Address>();
        for (int i = 0; i < 10; i++) {
            ECKey key = new ECKey();
            Address watchedAddress = key.toAddress(params);
            addressesForRemoval.add(watchedAddress);
            wallet.addWatchedAddress(watchedAddress);
        }

        wallet.removeWatchedAddresses(addressesForRemoval);

        for (Address addr : addressesForRemoval) {
            Transaction t1 = createFakeTx(params, CENT, addr);
            StoredBlock b1 = createFakeBlock(blockStore, t1).storedBlock;

            TransactionOutPoint outPoint = new TransactionOutPoint(params, 0, t1);

            // Note that this has a 1e-12 chance of failing this unit test due to a false positive
            assertFalse(wallet.getBloomFilter(1e-12).contains(outPoint.bitcoinSerialize()));

            wallet.receiveFromBlock(t1, b1, BlockChain.NewBlockType.BEST_CHAIN, 0);
            assertFalse(wallet.getBloomFilter(1e-12).contains(outPoint.bitcoinSerialize()));
        }
    }

    @Test
    public void marriedKeychainBloomFilter() throws Exception {
        createMarriedWallet(2, 2);
        Address address = wallet.currentReceiveAddress();

        assertTrue(wallet.getBloomFilter(0.001).contains(address.getHash160()));

        Transaction t1 = createFakeTx(params, CENT, address);
        StoredBlock b1 = createFakeBlock(blockStore, t1).storedBlock;

        TransactionOutPoint outPoint = new TransactionOutPoint(params, 0, t1);

        assertFalse(wallet.getBloomFilter(0.001).contains(outPoint.bitcoinSerialize()));

        wallet.receiveFromBlock(t1, b1, BlockChain.NewBlockType.BEST_CHAIN, 0);
        assertTrue(wallet.getBloomFilter(0.001).contains(outPoint.bitcoinSerialize()));
    }

    @Test
    public void autosaveImmediate() throws Exception {
        // Test that the wallet will save itself automatically when it changes.
        File f = File.createTempFile("bitcoinj-unit-test", null);
        Sha256Hash hash1 = Sha256Hash.of(f);
        // Start with zero delay and ensure the wallet file changes after adding a key.
        wallet.autosaveToFile(f, 0, TimeUnit.SECONDS, null);
        ECKey key = wallet.freshReceiveKey();
        Sha256Hash hash2 = Sha256Hash.of(f);
        assertFalse("Wallet not saved after generating fresh key", hash1.equals(hash2));  // File has changed.

        Transaction t1 = createFakeTx(params, valueOf(5, 0), key);
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        Sha256Hash hash3 = Sha256Hash.of(f);
        assertFalse("Wallet not saved after receivePending", hash2.equals(hash3));  // File has changed again.
    }

    @Test
    public void autosaveDelayed() throws Exception {
        // Test that the wallet will save itself automatically when it changes, but not immediately and near-by
        // updates are coalesced together. This test is a bit racy, it assumes we can complete the unit test within
        // an auto-save cycle of 1 second.
        final File[] results = new File[2];
        final CountDownLatch latch = new CountDownLatch(3);
        File f = File.createTempFile("bitcoinj-unit-test", null);
        Sha256Hash hash1 = Sha256Hash.of(f);
        wallet.autosaveToFile(f, 1, TimeUnit.SECONDS,
                new WalletFiles.Listener() {
                    @Override
                    public void onBeforeAutoSave(File tempFile) {
                        results[0] = tempFile;
                    }

                    @Override
                    public void onAfterAutoSave(File newlySavedFile) {
                        results[1] = newlySavedFile;
                        latch.countDown();
                    }
                }
        );
        ECKey key = wallet.freshReceiveKey();
        Sha256Hash hash2 = Sha256Hash.of(f);
        assertFalse(hash1.equals(hash2));  // File has changed immediately despite the delay, as keys are important.
        assertNotNull(results[0]);
        assertEquals(f, results[1]);
        results[0] = results[1] = null;

        Block b0 = createFakeBlock(blockStore).block;
        chain.add(b0);
        Sha256Hash hash3 = Sha256Hash.of(f);
        assertEquals(hash2, hash3);  // File has NOT changed yet. Just new blocks with no txns - delayed.
        assertNull(results[0]);
        assertNull(results[1]);

        Transaction t1 = createFakeTx(params, valueOf(5, 0), key);
        Block b1 = createFakeBlock(blockStore, t1).block;
        chain.add(b1);
        Sha256Hash hash4 = Sha256Hash.of(f);
        assertFalse(hash3.equals(hash4));  // File HAS changed.
        results[0] = results[1] = null;

        // A block that contains some random tx we don't care about.
        Block b2 = b1.createNextBlock(new ECKey().toAddress(params));
        chain.add(b2);
        assertEquals(hash4, Sha256Hash.of(f));  // File has NOT changed.
        assertNull(results[0]);
        assertNull(results[1]);

        // Wait for an auto-save to occur.
        latch.await();
        Sha256Hash hash5 = Sha256Hash.of(f);
        assertFalse(hash4.equals(hash5));  // File has now changed.
        assertNotNull(results[0]);
        assertEquals(f, results[1]);

        // Now we shutdown auto-saving and expect wallet changes to remain unsaved, even "important" changes.
        wallet.shutdownAutosaveAndWait();
        results[0] = results[1] = null;
        ECKey key2 = new ECKey();
        wallet.importKey(key2);
        assertEquals(hash5, Sha256Hash.of(f)); // File has NOT changed.
        Transaction t2 = createFakeTx(params, valueOf(5, 0), key2);
        Block b3 = createFakeBlock(blockStore, t2).block;
        chain.add(b3);
        Thread.sleep(2000); // Wait longer than autosave delay. TODO Fix the racyness.
        assertEquals(hash5, Sha256Hash.of(f)); // File has still NOT changed.
        assertNull(results[0]);
        assertNull(results[1]);
    }

    @Test
    public void spendOutputFromPendingTransaction() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        Coin v1 = COIN;
        sendMoneyToWallet(v1, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        // First create our current transaction
        ECKey k2 = wallet.freshReceiveKey();
        Coin v2 = valueOf(0, 50);
        Transaction t2 = new Transaction(params);
        TransactionOutput o2 = new TransactionOutput(params, t2, v2, k2.toAddress(params));
        t2.addOutput(o2);
        SendRequest req = SendRequest.forTx(t2);
        req.ensureMinRequiredFee = false;
        wallet.completeTx(req);

        // Commit t2, so it is placed in the pending pool
        wallet.commitTx(t2);
        assertEquals(0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(2, wallet.getTransactions(true).size());

        // Now try to the spend the output.
        ECKey k3 = new ECKey();
        Coin v3 = valueOf(0, 25);
        Transaction t3 = new Transaction(params);
        t3.addOutput(v3, k3.toAddress(params));
        t3.addInput(o2);
        wallet.signTransaction(SendRequest.forTx(t3));

        // Commit t3, so the coins from the pending t2 are spent
        wallet.commitTx(t3);
        assertEquals(0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(3, wallet.getTransactions(true).size());

        // Now the output of t2 must not be available for spending
        assertFalse(o2.isAvailableForSpending());
    }

    @Test
    public void replayWhilstPending() throws Exception {
        // Check that if a pending transaction spends outputs of chain-included transactions, we mark them as spent.
        // See bug 345. This can happen if there is a pending transaction floating around and then you replay the
        // chain without emptying the memory pool (or refilling it from a peer).
        Coin value = COIN;
        Transaction tx1 = createFakeTx(params, value, myAddress);
        Transaction tx2 = new Transaction(params);
        tx2.addInput(tx1.getOutput(0));
        tx2.addOutput(valueOf(0, 9), someOtherAddress);
        // Add a change address to ensure this tx is relevant.
        tx2.addOutput(CENT, wallet.getChangeAddress());
        wallet.receivePending(tx2, null);
        BlockPair bp = createFakeBlock(blockStore, tx1);
        wallet.receiveFromBlock(tx1, bp.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        wallet.notifyNewBestBlock(bp.storedBlock);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(Pool.SPENT));
        assertEquals(1, wallet.getPoolSize(Pool.PENDING));
        assertEquals(0, wallet.getPoolSize(Pool.UNSPENT));
    }

    @Test
    public void outOfOrderPendingTxns() throws Exception {
        // Check that if there are two pending transactions which we receive out of order, they are marked as spent
        // correctly. For instance, we are watching a wallet, someone pays us (A) and we then pay someone else (B)
        // with a change address but the network delivers the transactions to us in order B then A.
        Coin value = COIN;
        Transaction a = createFakeTx(params, value, myAddress);
        Transaction b = new Transaction(params);
        b.addInput(a.getOutput(0));
        b.addOutput(CENT, someOtherAddress);
        Coin v = COIN.subtract(CENT);
        b.addOutput(v, wallet.getChangeAddress());
        a = roundTripTransaction(params, a);
        b = roundTripTransaction(params, b);
        wallet.receivePending(b, null);
        assertEquals(v, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        wallet.receivePending(a, null);
        assertEquals(v, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void encryptionDecryptionAESBasic() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);

        assertEquals(EncryptionType.ENCRYPTED_SCRYPT_AES, encryptedWallet.getEncryptionType());
        assertTrue(encryptedWallet.checkPassword(PASSWORD1));
        assertTrue(encryptedWallet.checkAESKey(aesKey));
        assertFalse(encryptedWallet.checkPassword(WRONG_PASSWORD));
        assertTrue("The keyCrypter is missing but should not be", keyCrypter != null);
        encryptedWallet.decrypt(aesKey);

        // Wallet should now be unencrypted.
        assertTrue("Wallet is not an unencrypted wallet", encryptedWallet.getKeyCrypter() == null);
        try {
            encryptedWallet.checkPassword(PASSWORD1);
            fail();
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void encryptionDecryptionPasswordBasic() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);

        assertTrue(encryptedWallet.isEncrypted());
        encryptedWallet.decrypt(PASSWORD1);
        assertFalse(encryptedWallet.isEncrypted());

        // Wallet should now be unencrypted.
        assertTrue("Wallet is not an unencrypted wallet", encryptedWallet.getKeyCrypter() == null);
        try {
            encryptedWallet.checkPassword(PASSWORD1);
            fail();
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void encryptionDecryptionBadPassword() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter wrongAesKey = keyCrypter.deriveKey(WRONG_PASSWORD);

        // Check the wallet is currently encrypted
        assertTrue("Wallet is not an encrypted wallet", encryptedWallet.getEncryptionType() == EncryptionType.ENCRYPTED_SCRYPT_AES);
        assertFalse(encryptedWallet.checkAESKey(wrongAesKey));

        // Check that the wrong password does not decrypt the wallet.
        try {
            encryptedWallet.decrypt(wrongAesKey);
            fail("Incorrectly decoded wallet with wrong password");
        } catch (KeyCrypterException ede) {
            // Expected.
        }
    }

    @Test
    public void changePasswordTest() {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);
        CharSequence newPassword = "My name is Tom";
        encryptedWallet.changeEncryptionPassword(PASSWORD1, newPassword);
        assertTrue(encryptedWallet.checkPassword(newPassword));
        assertFalse(encryptedWallet.checkPassword(WRONG_PASSWORD));
    }

    @Test
    public void changeAesKeyTest() {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);

        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);

        CharSequence newPassword = "My name is Tom";
        KeyParameter newAesKey = keyCrypter.deriveKey(newPassword);

        encryptedWallet.changeEncryptionKey(keyCrypter, aesKey, newAesKey);

        assertTrue(encryptedWallet.checkAESKey(newAesKey));
        assertFalse(encryptedWallet.checkAESKey(aesKey));
    }

    @Test
    public void encryptionDecryptionCheckExceptions() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);

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

    @Test(expected = KeyCrypterException.class)
    public void addUnencryptedKeyToEncryptedWallet() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);

        ECKey key1 = new ECKey();
        encryptedWallet.importKey(key1);
    }

    @Test(expected = KeyCrypterException.class)
    public void addEncryptedKeyToUnencryptedWallet() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();

        ECKey key1 = new ECKey();
        key1 = key1.encrypt(keyCrypter, keyCrypter.deriveKey("PASSWORD!"));
        wallet.importKey(key1);
    }

    @Test(expected = KeyCrypterException.class)
    public void mismatchedCrypter() throws Exception {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);

        // Try added an ECKey that was encrypted with a differenct ScryptParameters (i.e. a non-homogenous key).
        // This is not allowed as the ScryptParameters is stored at the Wallet level.
        byte[] salt = new byte[KeyCrypterScrypt.SALT_LENGTH];
        secureRandom.nextBytes(salt);
        Protos.ScryptParameters.Builder scryptParametersBuilder = Protos.ScryptParameters.newBuilder().setSalt(ByteString.copyFrom(salt));
        Protos.ScryptParameters scryptParameters = scryptParametersBuilder.build();
        KeyCrypter keyCrypterDifferent = new KeyCrypterScrypt(scryptParameters);
        ECKey ecKeyDifferent = new ECKey();
        ecKeyDifferent = ecKeyDifferent.encrypt(keyCrypterDifferent, aesKey);
        encryptedWallet.importKey(ecKeyDifferent);
    }

    @Test
    public void importAndEncrypt() throws InsufficientMoneyException {
        Wallet encryptedWallet = new Wallet(params);
        encryptedWallet.encrypt(PASSWORD1);

        final ECKey key = new ECKey();
        encryptedWallet.importKeysAndEncrypt(ImmutableList.of(key), PASSWORD1);
        assertEquals(1, encryptedWallet.getImportedKeys().size());
        assertEquals(key.getPubKeyPoint(), encryptedWallet.getImportedKeys().get(0).getPubKeyPoint());
        sendMoneyToWallet(encryptedWallet, Coin.COIN, key.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertEquals(Coin.COIN, encryptedWallet.getBalance());
        SendRequest req = Wallet.SendRequest.emptyWallet(new ECKey().toAddress(params));
        req.aesKey = checkNotNull(encryptedWallet.getKeyCrypter()).deriveKey(PASSWORD1);
        encryptedWallet.sendCoinsOffline(req);
    }

    @Test
    public void ageMattersDuringSelection() throws Exception {
        // Test that we prefer older coins to newer coins when building spends. This reduces required fees and improves
        // time to confirmation as the transaction will appear less spammy.
        final int ITERATIONS = 10;
        Transaction[] txns = new Transaction[ITERATIONS];
        for (int i = 0; i < ITERATIONS; i++) {
            txns[i] = sendMoneyToWallet(COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        }
        // Check that we spend transactions in order of reception.
        for (int i = 0; i < ITERATIONS; i++) {
            Transaction spend = wallet.createSend(new ECKey().toAddress(params), COIN);
            assertEquals(spend.getInputs().size(), 1);
            assertEquals("Failed on iteration " + i, spend.getInput(0).getOutpoint().getHash(), txns[i].getHash());
            wallet.commitTx(spend);
        }
    }

    @Test(expected = Wallet.ExceededMaxTransactionSize.class)
    public void respectMaxStandardSize() throws Exception {
        // Check that we won't create txns > 100kb. Average tx size is ~220 bytes so this would have to be enormous.
        sendMoneyToWallet(valueOf(100, 0), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Transaction tx = new Transaction(params);
        byte[] bits = new byte[20];
        new Random().nextBytes(bits);
        Coin v = CENT;
        // 3100 outputs to a random address.
        for (int i = 0; i < 3100; i++) {
            tx.addOutput(v, new Address(params, bits));
        }
        Wallet.SendRequest req = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(req);
    }

    @Test
    public void opReturnOneOutputTest() throws Exception {
        // Tests basic send of transaction with one output that doesn't transfer any value but just writes OP_RETURN.
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(params);
        Coin messagePrice = Coin.ZERO;
        Script script = ScriptBuilder.createOpReturnScript("hello world!".getBytes());
        tx.addOutput(messagePrice, script);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test
    public void opReturnOneOutputWithValueTest() throws Exception {
        // Tests basic send of transaction with one output that destroys coins and has an OP_RETURN.
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(params);
        Coin messagePrice = CENT;
        Script script = ScriptBuilder.createOpReturnScript("hello world!".getBytes());
        tx.addOutput(messagePrice, script);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test
    public void opReturnTwoOutputsTest() throws Exception {
        // Tests sending transaction where one output transfers BTC, the other one writes OP_RETURN.
        receiveATransaction(wallet, myAddress);
        Address notMyAddr = new ECKey().toAddress(params);
        Transaction tx = new Transaction(params);
        Coin messagePrice = Coin.ZERO;
        Script script = ScriptBuilder.createOpReturnScript("hello world!".getBytes());
        tx.addOutput(CENT, notMyAddr);
        tx.addOutput(messagePrice, script);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.MultipleOpReturnRequested.class)
    public void twoOpReturnsPerTransactionTest() throws Exception {
        // Tests sending transaction where there are 2 attempts to write OP_RETURN scripts - this should fail and throw MultipleOpReturnRequested.
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(params);
        Coin messagePrice = Coin.ZERO;
        Script script1 = ScriptBuilder.createOpReturnScript("hello world 1!".getBytes());
        Script script2 = ScriptBuilder.createOpReturnScript("hello world 2!".getBytes());
        tx.addOutput(messagePrice, script1);
        tx.addOutput(messagePrice, script2);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.DustySendRequested.class)
    public void sendDustTest() throws InsufficientMoneyException {
        // Tests sending dust, should throw DustySendRequested.
        Transaction tx = new Transaction(params);
        Address notMyAddr = new ECKey().toAddress(params);
        tx.addOutput(Transaction.MIN_NONDUST_OUTPUT.subtract(SATOSHI), notMyAddr);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test
    public void sendMultipleCentsTest() throws Exception {
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        Transaction tx = new Transaction(params);
        Address notMyAddr = new ECKey().toAddress(params);
        Coin c = CENT.subtract(SATOSHI);
        tx.addOutput(c, notMyAddr);
        tx.addOutput(c, notMyAddr);
        tx.addOutput(c, notMyAddr);
        tx.addOutput(c, notMyAddr);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.DustySendRequested.class)
    public void sendDustAndOpReturnWithoutValueTest() throws Exception {
        // Tests sending dust and OP_RETURN without value, should throw DustySendRequested because sending sending dust is not allowed in any case.
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        Transaction tx = new Transaction(params);
        Address notMyAddr = new ECKey().toAddress(params);
        Script script = new ScriptBuilder().op(ScriptOpCodes.OP_RETURN).data("hello world!".getBytes()).build();
        tx.addOutput(Coin.ZERO, script);
        tx.addOutput(Coin.SATOSHI, notMyAddr);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.DustySendRequested.class)
    public void sendDustAndMessageWithValueTest() throws Exception {
        //Tests sending dust and OP_RETURN with value, should throw DustySendRequested
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(params);
        Address notMyAddr = new ECKey().toAddress(params);
        Script script = new ScriptBuilder().op(ScriptOpCodes.OP_RETURN).data("hello world!".getBytes()).build();
        tx.addOutput(Coin.CENT, script);
        tx.addOutput(Transaction.MIN_NONDUST_OUTPUT.subtract(SATOSHI), notMyAddr);
        SendRequest request = Wallet.SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test
    public void sendRequestP2PKTest() {
        ECKey key = new ECKey();
        Address notMyAddr = key.toAddress(params);
        SendRequest req = SendRequest.to(notMyAddr.getParameters(), key, SATOSHI.multiply(12));
        assertArrayEquals(key.getPubKey(), req.tx.getOutputs().get(0).getScriptPubKey().getPubKey());
    }

    @Test
    public void sendRequestP2PKHTest() {
        ECKey key = new ECKey();
        Address notMyAddr = key.toAddress(params);
        SendRequest req = SendRequest.to(notMyAddr, SATOSHI.multiply(12));
        assertEquals(notMyAddr, req.tx.getOutputs().get(0).getScriptPubKey().getToAddress(params));
    }

    @Test
    public void feeSolverAndCoinSelectionTest() throws Exception {
        // Tests basic fee solving works

        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a few outputs to us that are far too small to spend reasonably
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx1 = createFakeTx(params, SATOSHI, myAddress);
        wallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        Transaction tx2 = createFakeTx(params, SATOSHI, myAddress);
        assertTrue(!tx1.getHash().equals(tx2.getHash()));
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        Transaction tx3 = createFakeTx(params, SATOSHI.multiply(10), myAddress);
        wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 2);

        // Not allowed to send dust.
        try {
            wallet.createSend(notMyAddr, SATOSHI);
            fail();
        } catch (Wallet.DustySendRequested e) {
            // Expected.
        }
        // Spend it all without fee enforcement
        SendRequest req = SendRequest.to(notMyAddr, SATOSHI.multiply(12));
        req.ensureMinRequiredFee = false;
        assertNotNull(wallet.sendCoinsOffline(req));
        assertEquals(ZERO, wallet.getBalance());

        // Add some reasonable-sized outputs
        block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx4 = createFakeTx(params, Coin.COIN, myAddress);
        wallet.receiveFromBlock(tx4, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);

        // Simple test to make sure if we have an ouput < 0.01 we get a fee
        Transaction spend1 = wallet.createSend(notMyAddr, CENT.subtract(SATOSHI));
        assertEquals(2, spend1.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        // We should have paid the default minfee.
        assertEquals(spend1.getOutput(0).getValue().add(spend1.getOutput(1).getValue()),
                Coin.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        // But not at exactly 0.01
        Transaction spend2 = wallet.createSend(notMyAddr, CENT);
        assertEquals(2, spend2.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(Coin.COIN, spend2.getOutput(0).getValue().add(spend2.getOutput(1).getValue()));

        // ...but not more fee than what we request
        SendRequest request3 = SendRequest.to(notMyAddr, CENT.subtract(SATOSHI));
        request3.fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(SATOSHI);
        wallet.completeTx(request3);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(SATOSHI), request3.tx.getFee());
        Transaction spend3 = request3.tx;
        assertEquals(2, spend3.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend3.getOutput(0).getValue().add(spend3.getOutput(1).getValue()),
                Coin.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(SATOSHI)));

        // ...unless we need it
        SendRequest request4 = SendRequest.to(notMyAddr, CENT.subtract(SATOSHI));
        request4.fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.subtract(SATOSHI);
        wallet.completeTx(request4);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request4.tx.getFee());
        Transaction spend4 = request4.tx;
        assertEquals(2, spend4.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend4.getOutput(0).getValue().add(spend4.getOutput(1).getValue()),
                Coin.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request5 = SendRequest.to(notMyAddr, Coin.COIN.subtract(CENT.subtract(SATOSHI)));
        wallet.completeTx(request5);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request5.tx.getFee());
        Transaction spend5 = request5.tx;
        // If we would have a change output < 0.01, it should add the fee
        assertEquals(2, spend5.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend5.getOutput(0).getValue().add(spend5.getOutput(1).getValue()),
                Coin.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request6 = SendRequest.to(notMyAddr, Coin.COIN.subtract(CENT));
        wallet.completeTx(request6);
        assertEquals(ZERO, request6.tx.getFee());
        Transaction spend6 = request6.tx;
        // ...but not if change output == 0.01
        assertEquals(2, spend6.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(Coin.COIN, spend6.getOutput(0).getValue().add(spend6.getOutput(1).getValue()));

        SendRequest request7 = SendRequest.to(notMyAddr, Coin.COIN.subtract(CENT.subtract(SATOSHI.multiply(2)).multiply(2)));
        request7.tx.addOutput(CENT.subtract(SATOSHI), notMyAddr);
        wallet.completeTx(request7);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request7.tx.getFee());
        Transaction spend7 = request7.tx;
        // If change is 0.1-satoshi and we already have a 0.1-satoshi output, fee should be reference fee
        assertEquals(3, spend7.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend7.getOutput(0).getValue().add(spend7.getOutput(1).getValue()).add(spend7.getOutput(2).getValue()),
                Coin.COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request8 = SendRequest.to(notMyAddr, COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));
        wallet.completeTx(request8);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request8.tx.getFee());
        Transaction spend8 = request8.tx;
        // If we would have a change output == REFERENCE_DEFAULT_MIN_TX_FEE that would cause a fee, throw it away and make it fee
        assertEquals(1, spend8.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(spend8.getOutput(0).getValue(), COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request9 = SendRequest.to(notMyAddr, COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)));
        wallet.completeTx(request9);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT), request9.tx.getFee());
        Transaction spend9 = request9.tx;
        // ...in fact, also add fee if we would get back less than MIN_NONDUST_OUTPUT
        assertEquals(1, spend9.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend9.getOutput(0).getValue(),
                COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)));

        SendRequest request10 = SendRequest.to(notMyAddr, COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT).add(SATOSHI)));
        wallet.completeTx(request10);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request10.tx.getFee());
        Transaction spend10 = request10.tx;
        // ...but if we get back any more than that, we should get a refund (but still pay fee)
        assertEquals(2, spend10.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(spend10.getOutput(0).getValue().add(spend10.getOutput(1).getValue()),
                COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        SendRequest request11 = SendRequest.to(notMyAddr, COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT).add(SATOSHI.multiply(2))));
        request11.fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(SATOSHI);
        wallet.completeTx(request11);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(SATOSHI), request11.tx.getFee());
        Transaction spend11 = request11.tx;
        // ...of course fee should be min(request.fee, MIN_TX_FEE) so we should get MIN_TX_FEE.add(SATOSHI) here
        assertEquals(2, spend11.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one.
        assertEquals(spend11.getOutput(0).getValue().add(spend11.getOutput(1).getValue()),
                COIN.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(SATOSHI)));

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
        Transaction tx6 = createFakeTx(params, COIN, myAddress);
        wallet.receiveFromBlock(tx6, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        assertTrue(tx5.getOutput(0).isMine(wallet) && tx5.getOutput(0).isAvailableForSpending() && tx5.getConfidence().getDepthInBlocks() == 100);
        assertTrue(tx6.getOutput(0).isMine(wallet) && tx6.getOutput(0).isAvailableForSpending() && tx6.getConfidence().getDepthInBlocks() == 1);

        // tx5 and tx6 have exactly the same coin*depth, so the larger should be selected...
        Transaction spend12 = wallet.createSend(notMyAddr, CENT);
        assertTrue(spend12.getOutputs().size() == 2 && spend12.getOutput(0).getValue().add(spend12.getOutput(1).getValue()).equals(COIN));

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
        assertTrue(spend14.getOutputs().size() == 2 && spend14.getOutput(0).getValue().add(spend14.getOutput(1).getValue()).equals(COIN));

        // Now test feePerKb
        SendRequest request15 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 29; i++)
            request15.tx.addOutput(CENT, notMyAddr);
        assertTrue(request15.tx.bitcoinSerialize().length > 1000);
        request15.feePerKb = SATOSHI;
        wallet.completeTx(request15);
        assertEquals(SATOSHI.multiply(2), request15.tx.getFee());
        Transaction spend15 = request15.tx;
        // If a transaction is over 1kb, 2 satoshis should be added.
        assertEquals(31, spend15.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        Coin outValue15 = ZERO;
        for (TransactionOutput out : spend15.getOutputs())
            outValue15 = outValue15.add(out.getValue());
        assertEquals(COIN.subtract(SATOSHI.multiply(2)), outValue15);

        SendRequest request16 = SendRequest.to(notMyAddr, CENT);
        request16.feePerKb = ZERO;
        for (int i = 0; i < 29; i++)
            request16.tx.addOutput(CENT, notMyAddr);
        assertTrue(request16.tx.bitcoinSerialize().length > 1000);
        wallet.completeTx(request16);
        // Of course the fee shouldn't be added if feePerKb == 0
        assertEquals(ZERO, request16.tx.getFee());
        Transaction spend16 = request16.tx;
        assertEquals(31, spend16.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        Coin outValue16 = ZERO;
        for (TransactionOutput out : spend16.getOutputs())
            outValue16 = outValue16.add(out.getValue());
        assertEquals(COIN, outValue16);

        // Create a transaction whose max size could be up to 999 (if signatures were maximum size)
        SendRequest request17 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 22; i++)
            request17.tx.addOutput(CENT, notMyAddr);
        request17.tx.addOutput(new TransactionOutput(params, request17.tx, CENT, new byte[15]));
        request17.feePerKb = SATOSHI;
        wallet.completeTx(request17);
        assertEquals(SATOSHI, request17.tx.getFee());
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
        Coin outValue17 = ZERO;
        for (TransactionOutput out : spend17.getOutputs())
            outValue17 = outValue17.add(out.getValue());
        assertEquals(COIN.subtract(SATOSHI), outValue17);

        // Create a transaction who's max size could be up to 1001 (if signatures were maximum size)
        SendRequest request18 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 22; i++)
            request18.tx.addOutput(CENT, notMyAddr);
        request18.tx.addOutput(new TransactionOutput(params, request18.tx, CENT, new byte[17]));
        request18.feePerKb = SATOSHI;
        wallet.completeTx(request18);
        assertEquals(SATOSHI.multiply(2), request18.tx.getFee());
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
        Coin outValue18 = ZERO;
        for (TransactionOutput out : spend18.getOutputs())
            outValue18 = outValue18.add(out.getValue());
        assertEquals(outValue18, COIN.subtract(SATOSHI.multiply(2)));

        // Now create a transaction that will spend COIN + fee, which makes it require both inputs
        assertEquals(wallet.getBalance(), CENT.add(COIN));
        SendRequest request19 = SendRequest.to(notMyAddr, CENT);
        request19.feePerKb = ZERO;
        for (int i = 0; i < 99; i++)
            request19.tx.addOutput(CENT, notMyAddr);
        // If we send now, we shouldn't need a fee and should only have to spend our COIN
        wallet.completeTx(request19);
        assertEquals(ZERO, request19.tx.getFee());
        assertEquals(1, request19.tx.getInputs().size());
        assertEquals(100, request19.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request19.tx.clearInputs();
        request19 = SendRequest.forTx(request19.tx);
        request19.feePerKb = SATOSHI;
        request19.shuffleOutputs = false;
        wallet.completeTx(request19);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request19.tx.getFee());
        assertEquals(2, request19.tx.getInputs().size());
        Coin outValue19 = ZERO;
        for (TransactionOutput out : request19.tx.getOutputs())
            outValue19 = outValue19.add(out.getValue());
        // But now our change output is CENT-minfee, so we have to pay min fee
        assertEquals(request19.tx.getOutput(request19.tx.getOutputs().size() - 1).getValue(), CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));
        assertEquals(outValue19, COIN.add(CENT).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        // Create another transaction that will spend COIN + fee, which makes it require both inputs
        SendRequest request20 = SendRequest.to(notMyAddr, CENT);
        request20.feePerKb = ZERO;
        for (int i = 0; i < 99; i++)
            request20.tx.addOutput(CENT, notMyAddr);
        // If we send now, we shouldn't have a fee and should only have to spend our COIN
        wallet.completeTx(request20);
        assertEquals(ZERO, request20.tx.getFee());
        assertEquals(1, request20.tx.getInputs().size());
        assertEquals(100, request20.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request20.tx.clearInputs();
        request20 = SendRequest.forTx(request20.tx);
        request20.feePerKb = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;
        wallet.completeTx(request20);
        // 4kb tx.
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(4), request20.tx.getFee());
        assertEquals(2, request20.tx.getInputs().size());
        Coin outValue20 = ZERO;
        for (TransactionOutput out : request20.tx.getOutputs())
            outValue20 = outValue20.add(out.getValue());
        // This time the fee we wanted to pay was more, so that should be what we paid
        assertEquals(outValue20, COIN.add(CENT).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(4)));

        // Same as request 19, but make the change 0 (so it doesnt force fee) and make us require min fee as a
        // result of an output < CENT.
        SendRequest request21 = SendRequest.to(notMyAddr, CENT);
        request21.feePerKb = ZERO;
        for (int i = 0; i < 99; i++)
            request21.tx.addOutput(CENT, notMyAddr);
        request21.tx.addOutput(CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), notMyAddr);
        // If we send without a feePerKb, we should still require REFERENCE_DEFAULT_MIN_TX_FEE because we have an output < 0.01
        wallet.completeTx(request21);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request21.tx.getFee());
        assertEquals(2, request21.tx.getInputs().size());
        Coin outValue21 = ZERO;
        for (TransactionOutput out : request21.tx.getOutputs())
            outValue21 = outValue21.add(out.getValue());
        assertEquals(outValue21, COIN.add(CENT).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE));

        // Test feePerKb when we aren't using ensureMinRequiredFee
        // Same as request 19
        SendRequest request25 = SendRequest.to(notMyAddr, CENT);
        request25.feePerKb = ZERO;
        for (int i = 0; i < 70; i++)
            request25.tx.addOutput(CENT, notMyAddr);
        // If we send now, we shouldn't need a fee and should only have to spend our COIN
        wallet.completeTx(request25);
        assertEquals(ZERO, request25.tx.getFee());
        assertEquals(1, request25.tx.getInputs().size());
        assertEquals(72, request25.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request25.tx.clearInputs();
        request25 = SendRequest.forTx(request25.tx);
        request25.feePerKb = CENT.divide(3);
        request25.ensureMinRequiredFee = false;
        request25.shuffleOutputs = false;
        wallet.completeTx(request25);
        assertEquals(CENT.subtract(SATOSHI), request25.tx.getFee());
        assertEquals(2, request25.tx.getInputs().size());
        Coin outValue25 = ZERO;
        for (TransactionOutput out : request25.tx.getOutputs())
            outValue25 = outValue25.add(out.getValue());
        // Our change output should be one satoshi
        assertEquals(SATOSHI, request25.tx.getOutput(request25.tx.getOutputs().size() - 1).getValue());
        // and our fee should be CENT-1 satoshi
        assertEquals(outValue25, COIN.add(SATOSHI));

        // Spend our CENT output.
        Transaction spendTx5 = new Transaction(params);
        spendTx5.addOutput(CENT, notMyAddr);
        spendTx5.addInput(tx5.getOutput(0));
        wallet.signTransaction(SendRequest.forTx(spendTx5));

        wallet.receiveFromBlock(spendTx5, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 4);
        assertEquals(COIN, wallet.getBalance());

        // Ensure change is discarded if it results in a fee larger than the chain (same as 8 and 9 but with feePerKb)
        SendRequest request26 = SendRequest.to(notMyAddr, CENT);
        for (int i = 0; i < 98; i++)
            request26.tx.addOutput(CENT, notMyAddr);
        request26.tx.addOutput(CENT.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)), notMyAddr);
        assertTrue(request26.tx.bitcoinSerialize().length > 1000);
        request26.feePerKb = SATOSHI;
        wallet.completeTx(request26);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT), request26.tx.getFee());
        Transaction spend26 = request26.tx;
        // If a transaction is over 1kb, the set fee should be added
        assertEquals(100, spend26.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        Coin outValue26 = ZERO;
        for (TransactionOutput out : spend26.getOutputs())
            outValue26 = outValue26.add(out.getValue());
        assertEquals(outValue26, COIN.subtract(
                Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Transaction.MIN_NONDUST_OUTPUT)));
    }

    @Test
    public void basicCategoryStepTest() throws Exception {
        // Creates spends that step through the possible fee solver categories
        SendRequest.DEFAULT_FEE_PER_KB = ZERO;
        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a ton of small outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        int i = 0;
        Coin tenThousand = Coin.valueOf(10000);
        while (i <= 100) {
            Transaction tx = createFakeTxWithChangeAddress(params, tenThousand, myAddress, notMyAddr);
            tx.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
            wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }
        Coin balance = wallet.getBalance();

        // Create a spend that will throw away change (category 3 type 2 in which the change causes fee which is worth more than change)
        SendRequest request1 = SendRequest.to(notMyAddr, balance.subtract(SATOSHI));
        wallet.completeTx(request1);
        assertEquals(SATOSHI, request1.tx.getFee());
        assertEquals(request1.tx.getInputs().size(), i); // We should have spent all inputs

        // Give us one more input...
        Transaction tx1 = createFakeTxWithChangeAddress(params, tenThousand, myAddress, notMyAddr);
        tx1.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
        wallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);

        // ... and create a spend that will throw away change (category 3 type 1 in which the change causes dust output)
        SendRequest request2 = SendRequest.to(notMyAddr, balance.subtract(SATOSHI));
        wallet.completeTx(request2);
        assertEquals(SATOSHI, request2.tx.getFee());
        assertEquals(request2.tx.getInputs().size(), i - 1); // We should have spent all inputs - 1

        // Give us one more input...
        Transaction tx2 = createFakeTxWithChangeAddress(params, tenThousand, myAddress, notMyAddr);
        tx2.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);

        // ... and create a spend that will throw away change (category 3 type 1 in which the change causes dust output)
        // but that also could have been category 2 if it wanted
        SendRequest request3 = SendRequest.to(notMyAddr, CENT.add(tenThousand).subtract(SATOSHI));
        wallet.completeTx(request3);
        assertEquals(SATOSHI, request3.tx.getFee());
        assertEquals(request3.tx.getInputs().size(), i - 2); // We should have spent all inputs - 2

        //
        SendRequest request4 = SendRequest.to(notMyAddr, balance.subtract(SATOSHI));
        request4.feePerKb = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.divide(request3.tx.bitcoinSerialize().length);
        wallet.completeTx(request4);
        assertEquals(SATOSHI, request4.tx.getFee());
        assertEquals(request4.tx.getInputs().size(), i - 2); // We should have spent all inputs - 2

        // Give us a few more inputs...
        while (wallet.getBalance().compareTo(CENT.multiply(2)) < 0) {
            Transaction tx3 = createFakeTxWithChangeAddress(params, tenThousand, myAddress, notMyAddr);
            tx3.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
            wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }

        // ...that is just slightly less than is needed for category 1
        SendRequest request5 = SendRequest.to(notMyAddr, CENT.add(tenThousand).subtract(SATOSHI));
        wallet.completeTx(request5);
        assertEquals(SATOSHI, request5.tx.getFee());
        assertEquals(1, request5.tx.getOutputs().size()); // We should have no change output

        // Give us one more input...
        Transaction tx4 = createFakeTxWithChangeAddress(params, tenThousand, myAddress, notMyAddr);
        tx4.getInput(0).setSequenceNumber(i); // Keep every transaction unique
        wallet.receiveFromBlock(tx4, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);

        // ... that puts us in category 1 (no fee!)
        SendRequest request6 = SendRequest.to(notMyAddr, CENT.add(tenThousand).subtract(SATOSHI));
        wallet.completeTx(request6);
        assertEquals(ZERO, request6.tx.getFee());
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
        while (i <= CENT.divide(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(10))) {
            Transaction tx = createFakeTxWithChangeAddress(params, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(10), myAddress, notMyAddr);
            tx.getInput(0).setSequenceNumber(i++); // Keep every transaction unique
            wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }

        // The selector will choose 2 with MIN_TX_FEE fee
        SendRequest request1 = SendRequest.to(notMyAddr, CENT.add(SATOSHI));
        wallet.completeTx(request1);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request1.tx.getFee());
        assertEquals(request1.tx.getInputs().size(), i); // We should have spent all inputs
        assertEquals(2, request1.tx.getOutputs().size()); // and gotten change back
    }

    @Test
    public void transactionGetFeeTest() throws Exception {
        Address notMyAddr = new ECKey().toAddress(params);

        // Prepare wallet to spend
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(params, COIN, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);

        // Create a transaction
        SendRequest request = SendRequest.to(notMyAddr, CENT);
        request.feePerKb = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;
        wallet.completeTx(request);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request.tx.getFee());
    }

    @Test
    public void lowerThanDefaultFee() throws InsufficientMoneyException {
        Coin fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.divide(10);
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        SendRequest req = SendRequest.to(myAddress, Coin.CENT);
        req.feePerKb = fee;
        wallet.completeTx(req);
        assertEquals(fee, req.tx.getFee());
        wallet.commitTx(req.tx);
        SendRequest emptyReq = SendRequest.emptyWallet(myAddress);
        emptyReq.feePerKb = fee;
        emptyReq.emptyWallet = true;
        emptyReq.coinSelector = AllowUnconfirmedCoinSelector.get();
        wallet.completeTx(emptyReq);
        assertEquals(fee, emptyReq.tx.getFee());
        wallet.commitTx(emptyReq.tx);
    }

    @Test
    public void higherThanDefaultFee() throws InsufficientMoneyException {
        Coin fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(10);
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        SendRequest req = SendRequest.to(myAddress, Coin.CENT);
        req.feePerKb = fee;
        wallet.completeTx(req);
        assertEquals(fee, req.tx.getFee());
        wallet.commitTx(req.tx);
        SendRequest emptyReq = SendRequest.emptyWallet(myAddress);
        emptyReq.feePerKb = fee;
        emptyReq.emptyWallet = true;
        emptyReq.coinSelector = AllowUnconfirmedCoinSelector.get();
        wallet.completeTx(emptyReq);
        assertEquals(fee, emptyReq.tx.getFee());
        wallet.commitTx(emptyReq.tx);
    }

    @Test
    public void feePerKbCategoryJumpTest() throws Exception {
        // Simple test of boundary condition on fee per kb in category fee solver

        // Make sure TestWithWallet isnt doing anything crazy.
        assertEquals(0, wallet.getTransactions(true).size());

        Address notMyAddr = new ECKey().toAddress(params);

        // Generate a ton of small outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, notMyAddr), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(params, COIN, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        Transaction tx2 = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        Transaction tx3 = createFakeTx(params, SATOSHI, myAddress);
        wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 2);

        // Create a transaction who's max size could be up to 1000 (if signatures were maximum size)
        SendRequest request1 = SendRequest.to(notMyAddr, COIN.subtract(CENT.multiply(17)));
        for (int i = 0; i < 16; i++)
            request1.tx.addOutput(CENT, notMyAddr);
        request1.tx.addOutput(new TransactionOutput(params, request1.tx, CENT, new byte[16]));
        request1.fee = SATOSHI;
        request1.feePerKb = SATOSHI;
        // We get a category 2 using COIN+CENT
        // It spends COIN + 1(fee) and because its output is thus < CENT, we have to pay MIN_TX_FEE
        // When it tries category 1, its too large and requires COIN + 2 (fee)
        // This adds the next input, but still has a < CENT output which means it cant reach category 1
        wallet.completeTx(request1);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request1.tx.getFee());
        assertEquals(2, request1.tx.getInputs().size());

        // We then add one more satoshi output to the wallet
        Transaction tx4 = createFakeTx(params, SATOSHI, myAddress);
        wallet.receiveFromBlock(tx4, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 3);

        // Create a transaction who's max size could be up to 1000 (if signatures were maximum size)
        SendRequest request2 = SendRequest.to(notMyAddr, COIN.subtract(CENT.multiply(17)));
        for (int i = 0; i < 16; i++)
            request2.tx.addOutput(CENT, notMyAddr);
        request2.tx.addOutput(new TransactionOutput(params, request2.tx, CENT, new byte[16]));
        request2.feePerKb = SATOSHI;
        // The process is the same as above, but now we can complete category 1 with one more input, and pay a fee of 2
        wallet.completeTx(request2);
        assertEquals(SATOSHI.multiply(2), request2.tx.getFee());
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
        Transaction tx1 = createFakeTx(params, COIN, myAddress);
        wallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        Transaction tx2 = createFakeTx(params, COIN, myAddress); assertTrue(!tx1.getHash().equals(tx2.getHash()));
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        Transaction tx3 = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 2);

        SendRequest request1 = SendRequest.to(notMyAddr, CENT);
        // If we just complete as-is, we will use one of the COIN outputs to get higher priority,
        // resulting in a change output
        request1.shuffleOutputs = false;
        wallet.completeTx(request1);
        assertEquals(1, request1.tx.getInputs().size());
        assertEquals(2, request1.tx.getOutputs().size());
        assertEquals(CENT, request1.tx.getOutput(0).getValue());
        assertEquals(COIN.subtract(CENT), request1.tx.getOutput(1).getValue());

        // Now create an identical request2 and add an unsigned spend of the CENT output
        SendRequest request2 = SendRequest.to(notMyAddr, CENT);
        request2.tx.addInput(tx3.getOutput(0));
        // Now completeTx will result in one input, one output
        wallet.completeTx(request2);
        assertEquals(1, request2.tx.getInputs().size());
        assertEquals(1, request2.tx.getOutputs().size());
        assertEquals(CENT, request2.tx.getOutput(0).getValue());
        // Make sure it was properly signed
        request2.tx.getInput(0).getScriptSig().correctlySpends(request2.tx, 0, tx3.getOutput(0).getScriptPubKey());

        // However, if there is no connected output, we will grab a COIN output anyway and add the CENT to fee
        SendRequest request3 = SendRequest.to(notMyAddr, CENT);
        request3.tx.addInput(new TransactionInput(params, request3.tx, new byte[]{}, new TransactionOutPoint(params, 0, tx3.getHash())));
        // Now completeTx will result in two inputs, two outputs and a fee of a CENT
        // Note that it is simply assumed that the inputs are correctly signed, though in fact the first is not
        request3.shuffleOutputs = false;
        wallet.completeTx(request3);
        assertEquals(2, request3.tx.getInputs().size());
        assertEquals(2, request3.tx.getOutputs().size());
        assertEquals(CENT, request3.tx.getOutput(0).getValue());
        assertEquals(COIN.subtract(CENT), request3.tx.getOutput(1).getValue());

        SendRequest request4 = SendRequest.to(notMyAddr, CENT);
        request4.tx.addInput(tx3.getOutput(0));
        // Now if we manually sign it, completeTx will not replace our signature
        wallet.signTransaction(request4);
        byte[] scriptSig = request4.tx.getInput(0).getScriptBytes();
        wallet.completeTx(request4);
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
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                log.info("onCoinsReceived 1");
                throw new RuntimeException("barf");
            }
        });
        final AtomicInteger flag = new AtomicInteger();
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                log.info("onCoinsReceived 2");
                flag.incrementAndGet();
            }
        });

        sendMoneyToWallet(COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        log.info("Wait for user thread");
        Threading.waitForUserCode();
        log.info("... and test flag.");
        assertEquals(1, flag.get());
    }

    @Test
    public void testEmptyRandomWallet() throws Exception {
        // Add a random set of outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, new ECKey().toAddress(params)), BigInteger.ONE, 1);
        Random rng = new Random();
        for (int i = 0; i < rng.nextInt(100) + 1; i++) {
            Transaction tx = createFakeTx(params, Coin.valueOf(rng.nextInt((int) COIN.value)), myAddress);
            wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }
        SendRequest request = SendRequest.emptyWallet(new ECKey().toAddress(params));
        wallet.completeTx(request);
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
    }

    @Test
    public void testEmptyWallet() throws Exception {
        Address outputKey = new ECKey().toAddress(params);
        // Add exactly 0.01
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, outputKey), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        SendRequest request = SendRequest.emptyWallet(outputKey);
        wallet.completeTx(request);
        assertEquals(Wallet.SendRequest.DEFAULT_FEE_PER_KB, request.tx.getFee());
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(CENT, request.tx.getOutput(0).getValue());

        // Add 1 confirmed cent and 1 unconfirmed cent. Verify only one cent is emptied because of the coin selection
        // policies that are in use by default.
        block = new StoredBlock(makeSolvedTestBlock(blockStore, outputKey), BigInteger.ONE, 1);
        tx = createFakeTx(params, CENT, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        tx = createFakeTx(params, CENT, myAddress);
        wallet.receivePending(tx, null);
        request = SendRequest.emptyWallet(outputKey);
        wallet.completeTx(request);
        assertEquals(Wallet.SendRequest.DEFAULT_FEE_PER_KB, request.tx.getFee());
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(CENT, request.tx.getOutput(0).getValue());

        // Add just under 0.01
        StoredBlock block2 = new StoredBlock(block.getHeader().createNextBlock(outputKey), BigInteger.ONE, 2);
        tx = createFakeTx(params, CENT.subtract(SATOSHI), myAddress);
        wallet.receiveFromBlock(tx, block2, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        request = SendRequest.emptyWallet(outputKey);
        wallet.completeTx(request);
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, request.tx.getFee());
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(CENT.subtract(SATOSHI).subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), request.tx.getOutput(0).getValue());

        // Add an unsendable value
        StoredBlock block3 = new StoredBlock(block2.getHeader().createNextBlock(outputKey), BigInteger.ONE, 3);
        Coin outputValue = Transaction.MIN_NONDUST_OUTPUT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE).subtract(SATOSHI);
        tx = createFakeTx(params, outputValue, myAddress);
        wallet.receiveFromBlock(tx, block3, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        try {
            request = SendRequest.emptyWallet(outputKey);
            wallet.completeTx(request);
            fail();
        } catch (Wallet.CouldNotAdjustDownwards e) {}
        request = SendRequest.emptyWallet(outputKey);
        request.ensureMinRequiredFee = false;
        wallet.completeTx(request);
        assertEquals(ZERO, request.tx.getFee());
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(outputValue, request.tx.getOutput(0).getValue());
    }

    @Test
    public void keyRotationRandom() throws Exception {
        Utils.setMockClock();
        // Start with an empty wallet (no HD chain).
        wallet = new Wallet(params);
        // Watch out for wallet-initiated broadcasts.
        MockTransactionBroadcaster broadcaster = new MockTransactionBroadcaster(wallet);
        // Send three cents to two different random keys, then add a key and mark the initial keys as compromised.
        ECKey key1 = new ECKey();
        key1.setCreationTimeSeconds(Utils.currentTimeSeconds() - (86400 * 2));
        ECKey key2 = new ECKey();
        key2.setCreationTimeSeconds(Utils.currentTimeSeconds() - 86400);
        wallet.importKey(key1);
        wallet.importKey(key2);
        sendMoneyToWallet(wallet, CENT, key1.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(wallet, CENT, key2.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(wallet, CENT, key2.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Date compromiseTime = Utils.now();
        assertEquals(0, broadcaster.size());
        assertFalse(wallet.isKeyRotating(key1));

        // We got compromised!
        Utils.rollMockClock(1);
        wallet.setKeyRotationTime(compromiseTime);
        assertTrue(wallet.isKeyRotating(key1));
        wallet.doMaintenance(null, true);

        Transaction tx = broadcaster.waitForTransactionAndSucceed();
        final Coin THREE_CENTS = CENT.add(CENT).add(CENT);
        assertEquals(THREE_CENTS, tx.getValueSentFromMe(wallet));
        assertEquals(THREE_CENTS.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), tx.getValueSentToMe(wallet));
        // TX sends to one of our addresses (for now we ignore married wallets).
        final Address toAddress = tx.getOutput(0).getScriptPubKey().getToAddress(params);
        final ECKey rotatingToKey = wallet.findKeyFromPubHash(toAddress.getHash160());
        assertNotNull(rotatingToKey);
        assertFalse(wallet.isKeyRotating(rotatingToKey));
        assertEquals(3, tx.getInputs().size());
        // It confirms.
        sendMoneyToWallet(tx, AbstractBlockChain.NewBlockType.BEST_CHAIN);

        // Now receive some more money to the newly derived address via a new block and check that nothing happens.
        sendMoneyToWallet(wallet, CENT, toAddress, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertTrue(wallet.doMaintenance(null, true).get().isEmpty());
        assertEquals(0, broadcaster.size());

        // Receive money via a new block on key1 and ensure it shows up as a maintenance task.
        sendMoneyToWallet(wallet, CENT, key1.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        wallet.doMaintenance(null, true);
        tx = broadcaster.waitForTransactionAndSucceed();
        assertNotNull(wallet.findKeyFromPubHash(tx.getOutput(0).getScriptPubKey().getPubKeyHash()));
        log.info("Unexpected thing: {}", tx);
        assertEquals(1, tx.getInputs().size());
        assertEquals(1, tx.getOutputs().size());
        assertEquals(CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), tx.getOutput(0).getValue());

        assertEquals(Transaction.Purpose.KEY_ROTATION, tx.getPurpose());

        // We don't attempt to race an attacker against unconfirmed transactions.

        // Now round-trip the wallet and check the protobufs are storing the data correctly.
        wallet = roundTrip(wallet);

        tx = wallet.getTransaction(tx.getHash());
        checkNotNull(tx);
        assertEquals(Transaction.Purpose.KEY_ROTATION, tx.getPurpose());
        // Have to divide here to avoid mismatch due to second-level precision in serialisation.
        assertEquals(compromiseTime.getTime() / 1000, wallet.getKeyRotationTime().getTime() / 1000);

        // Make a normal spend and check it's all ok.
        final Address address = new ECKey().toAddress(params);
        wallet.sendCoins(broadcaster, address, wallet.getBalance());
        tx = broadcaster.waitForTransaction();
        assertArrayEquals(address.getHash160(), tx.getOutput(0).getScriptPubKey().getPubKeyHash());
    }

    private Wallet roundTrip(Wallet wallet) throws UnreadableWalletException {
        Protos.Wallet protos = new WalletProtobufSerializer().walletToProto(wallet);
        return new WalletProtobufSerializer().readWallet(params, null, protos);
    }

    @Test
    public void keyRotationHD() throws Exception {
        // Test that if we rotate an HD chain, a new one is created and all arrivals on the old keys are moved.
        Utils.setMockClock();
        wallet = new Wallet(params);
        ECKey key1 = wallet.freshReceiveKey();
        ECKey key2 = wallet.freshReceiveKey();
        sendMoneyToWallet(wallet, CENT, key1.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(wallet, CENT, key2.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        DeterministicKey watchKey1 = wallet.getWatchingKey();

        // A day later, we get compromised.
        Utils.rollMockClock(86400);
        wallet.setKeyRotationTime(Utils.currentTimeSeconds());

        List<Transaction> txns = wallet.doMaintenance(null, false).get();
        assertEquals(1, txns.size());
        DeterministicKey watchKey2 = wallet.getWatchingKey();
        assertNotEquals(watchKey1, watchKey2);
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    public void keyRotationHD2() throws Exception {
        // Check we handle the following scenario: a weak random key is created, then some good random keys are created
        // but the weakness of the first isn't known yet. The wallet is upgraded to HD based on the weak key. Later, we
        // find out about the weakness and set the rotation time to after the bad key's creation date. A new HD chain
        // should be created based on the oldest known good key and the old chain + bad random key should rotate to it.

        // We fix the private keys just to make the test deterministic (last byte differs).
        Utils.setMockClock();
        ECKey badKey = ECKey.fromPrivate(Utils.HEX.decode("00905b93f990267f4104f316261fc10f9f983551f9ef160854f40102eb71cffdbb"));
        badKey.setCreationTimeSeconds(Utils.currentTimeSeconds());
        Utils.rollMockClock(86400);
        ECKey goodKey = ECKey.fromPrivate(Utils.HEX.decode("00905b93f990267f4104f316261fc10f9f983551f9ef160854f40102eb71cffdcc"));
        goodKey.setCreationTimeSeconds(Utils.currentTimeSeconds());

        // Do an upgrade based on the bad key.
        final AtomicReference<List<DeterministicKeyChain>> fChains = new AtomicReference<List<DeterministicKeyChain>>();
        KeyChainGroup kcg = new KeyChainGroup(params) {

            {
                fChains.set(chains);
            }
        };
        kcg.importKeys(badKey, goodKey);
        Utils.rollMockClock(86400);
        wallet = new Wallet(params, kcg);   // This avoids the automatic HD initialisation
        assertTrue(fChains.get().isEmpty());
        wallet.upgradeToDeterministic(null);
        DeterministicKey badWatchingKey = wallet.getWatchingKey();
        assertEquals(badKey.getCreationTimeSeconds(), badWatchingKey.getCreationTimeSeconds());
        sendMoneyToWallet(wallet, CENT, badWatchingKey.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);

        // Now we set the rotation time to the time we started making good keys. This should create a new HD chain.
        wallet.setKeyRotationTime(goodKey.getCreationTimeSeconds());
        List<Transaction> txns = wallet.doMaintenance(null, false).get();
        assertEquals(1, txns.size());
        Address output = txns.get(0).getOutput(0).getAddressFromP2PKHScript(params);
        ECKey usedKey = wallet.findKeyFromPubHash(output.getHash160());
        assertEquals(goodKey.getCreationTimeSeconds(), usedKey.getCreationTimeSeconds());
        assertEquals(goodKey.getCreationTimeSeconds(), wallet.freshReceiveKey().getCreationTimeSeconds());
        assertEquals("mrM3TpCnav5YQuVA1xLercCGJH4DXujMtv", usedKey.toAddress(params).toString());
        DeterministicKeyChain c = fChains.get().get(1);
        assertEquals(c.getEarliestKeyCreationTime(), goodKey.getCreationTimeSeconds());
        assertEquals(2, fChains.get().size());

        // Commit the maint txns.
        wallet.commitTx(txns.get(0));

        // Check next maintenance does nothing.
        assertTrue(wallet.doMaintenance(null, false).get().isEmpty());
        assertEquals(c, fChains.get().get(1));
        assertEquals(2, fChains.get().size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void importOfHDKeyForbidden() throws Exception {
        wallet.importKey(wallet.freshReceiveKey());
    }

    //@Test   //- this test is slow, disable for now.
    public void fragmentedReKeying() throws Exception {
        // Send lots of small coins and check the fee is correct.
        ECKey key = wallet.freshReceiveKey();
        Address address = key.toAddress(params);
        Utils.setMockClock();
        Utils.rollMockClock(86400);
        for (int i = 0; i < 800; i++) {
            sendMoneyToWallet(wallet, CENT, address, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        }

        MockTransactionBroadcaster broadcaster = new MockTransactionBroadcaster(wallet);

        Date compromise = Utils.now();
        Utils.rollMockClock(86400);
        wallet.freshReceiveKey();
        wallet.setKeyRotationTime(compromise);
        wallet.doMaintenance(null, true);

        Transaction tx = broadcaster.waitForTransactionAndSucceed();
        final Coin valueSentToMe = tx.getValueSentToMe(wallet);
        Coin fee = tx.getValueSentFromMe(wallet).subtract(valueSentToMe);
        assertEquals(Coin.valueOf(900000), fee);
        assertEquals(KeyTimeCoinSelector.MAX_SIMULTANEOUS_INPUTS, tx.getInputs().size());
        assertEquals(Coin.valueOf(599100000), valueSentToMe);

        tx = broadcaster.waitForTransaction();
        assertNotNull(tx);
        assertEquals(200, tx.getInputs().size());
    }

    @Test
    public void completeTxPartiallySignedWithDummySigs() throws Exception {
        byte[] dummySig = TransactionSignature.dummy().encodeToBitcoin();
        completeTxPartiallySigned(Wallet.MissingSigsMode.USE_DUMMY_SIG, dummySig);
    }

    @Test
    public void completeTxPartiallySignedWithEmptySig() throws Exception {
        byte[] emptySig = {};
        completeTxPartiallySigned(Wallet.MissingSigsMode.USE_OP_ZERO, emptySig);
    }

    @Test (expected = ECKey.MissingPrivateKeyException.class)
    public void completeTxPartiallySignedThrows() throws Exception {
        sendMoneyToWallet(wallet, CENT, wallet.freshReceiveKey(), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        SendRequest req = SendRequest.emptyWallet(new ECKey().toAddress(params));
        wallet.completeTx(req);
        // Delete the sigs
        for (TransactionInput input : req.tx.getInputs())
            input.setScriptBytes(new byte[]{});
        Wallet watching = Wallet.fromWatchingKey(params, wallet.getWatchingKey().dropParent().dropPrivateBytes());
        watching.completeTx(Wallet.SendRequest.forTx(req.tx));
    }

    @Test
    public void completeTxPartiallySignedMarriedWithDummySigs() throws Exception {
        byte[] dummySig = TransactionSignature.dummy().encodeToBitcoin();
        completeTxPartiallySignedMarried(Wallet.MissingSigsMode.USE_DUMMY_SIG, dummySig);
    }

    @Test
    public void completeTxPartiallySignedMarriedWithEmptySig() throws Exception {
        byte[] emptySig = {};
        completeTxPartiallySignedMarried(Wallet.MissingSigsMode.USE_OP_ZERO, emptySig);
    }

    @Test (expected = TransactionSigner.MissingSignatureException.class)
    public void completeTxPartiallySignedMarriedThrows() throws Exception {
        byte[] emptySig = {};
        completeTxPartiallySignedMarried(Wallet.MissingSigsMode.THROW, emptySig);
    }

    @Test (expected = TransactionSigner.MissingSignatureException.class)
    public void completeTxPartiallySignedMarriedThrowsByDefault() throws Exception {
        createMarriedWallet(2, 2, false);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        sendMoneyToWallet(wallet, COIN, myAddress, AbstractBlockChain.NewBlockType.BEST_CHAIN);

        Wallet.SendRequest req = Wallet.SendRequest.emptyWallet(new ECKey().toAddress(params));
        wallet.completeTx(req);
    }

    public void completeTxPartiallySignedMarried(Wallet.MissingSigsMode missSigMode, byte[] expectedSig) throws Exception {
        // create married wallet without signer
        createMarriedWallet(2, 2, false);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        sendMoneyToWallet(wallet, COIN, myAddress, AbstractBlockChain.NewBlockType.BEST_CHAIN);

        ECKey dest = new ECKey();
        Wallet.SendRequest req = Wallet.SendRequest.emptyWallet(dest.toAddress(params));
        req.missingSigsMode = missSigMode;
        wallet.completeTx(req);
        TransactionInput input = req.tx.getInput(0);

        boolean firstSigIsMissing = Arrays.equals(expectedSig, input.getScriptSig().getChunks().get(1).data);
        boolean secondSigIsMissing = Arrays.equals(expectedSig, input.getScriptSig().getChunks().get(2).data);

        assertTrue("Only one of the signatures should be missing/dummy", firstSigIsMissing ^ secondSigIsMissing);
        int localSigIndex = firstSigIsMissing ? 2 : 1;
        int length = input.getScriptSig().getChunks().get(localSigIndex).data.length;
        assertTrue("Local sig should be present: " + length, length >= 70);
    }


    @SuppressWarnings("ConstantConditions")
    public void completeTxPartiallySigned(Wallet.MissingSigsMode missSigMode, byte[] expectedSig) throws Exception {
        // Check the wallet will write dummy scriptSigs for inputs that we have only pubkeys for without the privkey.
        ECKey priv = new ECKey();
        ECKey pub = ECKey.fromPublicOnly(priv.getPubKeyPoint());
        wallet.importKey(pub);
        ECKey priv2 = wallet.freshReceiveKey();
        // Send three transactions, with one being an address type and the other being a raw CHECKSIG type pubkey only,
        // and the final one being a key we do have. We expect the first two inputs to be dummy values and the last
        // to be signed correctly.
        Transaction t1 = sendMoneyToWallet(wallet, CENT, pub.toAddress(params), AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Transaction t2 = sendMoneyToWallet(wallet, CENT, pub, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Transaction t3 = sendMoneyToWallet(wallet, CENT, priv2, AbstractBlockChain.NewBlockType.BEST_CHAIN);

        ECKey dest = new ECKey();
        Wallet.SendRequest req = Wallet.SendRequest.emptyWallet(dest.toAddress(params));
        req.missingSigsMode = missSigMode;
        wallet.completeTx(req);
        byte[] dummySig = TransactionSignature.dummy().encodeToBitcoin();
        // Selected inputs can be in any order.
        for (int i = 0; i < req.tx.getInputs().size(); i++) {
            TransactionInput input = req.tx.getInput(i);
            if (input.getConnectedOutput().getParentTransaction().equals(t1)) {
                assertArrayEquals(expectedSig, input.getScriptSig().getChunks().get(0).data);
            } else if (input.getConnectedOutput().getParentTransaction().equals(t2)) {
                assertArrayEquals(expectedSig, input.getScriptSig().getChunks().get(0).data);
            } else if (input.getConnectedOutput().getParentTransaction().equals(t3)) {
                input.getScriptSig().correctlySpends(req.tx, i, t3.getOutput(0).getScriptPubKey());
            }
        }
        assertTrue(TransactionSignature.isEncodingCanonical(dummySig));
    }

    @Test
    public void riskAnalysis() throws Exception {
        // Send a tx that is considered risky to the wallet, verify it doesn't show up in the balances.
        final Transaction tx = createFakeTx(params, COIN, myAddress);
        final AtomicBoolean bool = new AtomicBoolean();
        wallet.setRiskAnalyzer(new RiskAnalysis.Analyzer() {
            @Override
            public RiskAnalysis create(Wallet wallet, Transaction wtx, List<Transaction> dependencies) {
                RiskAnalysis.Result result = RiskAnalysis.Result.OK;
                if (wtx.getHash().equals(tx.getHash()))
                    result = RiskAnalysis.Result.NON_STANDARD;
                final RiskAnalysis.Result finalResult = result;
                return new RiskAnalysis() {
                    @Override
                    public Result analyze() {
                        bool.set(true);
                        return finalResult;
                    }
                };
            }
        });
        assertTrue(wallet.isPendingTransactionRelevant(tx));
        assertEquals(Coin.ZERO, wallet.getBalance());
        assertEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        wallet.receivePending(tx, null);
        assertEquals(Coin.ZERO, wallet.getBalance());
        assertEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertTrue(bool.get());
        // Confirm it in the same manner as how Bloom filtered blocks do. Verify it shows up.
        StoredBlock block = createFakeBlock(blockStore, tx).storedBlock;
        wallet.notifyTransactionIsInBlock(tx.getHash(), block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        assertEquals(COIN, wallet.getBalance());
    }

    @Test
    public void transactionInBlockNotification() {
        final Transaction tx = createFakeTx(params, COIN, myAddress);
        StoredBlock block = createFakeBlock(blockStore, tx).storedBlock;
        wallet.receivePending(tx, null);
        boolean notification = wallet.notifyTransactionIsInBlock(tx.getHash(), block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        assertTrue(notification);

        Address notMyAddr = new ECKey().toAddress(params);
        final Transaction tx2 = createFakeTx(params, COIN, notMyAddr);
        wallet.receivePending(tx2, null);
        StoredBlock block2 = createFakeBlock(blockStore, tx2).storedBlock;
        boolean notification2 = wallet.notifyTransactionIsInBlock(tx2.getHash(), block2, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        assertFalse(notification2);
    }

    @Test
    public void duplicatedBlock() {
        final Transaction tx = createFakeTx(params, COIN, myAddress);
        StoredBlock block = createFakeBlock(blockStore, tx).storedBlock;
        wallet.notifyNewBestBlock(block);
        wallet.notifyNewBestBlock(block);
    }

    @Test
    public void keyEvents() throws Exception {
        // Check that we can register an event listener, generate some keys and the callbacks are invoked properly.
        wallet = new Wallet(params);
        final List<ECKey> keys = Lists.newLinkedList();
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> k) {
                keys.addAll(k);
            }
        }, Threading.SAME_THREAD);
        wallet.freshReceiveKey();
        assertEquals(1, keys.size());
    }

    @Test
    public void upgradeToHDUnencrypted() throws Exception {
        // This isn't very deep because most of it is tested in KeyChainGroupTest and Wallet just forwards most logic
        // there. We're mostly concerned with the slightly different auto upgrade logic: KeyChainGroup won't do an
        // on-demand auto upgrade of the wallet to HD even in the unencrypted case, because the key rotation time is
        // a property of the Wallet, not the KeyChainGroup (it should perhaps be moved at some point - it doesn't matter
        // much where it goes). Wallet on the other hand will try to auto-upgrade you when possible.

        // Create an old-style random wallet.
        KeyChainGroup group = new KeyChainGroup(params);
        group.importKeys(new ECKey(), new ECKey());
        wallet = new Wallet(params, group);
        assertTrue(wallet.isDeterministicUpgradeRequired());
        // Use an HD feature.
        wallet.freshReceiveKey();
        assertFalse(wallet.isDeterministicUpgradeRequired());
    }

    @Test
    public void upgradeToHDEncrypted() throws Exception {
        // Create an old-style random wallet.
        KeyChainGroup group = new KeyChainGroup(params);
        group.importKeys(new ECKey(), new ECKey());
        wallet = new Wallet(params, group);
        assertTrue(wallet.isDeterministicUpgradeRequired());
        KeyCrypter crypter = new KeyCrypterScrypt();
        KeyParameter aesKey = crypter.deriveKey("abc");
        wallet.encrypt(crypter, aesKey);
        try {
            wallet.freshReceiveKey();
        } catch (DeterministicUpgradeRequiresPassword e) {
            // Expected.
        }
        wallet.upgradeToDeterministic(aesKey);
        assertFalse(wallet.isDeterministicUpgradeRequired());
        wallet.freshReceiveKey();  // works.
    }

    @Test(expected = IllegalStateException.class)
    public void shouldNotAddTransactionSignerThatIsNotReady() throws Exception {
        wallet.addTransactionSigner(new NopTransactionSigner(false));
    }

    @Test
    public void transactionSignersShouldBeSerializedAlongWithWallet() throws Exception {
        TransactionSigner signer = new NopTransactionSigner(true);
        wallet.addTransactionSigner(signer);
        assertEquals(2, wallet.getTransactionSigners().size());
        wallet = roundTrip(wallet);
        assertEquals(2, wallet.getTransactionSigners().size());
        assertTrue(wallet.getTransactionSigners().get(1).isReady());
    }

    @Test
    public void watchingMarriedWallet() throws Exception {
        DeterministicKey watchKey = wallet.getWatchingKey();
        String serialized = watchKey.serializePubB58(params);
        watchKey = DeterministicKey.deserializeB58(null, serialized, params);
        Wallet wallet = Wallet.fromWatchingKey(params, watchKey);
        blockStore = new MemoryBlockStore(params);
        chain = new BlockChain(params, wallet, blockStore);

        final DeterministicKeyChain keyChain = new DeterministicKeyChain(new SecureRandom());
        DeterministicKey partnerKey = DeterministicKey.deserializeB58(null, keyChain.getWatchingKey().serializePubB58(params), params);

        TransactionSigner signer = new StatelessTransactionSigner() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public boolean signInputs(ProposedTransaction propTx, KeyBag keyBag) {
                assertEquals(propTx.partialTx.getInputs().size(), propTx.keyPaths.size());
                List<ChildNumber> externalZeroLeaf = ImmutableList.<ChildNumber>builder()
                        .addAll(DeterministicKeyChain.ACCOUNT_ZERO_PATH)
                        .addAll(DeterministicKeyChain.EXTERNAL_SUBPATH).add(ChildNumber.ZERO).build();
                for (TransactionInput input : propTx.partialTx.getInputs()) {
                    List<ChildNumber> keypath = propTx.keyPaths.get(input.getConnectedOutput().getScriptPubKey());
                    assertNotNull(keypath);
                    assertEquals(externalZeroLeaf, keypath);
                }
                return true;
            }
        };
        wallet.addTransactionSigner(signer);
        MarriedKeyChain chain = MarriedKeyChain.builder()
                .random(new SecureRandom())
                .followingKeys(partnerKey)
                .build();
        wallet.addAndActivateHDChain(chain);

        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        sendMoneyToWallet(wallet, COIN, myAddress, AbstractBlockChain.NewBlockType.BEST_CHAIN);

        ECKey dest = new ECKey();
        Wallet.SendRequest req = Wallet.SendRequest.emptyWallet(dest.toAddress(params));
        req.missingSigsMode = Wallet.MissingSigsMode.USE_DUMMY_SIG;
        wallet.completeTx(req);
    }

    @Test
    public void sendRequestExchangeRate() throws Exception {
        receiveATransaction(wallet, myAddress);
        SendRequest sendRequest = SendRequest.to(myAddress, Coin.COIN);
        sendRequest.exchangeRate = new ExchangeRate(Fiat.parseFiat("EUR", "500"));
        wallet.completeTx(sendRequest);
        assertEquals(sendRequest.exchangeRate, sendRequest.tx.getExchangeRate());
    }

    @Test
    public void sendRequestMemo() throws Exception {
        receiveATransaction(wallet, myAddress);
        SendRequest sendRequest = SendRequest.to(myAddress, Coin.COIN);
        sendRequest.memo = "memo";
        wallet.completeTx(sendRequest);
        assertEquals(sendRequest.memo, sendRequest.tx.getMemo());
    }

    @Test(expected = java.lang.IllegalStateException.class)
    public void sendCoinsNoBroadcasterTest() throws InsufficientMoneyException {
        ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        Address notMyAddr = key.toAddress(params);
        SendRequest req = SendRequest.to(notMyAddr.getParameters(), key, SATOSHI.multiply(12));
        wallet.sendCoins(req);
    }

    @Test
    public void sendCoinsWithBroadcasterTest() throws InsufficientMoneyException {
        ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        Address notMyAddr = key.toAddress(params);
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        MockTransactionBroadcaster broadcaster = new MockTransactionBroadcaster(wallet);
        wallet.setTransactionBroadcaster(broadcaster);
        SendRequest req = SendRequest.to(notMyAddr.getParameters(), key, Coin.CENT);
        wallet.sendCoins(req);
    }

    @Test
    public void fromKeys() {
        ECKey key = ECKey.fromPrivate(Utils.HEX.decode("00905b93f990267f4104f316261fc10f9f983551f9ef160854f40102eb71cffdcc"));
        Wallet wallet = Wallet.fromKeys(params, Arrays.asList(key));
        assertEquals(1, wallet.getImportedKeys().size());
        assertEquals(key, wallet.getImportedKeys().get(0));
        wallet.upgradeToDeterministic(null);
        String seed = wallet.getKeyChainSeed().toHexString();
        assertEquals("5ca8cd6c01aa004d3c5396c628b78a4a89462f412f460a845b594ac42eceaa264b0e14dcd4fe73d4ed08ce06f4c28facfa85042d26d784ab2798a870bb7af556", seed);
    }

    @Test
    public void reset() {
        sendMoneyToWallet(wallet, COIN, myAddress, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertNotEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertNotEquals(0, wallet.getTransactions(false).size());
        assertNotEquals(0, wallet.getUnspents().size());
        wallet.reset();
        assertEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertEquals(0, wallet.getTransactions(false).size());
        assertEquals(0, wallet.getUnspents().size());
    }
}
