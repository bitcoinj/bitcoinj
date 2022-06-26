/*
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

package org.bitcoinj.wallet;

import com.google.common.collect.Lists;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.crypto.MnemonicException;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.testing.KeyChainTransactionSigner;
import org.bitcoinj.testing.MockTransactionBroadcaster;
import org.bitcoinj.testing.NopTransactionSigner;
import org.bitcoinj.testing.TestWithWallet;
import org.bitcoinj.utils.ExchangeRate;
import org.bitcoinj.base.utils.Fiat;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.KeyChain.KeyPurpose;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;
import org.bitcoinj.wallet.Wallet.BalanceType;
import org.bitcoinj.wallet.WalletTransaction.Pool;
import org.bouncycastle.crypto.params.KeyParameter;
import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.bitcoinj.base.Coin.CENT;
import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.base.Coin.MILLICOIN;
import static org.bitcoinj.base.Coin.SATOSHI;
import static org.bitcoinj.base.Coin.ZERO;
import static org.bitcoinj.base.Coin.valueOf;
import static org.bitcoinj.base.utils.ByteUtils.HEX;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTxWithoutChangeAddress;
import static org.bitcoinj.testing.FakeTxBuilder.makeSolvedTestBlock;
import static org.bitcoinj.testing.FakeTxBuilder.roundTripTransaction;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.replay;
import static org.hamcrest.Matchers.closeTo;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class WalletTest extends TestWithWallet {
    private static final Logger log = LoggerFactory.getLogger(WalletTest.class);

    private static final int SCRYPT_ITERATIONS = 256;
    private static final CharSequence PASSWORD1 = "my helicopter contains eels";
    private static final CharSequence WRONG_PASSWORD = "nothing noone nobody nowhere";

    private final Address OTHER_ADDRESS = LegacyAddress.fromKey(UNITTEST, new ECKey());
    private final Address OTHER_SEGWIT_ADDRESS = SegwitAddress.fromKey(UNITTEST, new ECKey());

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
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        blockStore = new MemoryBlockStore(UNITTEST);
        chain = new BlockChain(UNITTEST, wallet, blockStore);

        List<DeterministicKey> followingKeys = new ArrayList<>();
        for (int i = 0; i < numKeys - 1; i++) {
            final DeterministicKeyChain keyChain = DeterministicKeyChain.builder().random(new SecureRandom()).build();
            DeterministicKey partnerKey = DeterministicKey.deserializeB58(null, keyChain.getWatchingKey().serializePubB58(UNITTEST), UNITTEST);
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
    public void createBasic() {
        Wallet wallet = Wallet.createBasic(UNITTEST);
        assertEquals(0, wallet.getKeyChainGroupSize());
        wallet.importKey(new ECKey());
        assertEquals(1, wallet.getKeyChainGroupSize());
    }

    @Test(expected = IllegalStateException.class)
    public void createBasic_noDerivation() {
        Wallet wallet = Wallet.createBasic(UNITTEST);
        wallet.currentReceiveAddress();
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
        basicSpendingCommon(wallet, myAddress, OTHER_ADDRESS, null);
    }

    @Test
    public void basicSpendingToP2SH() throws Exception {
        Address destination = LegacyAddress.fromScriptHash(UNITTEST, HEX.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        basicSpendingCommon(wallet, myAddress, destination, null);
    }

    @Test
    public void basicSpendingWithEncryptedWallet() throws Exception {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);
        Address myEncryptedAddress = LegacyAddress.fromKey(UNITTEST, encryptedWallet.freshReceiveKey());
        basicSpendingCommon(encryptedWallet, myEncryptedAddress, OTHER_ADDRESS, encryptedWallet);
    }

    @Test
    public void encryptDecryptWalletWithArbitraryPathAndScriptType() throws Exception {
        final byte[] ENTROPY = Sha256Hash.hash("don't use a string seed like this in real life".getBytes());
        KeyChainGroup keyChainGroup = KeyChainGroup.builder(UNITTEST)
                .addChain(DeterministicKeyChain.builder().seed(new DeterministicSeed(ENTROPY, "", 1389353062L))
                        .outputScriptType(ScriptType.P2WPKH)
                        .accountPath(DeterministicKeyChain.BIP44_ACCOUNT_ZERO_PATH).build())
                .build();
        Wallet encryptedWallet = new Wallet(UNITTEST, keyChainGroup);
        encryptedWallet = roundTrip(encryptedWallet);
        encryptedWallet.encrypt(PASSWORD1);
        encryptedWallet = roundTrip(encryptedWallet);
        encryptedWallet.decrypt(PASSWORD1);
        encryptedWallet = roundTrip(encryptedWallet);
    }

    @Test
    public void basicSpendingFromP2SH() throws Exception {
        createMarriedWallet(2, 2);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        basicSpendingCommon(wallet, myAddress, OTHER_ADDRESS, null);

        createMarriedWallet(2, 3);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        basicSpendingCommon(wallet, myAddress, OTHER_ADDRESS, null);

        createMarriedWallet(3, 3);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        basicSpendingCommon(wallet, myAddress, OTHER_ADDRESS, null);
    }

    @Test (expected = IllegalArgumentException.class)
    public void thresholdShouldNotExceedNumberOfKeys() throws Exception {
        createMarriedWallet(3, 2);
    }

    @Test
    public void spendingWithIncompatibleSigners() throws Exception {
        wallet.addTransactionSigner(new NopTransactionSigner(true));
        basicSpendingCommon(wallet, myAddress, OTHER_ADDRESS, null);
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
        wallet.completeTx(req);

        Transaction t2 = req.tx;

        // Broadcast the transaction and commit.
        broadcastAndCommit(wallet, t2);

        // At this point we have one pending and one spent

        Coin v1 = valueOf(0, 10);
        Transaction t = sendMoneyToWallet(null, v1, myAddress);
        Threading.waitForUserCode();
        sendMoneyToWallet(null, t);
        assertEquals("Wrong number of PENDING", 2, wallet.getPoolSize(Pool.PENDING));
        assertEquals("Wrong number of UNSPENT", 0, wallet.getPoolSize(Pool.UNSPENT));
        assertEquals("Wrong number of ALL", 3, wallet.getTransactions(true).size());
        assertEquals(valueOf(0, 60), wallet.getBalance(Wallet.BalanceType.ESTIMATED));

        // Now we have another incoming pending
        return t;
    }

    @Test
    public void cleanup() throws Exception {
        Transaction t = cleanupCommon(OTHER_ADDRESS);

        // Consider the new pending as risky and remove it from the wallet
        wallet.setRiskAnalyzer(new TestRiskAnalysis.Analyzer(t));

        wallet.cleanup();
        assertTrue(wallet.isConsistent());
        assertEquals("Wrong number of PENDING", 1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals("Wrong number of UNSPENT", 0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL", 2, wallet.getTransactions(true).size());
        assertEquals(valueOf(0, 50), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void cleanupFailsDueToSpend() throws Exception {
        Transaction t = cleanupCommon(OTHER_ADDRESS);

        // Now we have another incoming pending.  Spend everything.
        Coin v3 = valueOf(0, 60);
        SendRequest req = SendRequest.to(OTHER_ADDRESS, v3);

        // Force selection of the incoming coin so that we can spend it
        req.coinSelector = new TestCoinSelector();

        wallet.completeTx(req);
        wallet.commitTx(req.tx);

        assertEquals("Wrong number of PENDING", 3, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals("Wrong number of UNSPENT", 0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL", 4, wallet.getTransactions(true).size());

        // Consider the new pending as risky and try to remove it from the wallet
        wallet.setRiskAnalyzer(new TestRiskAnalysis.Analyzer(t));

        wallet.cleanup();
        assertTrue(wallet.isConsistent());

        // The removal should have failed
        assertEquals("Wrong number of PENDING", 3, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals("Wrong number of UNSPENT", 0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL", 4, wallet.getTransactions(true).size());
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
        SendRequest req = SendRequest.to(destination, vHuge);
        try {
            wallet.completeTx(req);
            fail();
        } catch (InsufficientMoneyException e) {
            assertEquals(valueOf(9, 0), e.missing);
        }

        // Prepare to send.
        Coin v2 = valueOf(0, 50);
        req = SendRequest.to(destination, v2);

        if (encryptedWallet != null) {
            KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
            KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);
            KeyParameter wrongAesKey = keyCrypter.deriveKey(WRONG_PASSWORD);

            // Try to create a send with a fee but no password (this should fail).
            try {
                wallet.completeTx(req);
                fail();
            } catch (ECKey.MissingPrivateKeyException kce) {
            }
            assertEquals("Wrong number of UNSPENT", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
            assertEquals("Wrong number of ALL", 1, wallet.getTransactions(true).size());

            // Try to create a send with a fee but the wrong password (this should fail).
            req = SendRequest.to(destination, v2);
            req.aesKey = wrongAesKey;

            try {
                wallet.completeTx(req);
                fail("No exception was thrown trying to sign an encrypted key with the wrong password supplied.");
            } catch (Wallet.BadWalletEncryptionKeyException e) {
                // Expected.
            }

            assertEquals("Wrong number of UNSPENT", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
            assertEquals("Wrong number of ALL", 1, wallet.getTransactions(true).size());

            // Create a send with a fee with the correct password (this should succeed).
            req = SendRequest.to(destination, v2);
            req.aesKey = aesKey;
        }

        // Complete the transaction successfully.
        req.shuffleOutputs = false;
        wallet.completeTx(req);

        Transaction t2 = req.tx;
        assertEquals("Wrong number of UNSPENT", 1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals("Wrong number of ALL", 1, wallet.getTransactions(true).size());
        assertEquals(TransactionConfidence.Source.SELF, t2.getConfidence().getSource());
        assertEquals(Transaction.Purpose.USER_PAYMENT, t2.getPurpose());

        // Do some basic sanity checks.
        basicSanityChecks(wallet, t2, destination);

        // Broadcast the transaction and commit.
        List<TransactionOutput> unspents1 = wallet.getUnspents();
        assertEquals(1, unspents1.size());
        broadcastAndCommit(wallet, t2);
        List<TransactionOutput> unspents2 = wallet.getUnspents();
        assertNotSame(unspents1, unspents2);

        // Now check that we can spend the unconfirmed change, with a new change address of our own selection.
        // (req.aesKey is null for unencrypted / the correct aesKey for encrypted.)
        wallet = spendUnconfirmedChange(wallet, t2, req.aesKey);
        assertNotEquals(unspents2, wallet.getUnspents());
    }

    private void receiveATransaction(Wallet wallet, Address toAddress) throws Exception {
        receiveATransactionAmount(wallet, toAddress, COIN);
    }

    private void receiveATransactionAmount(Wallet wallet, Address toAddress, Coin amount) {
        final CompletableFuture<Coin> availFuture = wallet.getBalanceFuture(amount, Wallet.BalanceType.AVAILABLE);
        final CompletableFuture<Coin> estimatedFuture = wallet.getBalanceFuture(amount, Wallet.BalanceType.ESTIMATED);
        assertFalse(availFuture.isDone());
        assertFalse(estimatedFuture.isDone());
        // Send some pending coins to the wallet.
        Transaction t1 = sendMoneyToWallet(wallet, null, amount, toAddress);
        Threading.waitForUserCode();
        final CompletableFuture<TransactionConfidence> depthFuture = t1.getConfidence().getDepthFuture(1);
        assertFalse(depthFuture.isDone());
        assertEquals(ZERO, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        assertEquals(amount, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertFalse(availFuture.isDone());
        // Our estimated balance has reached the requested level.
        assertTrue(estimatedFuture.isDone());
        assertEquals(1, wallet.getPoolSize(Pool.PENDING));
        assertEquals(0, wallet.getPoolSize(Pool.UNSPENT));
        // Confirm the coins.
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, t1);
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
        assertEquals(destination, t.getOutput(0).getScriptPubKey().getToAddress(UNITTEST));
        assertEquals(wallet.currentChangeAddress(), t.getOutputs().get(1).getScriptPubKey().getToAddress(UNITTEST));
        assertEquals(valueOf(0, 50), t.getOutputs().get(1).getValue());
        // Check the script runs and signatures verify.
        t.getInputs().get(0).verify();
    }

    private static void broadcastAndCommit(Wallet wallet, Transaction t) throws Exception {
        final LinkedList<Transaction> txns = new LinkedList<>();
        wallet.addCoinsSentEventListener((wallet1, tx, prevBalance, newBalance) -> txns.add(tx));

        t.getConfidence().markBroadcastBy(new PeerAddress(UNITTEST, InetAddress.getByAddress(new byte[]{1,2,3,4})));
        t.getConfidence().markBroadcastBy(new PeerAddress(UNITTEST, InetAddress.getByAddress(new byte[]{10,2,3,4})));
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
        Coin v3 = valueOf(0, 50);
        assertEquals(v3, wallet.getBalance());
        SendRequest req = SendRequest.to(OTHER_ADDRESS, valueOf(0, 48));
        req.aesKey = aesKey;
        req.shuffleOutputs = false;
        wallet.completeTx(req);
        Transaction t3 = req.tx;
        assertNotEquals(t2.getOutput(1).getScriptPubKey().getToAddress(UNITTEST),
                        t3.getOutput(1).getScriptPubKey().getToAddress(UNITTEST));
        assertNotNull(t3);
        wallet.commitTx(t3);
        assertTrue(wallet.isConsistent());
        // t2 and t3 gets confirmed in the same block.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, t2, t3);
        assertTrue(wallet.isConsistent());
        return wallet;
    }

    @Test
    public void customTransactionSpending() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        Coin v1 = valueOf(3, 0);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, v1);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());

        Coin v2 = valueOf(0, 50);
        Coin v3 = valueOf(0, 75);
        Coin v4 = valueOf(1, 25);

        Transaction t2 = new Transaction(UNITTEST);
        t2.addOutput(v2, OTHER_ADDRESS);
        t2.addOutput(v3, OTHER_ADDRESS);
        t2.addOutput(v4, OTHER_ADDRESS);
        SendRequest req = SendRequest.forTx(t2);
        wallet.completeTx(req);

        // Do some basic sanity checks.
        assertEquals(1, t2.getInputs().size());
        List<ScriptChunk> scriptSigChunks = t2.getInput(0).getScriptSig().getChunks();
        // check 'from address' -- in a unit test this is fine
        assertEquals(2, scriptSigChunks.size());
        assertEquals(myAddress, LegacyAddress.fromPubKeyHash(UNITTEST, Utils.sha256hash160(scriptSigChunks.get(1).data)));
        assertEquals(TransactionConfidence.ConfidenceType.UNKNOWN, t2.getConfidence().getConfidenceType());

        // We have NOT proven that the signature is correct!
        wallet.commitTx(t2);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.SPENT));
        assertEquals(2, wallet.getTransactions(true).size());
    }

    @Test
    public void sideChain() {
        // The wallet receives a coin on the best chain, then on a side chain. Balance is equal to both added together
        // as we assume the side chain tx is pending and will be included shortly.
        Coin v1 = COIN;
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, v1);
        assertEquals(v1, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());

        Coin v2 = valueOf(0, 50);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.SIDE_CHAIN, v2);
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
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, v1);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, v2);
        assertEquals(2, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(expected, wallet.getBalance());

        // Now spend one coin.
        Coin v3 = COIN;
        Transaction spend = wallet.createSend(OTHER_ADDRESS, v3);
        wallet.commitTx(spend);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));

        // Available and estimated balances should not be the same. We don't check the exact available balance here
        // because it depends on the coin selection algorithm.
        assertEquals(valueOf(4, 50), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertFalse(wallet.getBalance(Wallet.BalanceType.AVAILABLE).equals(
                    wallet.getBalance(Wallet.BalanceType.ESTIMATED)));

        // Now confirm the transaction by including it into a block.
        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, spend);

        // Change is confirmed. We started with 5.50 so we should have 4.50 left.
        Coin v4 = valueOf(4, 50);
        assertEquals(v4, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
    }

    @Test
    public void balanceWithIdenticalOutputs() {
        assertEquals(Coin.ZERO, wallet.getBalance(BalanceType.ESTIMATED));
        Transaction tx = new Transaction(UNITTEST);
        tx.addOutput(Coin.COIN, myAddress);
        tx.addOutput(Coin.COIN, myAddress); // identical to the above
        wallet.addWalletTransaction(new WalletTransaction(Pool.UNSPENT, tx));
        assertEquals(Coin.COIN.plus(Coin.COIN), wallet.getBalance(BalanceType.ESTIMATED));
    }

    // Intuitively you'd expect to be able to create a transaction with identical inputs and outputs and get an
    // identical result to Bitcoin Core. However the signatures are not deterministic - signing the same data
    // with the same key twice gives two different outputs. So we cannot prove bit-for-bit compatibility in this test
    // suite.

    @Test
    public void blockChainCatchup() throws Exception {
        // Test that we correctly process transactions arriving from the chain, with callbacks for inbound and outbound.
        final Coin[] bigints = new Coin[4];
        final Transaction[] txn = new Transaction[2];
        final LinkedList<Transaction> confTxns = new LinkedList<>();
        wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> {
            bigints[0] = prevBalance;
            bigints[1] = newBalance;
            txn[0] = tx;
        });

        wallet.addCoinsSentEventListener((wallet, tx, prevBalance, newBalance) -> {
            bigints[2] = prevBalance;
            bigints[3] = newBalance;
            txn[1] = tx;
        });

        wallet.addTransactionConfidenceEventListener((wallet, tx) -> confTxns.add(tx));

        // Receive some money.
        Coin oneCoin = COIN;
        Transaction tx1 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, oneCoin);
        Threading.waitForUserCode();
        assertEquals(null, txn[1]);  // onCoinsSent not called.
        assertEquals(tx1, confTxns.getFirst());   // onTransactionConfidenceChanged called
        assertEquals(txn[0].getTxId(), tx1.getTxId());
        assertEquals(ZERO, bigints[0]);
        assertEquals(oneCoin, bigints[1]);
        assertEquals(TransactionConfidence.ConfidenceType.BUILDING, tx1.getConfidence().getConfidenceType());
        assertEquals(1, tx1.getConfidence().getAppearedAtChainHeight());
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(OTHER_ADDRESS, valueOf(0, 10));
        // Pretend it makes it into the block chain, our wallet state is cleared but we still have the keys, and we
        // want to get back to our previous state. We can do this by just not confirming the transaction as
        // createSend is stateless.
        txn[0] = txn[1] = null;
        confTxns.clear();
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, send1);
        Threading.waitForUserCode();
        assertEquals(Coin.valueOf(0, 90), wallet.getBalance());
        assertEquals(null, txn[0]);
        assertEquals(2, confTxns.size());
        assertEquals(txn[1].getTxId(), send1.getTxId());
        assertEquals(Coin.COIN, bigints[2]);
        assertEquals(Coin.valueOf(0, 90), bigints[3]);
        // And we do it again after the catchup.
        Transaction send2 = wallet.createSend(OTHER_ADDRESS, valueOf(0, 10));
        // What we'd really like to do is prove Bitcoin Core would accept it .... no such luck unfortunately.
        wallet.commitTx(send2);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, send2);
        assertEquals(Coin.valueOf(0, 80), wallet.getBalance());
        Threading.waitForUserCode();
        FakeTxBuilder.BlockPair b4 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS);
        confTxns.clear();
        wallet.notifyNewBestBlock(b4.storedBlock);
        Threading.waitForUserCode();
        assertEquals(3, confTxns.size());
    }

    @Test
    public void balances() throws Exception {
        Coin nanos = COIN;
        Transaction tx1 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, nanos);
        assertEquals(nanos, tx1.getValueSentToMe(wallet));
        assertTrue(tx1.getWalletOutputs(wallet).size() >= 1);
        // Send 0.10 to somebody else.
        Transaction send1 = wallet.createSend(OTHER_ADDRESS, valueOf(0, 10));
        // Reserialize.
        Transaction send2 = UNITTEST.getDefaultSerializer().makeTransaction(send1.bitcoinSerialize());
        assertEquals(nanos, send2.getValueSentFromMe(wallet));
        assertEquals(ZERO.subtract(valueOf(0, 10)), send2.getValue(wallet));
    }

    @Test
    public void isConsistent_duplicates() {
        // This test ensures that isConsistent catches duplicate transactions, eg, because we submitted the same block
        // twice (this is not allowed).
        Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        TransactionOutput output = new TransactionOutput(UNITTEST, tx, valueOf(0, 5), OTHER_ADDRESS);
        tx.addOutput(output);
        wallet.receiveFromBlock(tx, null, BlockChain.NewBlockType.BEST_CHAIN, 0);

        assertTrue(wallet.isConsistent());

        Transaction txClone = UNITTEST.getDefaultSerializer().makeTransaction(tx.bitcoinSerialize());
        try {
            wallet.receiveFromBlock(txClone, null, BlockChain.NewBlockType.BEST_CHAIN, 0);
            fail("Illegal argument not thrown when it should have been.");
        } catch (IllegalStateException ex) {
            // expected
        }
    }

    @Test
    public void isConsistent_pools() {
        // This test ensures that isConsistent catches transactions that are in incompatible pools.
        Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        TransactionOutput output = new TransactionOutput(UNITTEST, tx, valueOf(0, 5), OTHER_ADDRESS);
        tx.addOutput(output);
        wallet.receiveFromBlock(tx, null, BlockChain.NewBlockType.BEST_CHAIN, 0);

        assertTrue(wallet.isConsistent());

        wallet.addWalletTransaction(new WalletTransaction(Pool.PENDING, tx));
        assertFalse(wallet.isConsistent());
    }

    @Test
    public void isConsistent_spent() {
        // This test ensures that isConsistent catches transactions that are marked spent when
        // they aren't.
        Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        TransactionOutput output = new TransactionOutput(UNITTEST, tx, valueOf(0, 5), OTHER_ADDRESS);
        tx.addOutput(output);
        assertTrue(wallet.isConsistent());

        wallet.addWalletTransaction(new WalletTransaction(Pool.SPENT, tx));
        assertFalse(wallet.isConsistent());
    }

    @Test
    public void isTxConsistentReturnsFalseAsExpected() {
        Wallet wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        TransactionOutput to = createMock(TransactionOutput.class);
        EasyMock.expect(to.isAvailableForSpending()).andReturn(true);
        EasyMock.expect(to.isMineOrWatched(wallet)).andReturn(true);
        EasyMock.expect(to.getSpentBy()).andReturn(new TransactionInput(UNITTEST, null, new byte[0]));

        Transaction tx = FakeTxBuilder.createFakeTxWithoutChange(UNITTEST, to);

        replay(to);

        boolean isConsistent = wallet.isTxConsistent(tx, false);
        assertFalse(isConsistent);
    }

    @Test
    public void isTxConsistentReturnsFalseAsExpected_WhenAvailableForSpendingEqualsFalse() {
        Wallet wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        TransactionOutput to = createMock(TransactionOutput.class);
        EasyMock.expect(to.isAvailableForSpending()).andReturn(false);
        EasyMock.expect(to.getSpentBy()).andReturn(null);

        Transaction tx = FakeTxBuilder.createFakeTxWithoutChange(UNITTEST, to);

        replay(to);

        boolean isConsistent = wallet.isTxConsistent(tx, false);
        assertFalse(isConsistent);
    }

    @Test
    public void transactions() {
        // This test covers a bug in which Transaction.getValueSentFromMe was calculating incorrectly.
        Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        // Now add another output (ie, change) that goes to some other address.
        TransactionOutput output = new TransactionOutput(UNITTEST, tx, valueOf(0, 5), OTHER_ADDRESS);
        tx.addOutput(output);
        // Note that tx is no longer valid: it spends more than it imports. However checking transactions balance
        // correctly isn't possible in SPV mode because value is a property of outputs not inputs. Without all
        // transactions you can't check they add up.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx);
        // Now the other guy creates a transaction which spends that change.
        Transaction tx2 = new Transaction(UNITTEST);
        tx2.addInput(output);
        tx2.addOutput(new TransactionOutput(UNITTEST, tx2, valueOf(0, 5), myAddress));
        // tx2 doesn't send any coins from us, even though the output is in the wallet.
        assertEquals(ZERO, tx2.getValueSentFromMe(wallet));
    }

    @Test
    public void bounce() throws Exception {
        // This test covers bug 64 (False double spends). Check that if we create a spend and it's immediately sent
        // back to us, this isn't considered as a double spend.
        Coin coin1 = COIN;
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, coin1);
        // Send half to some other guy. Sending only half then waiting for a confirm is important to ensure the tx is
        // in the unspent pool, not pending or spent.
        Coin coinHalf = valueOf(0, 50);
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());
        Transaction outbound1 = wallet.createSend(OTHER_ADDRESS, coinHalf);
        wallet.commitTx(outbound1);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, outbound1);
        assertTrue(outbound1.getWalletOutputs(wallet).size() <= 1); //the change address at most
        // That other guy gives us the coins right back.
        Transaction inbound2 = new Transaction(UNITTEST);
        inbound2.addOutput(new TransactionOutput(UNITTEST, inbound2, coinHalf, myAddress));
        assertTrue(outbound1.getWalletOutputs(wallet).size() >= 1);
        inbound2.addInput(outbound1.getOutputs().get(0));
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, inbound2);
        assertEquals(coin1, wallet.getBalance());
    }

    @Test
    public void doubleSpendUnspendsOtherInputs() throws Exception {
        // Test another Finney attack, but this time the killed transaction was also spending some other outputs in
        // our wallet which were not themselves double spent. This test ensures the death of the pending transaction
        // frees up the other outputs and makes them spendable again.

        // Receive 1 coin and then 2 coins in separate transactions.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(2, 0));
        // Create a send to a merchant of all our coins.
        Transaction send1 = wallet.createSend(OTHER_ADDRESS, valueOf(2, 90));
        // Create a double spend of just the first one.
        Address BAD_GUY = LegacyAddress.fromKey(UNITTEST, new ECKey());
        Transaction send2 = wallet.createSend(BAD_GUY, COIN);
        send2 = UNITTEST.getDefaultSerializer().makeTransaction(send2.bitcoinSerialize());
        // Broadcast send1, it's now pending.
        wallet.commitTx(send1);
        assertEquals(ZERO, wallet.getBalance()); // change of 10 cents is not yet mined so not included in the balance.
        // Receive a block that overrides the send1 using send2.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, send2);
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
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, value.add(value2));
        Transaction send1 = checkNotNull(wallet.createSend(OTHER_ADDRESS, value2));
        Transaction send2 = checkNotNull(wallet.createSend(OTHER_ADDRESS, value2));
        byte[] buf = send1.bitcoinSerialize();
        buf[43] = 0;  // Break the signature: bitcoinj won't check in SPV mode and this is easier than other mutations.
        send1 = UNITTEST.getDefaultSerializer().makeTransaction(buf);
        wallet.commitTx(send2);
        assertEquals(value, wallet.getBalance(BalanceType.ESTIMATED));
        // Now spend the change. This transaction should die permanently when the mutant appears in the chain.
        Transaction send3 = checkNotNull(wallet.createSend(OTHER_ADDRESS, value, true));
        wallet.commitTx(send3);
        assertEquals(ZERO, wallet.getBalance(BalanceType.AVAILABLE));
        final LinkedList<TransactionConfidence> dead = new LinkedList<>();
        final TransactionConfidence.Listener listener = (confidence, reason) -> {
            final ConfidenceType type = confidence.getConfidenceType();
            if (reason == TransactionConfidence.Listener.ChangeReason.TYPE && type == ConfidenceType.DEAD)
                dead.add(confidence);
        };
        send2.getConfidence().addEventListener(Threading.SAME_THREAD, listener);
        send3.getConfidence().addEventListener(Threading.SAME_THREAD, listener);
        // Double spend!
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, send1);
        // Back to having one coin.
        assertEquals(value, wallet.getBalance(BalanceType.AVAILABLE));
        assertEquals(send2.getTxId(), dead.poll().getTransactionHash());
        assertEquals(send3.getTxId(), dead.poll().getTransactionHash());
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
        wallet.addTransactionConfidenceEventListener((wallet, tx) -> {
            if (tx.getConfidence().getConfidenceType() ==
                    ConfidenceType.DEAD) {
                eventDead[0] = tx;
                eventReplacement[0] = tx.getConfidence().getOverridingTransaction();
            }
        });

        wallet.addChangeEventListener(wallet -> eventWalletChanged[0]++);

        // Receive 1 BTC.
        Coin nanos = COIN;
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, nanos);
        Transaction received = wallet.getTransactions(false).iterator().next();
        // Create a send to a merchant.
        Transaction send1 = wallet.createSend(OTHER_ADDRESS, valueOf(0, 50));
        // Create a double spend.
        Address BAD_GUY = LegacyAddress.fromKey(UNITTEST, new ECKey());
        Transaction send2 = wallet.createSend(BAD_GUY, valueOf(0, 50));
        send2 = UNITTEST.getDefaultSerializer().makeTransaction(send2.bitcoinSerialize());
        // Broadcast send1.
        wallet.commitTx(send1);
        assertEquals(send1, received.getOutput(0).getSpentBy().getParentTransaction());
        // Receive a block that overrides it.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, send2);
        Threading.waitForUserCode();
        assertEquals(send1, eventDead[0]);
        assertEquals(send2, eventReplacement[0]);
        assertEquals(TransactionConfidence.ConfidenceType.DEAD,
                send1.getConfidence().getConfidenceType());
        assertEquals(send2, received.getOutput(0).getSpentBy().getParentTransaction());

        FakeTxBuilder.DoubleSpends doubleSpends = FakeTxBuilder.createFakeDoubleSpendTxns(UNITTEST, myAddress);
        // t1 spends to our wallet. t2 double spends somewhere else.
        wallet.receivePending(doubleSpends.t1, null);
        assertEquals(TransactionConfidence.ConfidenceType.PENDING,
                doubleSpends.t1.getConfidence().getConfidenceType());
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, doubleSpends.t2);
        Threading.waitForUserCode();
        assertEquals(TransactionConfidence.ConfidenceType.DEAD,
                doubleSpends.t1.getConfidence().getConfidenceType());
        assertEquals(doubleSpends.t2, doubleSpends.t1.getConfidence().getOverridingTransaction());
        assertEquals(5, eventWalletChanged[0]);
    }

    @Test
    public void doubleSpendWeCreate() throws Exception {
        // Test we keep pending double spends in IN_CONFLICT until one of them is included in a block
        // and we handle reorgs and dependency chains properly.
        // The following graph shows the txns we use in this test and how they are related
        // (Eg txA1 spends txARoot outputs, txC1 spends txA1 and txB1 outputs, etc).
        // txARoot (10)  -> txA1 (1)  -+
        //                             |--> txC1 (0.10) -> txD1 (0.01)
        // txBRoot (100) -> txB1 (11) -+
        //
        // txARoot (10)  -> txA2 (2)  -+
        //                             |--> txC2 (0.20) -> txD2 (0.02)
        // txBRoot (100) -> txB2 (22) -+
        //
        // txARoot (10)  -> txA3 (3)
        //
        // txA1 is in conflict with txA2 and txA3. txB1 is in conflict with txB2.

        Transaction txARoot = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(10, 0));
        SendRequest a1Req = SendRequest.to(OTHER_ADDRESS, valueOf(1, 0));
        a1Req.tx.addInput(txARoot.getOutput(0));
        a1Req.shuffleOutputs = false;
        wallet.completeTx(a1Req);
        Transaction txA1 = a1Req.tx;
        SendRequest a2Req = SendRequest.to(OTHER_ADDRESS, valueOf(2, 0));
        a2Req.tx.addInput(txARoot.getOutput(0));
        a2Req.shuffleOutputs = false;
        wallet.completeTx(a2Req);
        Transaction txA2 = a2Req.tx;
        SendRequest a3Req = SendRequest.to(OTHER_ADDRESS, valueOf(3, 0));
        a3Req.tx.addInput(txARoot.getOutput(0));
        a3Req.shuffleOutputs = false;
        wallet.completeTx(a3Req);
        Transaction txA3 = a3Req.tx;
        wallet.commitTx(txA1);
        wallet.commitTx(txA2);
        wallet.commitTx(txA3);

        Transaction txBRoot = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(100, 0));
        SendRequest b1Req = SendRequest.to(OTHER_ADDRESS, valueOf(11, 0));
        b1Req.tx.addInput(txBRoot.getOutput(0));
        b1Req.shuffleOutputs = false;
        wallet.completeTx(b1Req);
        Transaction txB1 = b1Req.tx;
        SendRequest b2Req = SendRequest.to(OTHER_ADDRESS, valueOf(22, 0));
        b2Req.tx.addInput(txBRoot.getOutput(0));
        b2Req.shuffleOutputs = false;
        wallet.completeTx(b2Req);
        Transaction txB2 = b2Req.tx;
        wallet.commitTx(txB1);
        wallet.commitTx(txB2);

        SendRequest c1Req = SendRequest.to(OTHER_ADDRESS, valueOf(0, 10));
        c1Req.tx.addInput(txA1.getOutput(1));
        c1Req.tx.addInput(txB1.getOutput(1));
        c1Req.shuffleOutputs = false;
        wallet.completeTx(c1Req);
        Transaction txC1 = c1Req.tx;
        SendRequest c2Req = SendRequest.to(OTHER_ADDRESS, valueOf(0, 20));
        c2Req.tx.addInput(txA2.getOutput(1));
        c2Req.tx.addInput(txB2.getOutput(1));
        c2Req.shuffleOutputs = false;
        wallet.completeTx(c2Req);
        Transaction txC2 = c2Req.tx;
        wallet.commitTx(txC1);
        wallet.commitTx(txC2);

        SendRequest d1Req = SendRequest.to(OTHER_ADDRESS, valueOf(0, 1));
        d1Req.tx.addInput(txC1.getOutput(1));
        d1Req.shuffleOutputs = false;
        wallet.completeTx(d1Req);
        Transaction txD1 = d1Req.tx;
        SendRequest d2Req = SendRequest.to(OTHER_ADDRESS, valueOf(0, 2));
        d2Req.tx.addInput(txC2.getOutput(1));
        d2Req.shuffleOutputs = false;
        wallet.completeTx(d2Req);
        Transaction txD2 = d2Req.tx;
        wallet.commitTx(txD1);
        wallet.commitTx(txD2);

        assertInConflict(txA1);
        assertInConflict(txA2);
        assertInConflict(txA3);
        assertInConflict(txB1);
        assertInConflict(txB2);
        assertInConflict(txC1);
        assertInConflict(txC2);
        assertInConflict(txD1);
        assertInConflict(txD2);

        // Add a block to the block store. The rest of the blocks in this test will be on top of this one.
        FakeTxBuilder.BlockPair blockPair0 = createFakeBlock(blockStore, 1);

        // A block was mined including txA1
        FakeTxBuilder.BlockPair blockPair1 = createFakeBlock(blockStore, 2, txA1);
        wallet.receiveFromBlock(txA1, blockPair1.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        wallet.notifyNewBestBlock(blockPair1.storedBlock);
        assertSpent(txA1);
        assertDead(txA2);
        assertDead(txA3);
        assertInConflict(txB1);
        assertInConflict(txB2);
        assertInConflict(txC1);
        assertDead(txC2);
        assertInConflict(txD1);
        assertDead(txD2);

        // A reorg: previous block "replaced" by new block containing txA1 and txB1
        FakeTxBuilder.BlockPair blockPair2 = createFakeBlock(blockStore, blockPair0.storedBlock, 2, txA1, txB1);
        wallet.receiveFromBlock(txA1, blockPair2.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 0);
        wallet.receiveFromBlock(txB1, blockPair2.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 1);
        wallet.reorganize(blockPair0.storedBlock, Lists.newArrayList(blockPair1.storedBlock),
                Lists.newArrayList(blockPair2.storedBlock));
        assertSpent(txA1);
        assertDead(txA2);
        assertDead(txA3);
        assertSpent(txB1);
        assertDead(txB2);
        assertPending(txC1);
        assertDead(txC2);
        assertPending(txD1);
        assertDead(txD2);

        // A reorg: previous block "replaced" by new block containing txA1, txB1 and txC1
        FakeTxBuilder.BlockPair blockPair3 = createFakeBlock(blockStore, blockPair0.storedBlock, 2, txA1, txB1, txC1);
        wallet.receiveFromBlock(txA1, blockPair3.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 0);
        wallet.receiveFromBlock(txB1, blockPair3.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 1);
        wallet.receiveFromBlock(txC1, blockPair3.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 2);
        wallet.reorganize(blockPair0.storedBlock, Lists.newArrayList(blockPair2.storedBlock),
                Lists.newArrayList(blockPair3.storedBlock));
        assertSpent(txA1);
        assertDead(txA2);
        assertDead(txA3);
        assertSpent(txB1);
        assertDead(txB2);
        assertSpent(txC1);
        assertDead(txC2);
        assertPending(txD1);
        assertDead(txD2);

        // A reorg: previous block "replaced" by new block containing txB1
        FakeTxBuilder.BlockPair blockPair4 = createFakeBlock(blockStore, blockPair0.storedBlock, 2, txB1);
        wallet.receiveFromBlock(txB1, blockPair4.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 0);
        wallet.reorganize(blockPair0.storedBlock, Lists.newArrayList(blockPair3.storedBlock),
                Lists.newArrayList(blockPair4.storedBlock));
        assertPending(txA1);
        assertDead(txA2);
        assertDead(txA3);
        assertSpent(txB1);
        assertDead(txB2);
        assertPending(txC1);
        assertDead(txC2);
        assertPending(txD1);
        assertDead(txD2);

        // A reorg: previous block "replaced" by new block containing txA2
        FakeTxBuilder.BlockPair blockPair5 = createFakeBlock(blockStore, blockPair0.storedBlock, 2, txA2);
        wallet.receiveFromBlock(txA2, blockPair5.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 0);
        wallet.reorganize(blockPair0.storedBlock, Lists.newArrayList(blockPair4.storedBlock),
                Lists.newArrayList(blockPair5.storedBlock));
        assertDead(txA1);
        assertUnspent(txA2);
        assertDead(txA3);
        assertPending(txB1);
        assertDead(txB2);
        assertDead(txC1);
        assertDead(txC2);
        assertDead(txD1);
        assertDead(txD2);

        // A reorg: previous block "replaced" by new empty block
        FakeTxBuilder.BlockPair blockPair6 = createFakeBlock(blockStore, blockPair0.storedBlock, 2);
        wallet.reorganize(blockPair0.storedBlock, Lists.newArrayList(blockPair5.storedBlock),
                Lists.newArrayList(blockPair6.storedBlock));
        assertDead(txA1);
        assertPending(txA2);
        assertDead(txA3);
        assertPending(txB1);
        assertDead(txB2);
        assertDead(txC1);
        assertDead(txC2);
        assertDead(txD1);
        assertDead(txD2);
    }

    @Test
    public void doubleSpendWeReceive() {
        FakeTxBuilder.DoubleSpends doubleSpends = FakeTxBuilder.createFakeDoubleSpendTxns(UNITTEST, myAddress);
        // doubleSpends.t1 spends to our wallet. doubleSpends.t2 double spends somewhere else.

        Transaction t1b = new Transaction(UNITTEST);
        TransactionOutput t1bo = new TransactionOutput(UNITTEST, t1b, valueOf(0, 50), OTHER_ADDRESS);
        t1b.addOutput(t1bo);
        t1b.addInput(doubleSpends.t1.getOutput(0));

        wallet.receivePending(doubleSpends.t1, null);
        wallet.receivePending(doubleSpends.t2, null);
        wallet.receivePending(t1b, null);
        assertInConflict(doubleSpends.t1);
        assertInConflict(doubleSpends.t1);
        assertInConflict(t1b);

        // Add a block to the block store. The rest of the blocks in this test will be on top of this one.
        FakeTxBuilder.BlockPair blockPair0 = createFakeBlock(blockStore, 1);

        // A block was mined including doubleSpends.t1
        FakeTxBuilder.BlockPair blockPair1 = createFakeBlock(blockStore, 2, doubleSpends.t1);
        wallet.receiveFromBlock(doubleSpends.t1, blockPair1.storedBlock, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        wallet.notifyNewBestBlock(blockPair1.storedBlock);
        assertSpent(doubleSpends.t1);
        assertDead(doubleSpends.t2);
        assertPending(t1b);

        // A reorg: previous block "replaced" by new block containing doubleSpends.t2
        FakeTxBuilder.BlockPair blockPair2 = createFakeBlock(blockStore, blockPair0.storedBlock, 2, doubleSpends.t2);
        wallet.receiveFromBlock(doubleSpends.t2, blockPair2.storedBlock, AbstractBlockChain.NewBlockType.SIDE_CHAIN, 0);
        wallet.reorganize(blockPair0.storedBlock, Lists.newArrayList(blockPair1.storedBlock),
                Lists.newArrayList(blockPair2.storedBlock));
        assertDead(doubleSpends.t1);
        assertSpent(doubleSpends.t2);
        assertDead(t1b);
    }

    @Test
    public void doubleSpendForBuildingTx() throws Exception {
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(2, 0));
        Transaction send1 = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(1, 0), true));
        Transaction send2 = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(1, 20), true));

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, send1);
        assertUnspent(send1);

        wallet.receivePending(send2, null);
        assertUnspent(send1);
        assertDead(send2);
    }

    @Test
    public void txSpendingDeadTx() throws Exception {
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(2, 0));
        Transaction send1 = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(1, 0), true));
        Transaction send2 = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(1, 20), true));
        wallet.commitTx(send1);
        assertPending(send1);
        Transaction send1b = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(0, 50), true));

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, send2);
        assertDead(send1);
        assertUnspent(send2);

        wallet.receivePending(send1b, null);
        assertDead(send1);
        assertUnspent(send2);
        assertDead(send1b);
    }

    private void assertInConflict(Transaction tx) {
        assertEquals(ConfidenceType.IN_CONFLICT, tx.getConfidence().getConfidenceType());
        assertTrue(wallet.poolContainsTxHash(WalletTransaction.Pool.PENDING, tx.getTxId()));
    }

    private void assertPending(Transaction tx) {
        assertEquals(ConfidenceType.PENDING, tx.getConfidence().getConfidenceType());
        assertTrue(wallet.poolContainsTxHash(WalletTransaction.Pool.PENDING, tx.getTxId()));
    }

    private void assertSpent(Transaction tx) {
        assertEquals(ConfidenceType.BUILDING, tx.getConfidence().getConfidenceType());
        assertTrue(wallet.poolContainsTxHash(WalletTransaction.Pool.SPENT, tx.getTxId()));
    }

    private void assertUnspent(Transaction tx) {
        assertEquals(ConfidenceType.BUILDING, tx.getConfidence().getConfidenceType());
        assertTrue(wallet.poolContainsTxHash(WalletTransaction.Pool.UNSPENT, tx.getTxId()));
    }

    private void assertDead(Transaction tx) {
        assertEquals(ConfidenceType.DEAD, tx.getConfidence().getConfidenceType());
        assertTrue(wallet.poolContainsTxHash(WalletTransaction.Pool.DEAD, tx.getTxId()));
    }

    @Test
    public void testAddTransactionsDependingOn() throws Exception {
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(2, 0));
        Transaction send1 = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(1, 0), true));
        Transaction send2 = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(1, 20), true));
        wallet.commitTx(send1);
        Transaction send1b = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(0, 50), true));
        wallet.commitTx(send1b);
        Transaction send1c = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(0, 25), true));
        wallet.commitTx(send1c);
        wallet.commitTx(send2);
        Set<Transaction> txns = new HashSet<>();
        txns.add(send1);
        wallet.addTransactionsDependingOn(txns, wallet.getTransactions(true));
        assertEquals(3, txns.size());
        assertTrue(txns.contains(send1));
        assertTrue(txns.contains(send1b));
        assertTrue(txns.contains(send1c));
    }

    @Test
    public void sortTxnsByDependency() throws Exception {
        Transaction send1 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(2, 0));
        Transaction send1a = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(1, 0), true));
        wallet.commitTx(send1a);
        Transaction send1b = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(0, 50), true));
        wallet.commitTx(send1b);
        Transaction send1c = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(0, 25), true));
        wallet.commitTx(send1c);
        Transaction send1d = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(0, 12), true));
        wallet.commitTx(send1d);
        Transaction send1e = checkNotNull(wallet.createSend(OTHER_ADDRESS, valueOf(0, 06), true));
        wallet.commitTx(send1e);

        Transaction send2 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(200, 0));

        SendRequest req2a = SendRequest.to(OTHER_ADDRESS, valueOf(100, 0));
        req2a.tx.addInput(send2.getOutput(0));
        req2a.shuffleOutputs = false;
        wallet.completeTx(req2a);
        Transaction send2a = req2a.tx;

        SendRequest req2b = SendRequest.to(OTHER_ADDRESS, valueOf(50, 0));
        req2b.tx.addInput(send2a.getOutput(1));
        req2b.shuffleOutputs = false;
        wallet.completeTx(req2b);
        Transaction send2b = req2b.tx;

        SendRequest req2c = SendRequest.to(OTHER_ADDRESS, valueOf(25, 0));
        req2c.tx.addInput(send2b.getOutput(1));
        req2c.shuffleOutputs = false;
        wallet.completeTx(req2c);
        Transaction send2c = req2c.tx;

        Set<Transaction> unsortedTxns = new HashSet<>();
        unsortedTxns.add(send1a);
        unsortedTxns.add(send1b);
        unsortedTxns.add(send1c);
        unsortedTxns.add(send1d);
        unsortedTxns.add(send1e);
        unsortedTxns.add(send2a);
        unsortedTxns.add(send2b);
        unsortedTxns.add(send2c);
        List<Transaction> sortedTxns = wallet.sortTxnsByDependency(unsortedTxns);

        assertEquals(8, sortedTxns.size());
        assertTrue(sortedTxns.indexOf(send1a) < sortedTxns.indexOf(send1b));
        assertTrue(sortedTxns.indexOf(send1b) < sortedTxns.indexOf(send1c));
        assertTrue(sortedTxns.indexOf(send1c) < sortedTxns.indexOf(send1d));
        assertTrue(sortedTxns.indexOf(send1d) < sortedTxns.indexOf(send1e));
        assertTrue(sortedTxns.indexOf(send2a) < sortedTxns.indexOf(send2b));
        assertTrue(sortedTxns.indexOf(send2b) < sortedTxns.indexOf(send2c));
    }

    @Test
    public void pending1() {
        // Check that if we receive a pending transaction that is then confirmed, we are notified as appropriate.
        final Coin nanos = COIN;
        final Transaction t1 = createFakeTx(UNITTEST, nanos, myAddress);

        // First one is "called" second is "pending".
        final boolean[] flags = new boolean[2];
        final Transaction[] notifiedTx = new Transaction[1];
        final int[] walletChanged = new int[1];
        wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> {
            // Check we got the expected transaction.
            assertEquals(tx, t1);
            // Check that it's considered to be pending inclusion in the block chain.
            assertEquals(prevBalance, ZERO);
            assertEquals(newBalance, nanos);
            flags[0] = true;
            flags[1] = tx.isPending();
            notifiedTx[0] = tx;
        });

        wallet.addChangeEventListener(wallet -> walletChanged[0]++);

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
        notifiedTx[0].getConfidence().addEventListener((confidence, reason) -> {
            flags[1] = true;
            reasons[0] = reason;
        });
        assertEquals(TransactionConfidence.ConfidenceType.PENDING,
                notifiedTx[0].getConfidence().getConfidenceType());
        // Send a block with nothing interesting. Verify we don't get a callback.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Threading.waitForUserCode();
        assertNull(reasons[0]);
        final Transaction t1Copy = UNITTEST.getDefaultSerializer().makeTransaction(t1.bitcoinSerialize());
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, t1Copy);
        Threading.waitForUserCode();
        assertFalse(flags[0]);
        assertTrue(flags[1]);
        assertEquals(TransactionConfidence.ConfidenceType.BUILDING, notifiedTx[0].getConfidence().getConfidenceType());
        // Check we don't get notified about an irrelevant transaction.
        flags[0] = false;
        flags[1] = false;
        Transaction irrelevant = createFakeTx(UNITTEST, nanos, OTHER_ADDRESS);
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
        wallet.addCoinsSentEventListener((wallet, tx, prevBalance, newBalance) -> {
            txn[0] = tx;
            bigints[0] = prevBalance;
            bigints[1] = newBalance;
        });
        // Receive some coins.
        Coin nanos = COIN;
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, nanos);
        // Create a spend with them, but don't commit it (ie it's from somewhere else but using our keys). This TX
        // will have change as we don't spend our entire balance.
        Coin halfNanos = valueOf(0, 50);
        Transaction t2 = wallet.createSend(OTHER_ADDRESS, halfNanos);
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
    public void pending3() {
        // Check that if we receive a pending tx, and it's overridden by a double spend from the best chain, we
        // are notified that it's dead. This should work even if the pending tx inputs are NOT ours, ie, they don't
        // connect to anything.
        Coin nanos = COIN;

        // Create two transactions that share the same input tx.
        Address badGuy = LegacyAddress.fromKey(UNITTEST, new ECKey());
        Transaction doubleSpentTx = new Transaction(UNITTEST);
        TransactionOutput doubleSpentOut = new TransactionOutput(UNITTEST, doubleSpentTx, nanos, badGuy);
        doubleSpentTx.addOutput(doubleSpentOut);
        Transaction t1 = new Transaction(UNITTEST);
        TransactionOutput o1 = new TransactionOutput(UNITTEST, t1, nanos, myAddress);
        t1.addOutput(o1);
        t1.addInput(doubleSpentOut);
        Transaction t2 = new Transaction(UNITTEST);
        TransactionOutput o2 = new TransactionOutput(UNITTEST, t2, nanos, badGuy);
        t2.addOutput(o2);
        t2.addInput(doubleSpentOut);

        final Transaction[] called = new Transaction[2];
        wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> called[0] = tx);

        wallet.addTransactionConfidenceEventListener((wallet, tx) -> {
            if (tx.getConfidence().getConfidenceType() ==
                    ConfidenceType.DEAD) {
                called[0] = tx;
                called[1] = tx.getConfidence().getOverridingTransaction();
            }
        });

        assertEquals(ZERO, wallet.getBalance());
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        Threading.waitForUserCode();
        assertEquals(t1, called[0]);
        assertEquals(nanos, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        // Now receive a double spend on the best chain.
        called[0] = called[1] = null;
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, t2);
        Threading.waitForUserCode();
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(t1, called[0]); // dead
        assertEquals(t2, called[1]); // replacement
    }

    @Test
    public void transactionsList() throws Exception {
        // Check the wallet can give us an ordered list of all received transactions.
        Utils.setMockClock();
        Transaction tx1 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        Utils.rollMockClock(60 * 10);
        Transaction tx2 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(0, 5));
        // Check we got them back in order.
        List<Transaction> transactions = wallet.getTransactionsByTime();
        assertEquals(tx2, transactions.get(0));
        assertEquals(tx1, transactions.get(1));
        assertEquals(2, transactions.size());
        // Check we get only the last transaction if we request a subrange.
        transactions = wallet.getRecentTransactions(1, false);
        assertEquals(1, transactions.size());
        assertEquals(tx2,  transactions.get(0));

        // Create a spend five minutes later.
        Utils.rollMockClock(60 * 5);
        Transaction tx3 = wallet.createSend(OTHER_ADDRESS, valueOf(0, 5));
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
    public void keyCreationTime() {
        Utils.setMockClock();
        long now = Utils.currentTimeSeconds();
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        assertEquals(now, wallet.getEarliestKeyCreationTime());
        Utils.rollMockClock(60);
        wallet.freshReceiveKey();
        assertEquals(now, wallet.getEarliestKeyCreationTime());
    }

    @Test
    public void scriptCreationTime() {
        Utils.setMockClock();
        long now = Utils.currentTimeSeconds();
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        assertEquals(now, wallet.getEarliestKeyCreationTime());
        Utils.rollMockClock(-120);
        wallet.addWatchedAddress(OTHER_ADDRESS);
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
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, coin1);
        // Send half to ourselves. We should then have a balance available to spend of zero.
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getTransactions(true).size());
        Transaction outbound1 = wallet.createSend(myAddress, coinHalf);
        wallet.commitTx(outbound1);
        // We should have a zero available balance before the next block.
        assertEquals(ZERO, wallet.getBalance());
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, outbound1);
        // We should have a balance of 1 BTC after the block is received.
        assertEquals(coin1, wallet.getBalance());
    }

    @Test
    public void lastBlockSeen() throws Exception {
        Coin v1 = valueOf(5, 0);
        Coin v2 = valueOf(0, 50);
        Coin v3 = valueOf(0, 25);
        Transaction t1 = createFakeTx(UNITTEST, v1, myAddress);
        Transaction t2 = createFakeTx(UNITTEST, v2, myAddress);
        Transaction t3 = createFakeTx(UNITTEST, v3, myAddress);

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
        Transaction t1 = createFakeTx(UNITTEST, value, key1);
        if (wallet.isPendingTransactionRelevant(t1))
            wallet.receivePending(t1, null);
        // TX should have been seen as relevant.
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertEquals(ZERO, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, t1);
        // TX should have been seen as relevant, extracted and processed.
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        // Spend it and ensure we can spend the <key> OP_CHECKSIG output correctly.
        Transaction t2 = wallet.createSend(OTHER_ADDRESS, value);
        assertNotNull(t2);
        // TODO: This code is messy, improve the Script class and fixinate!
        assertEquals(t2.toString(), 1, t2.getInputs().get(0).getScriptSig().getChunks().size());
        assertTrue(t2.getInputs().get(0).getScriptSig().getChunks().get(0).data.length > 50);
    }

    @Test
    public void isWatching() {
        assertFalse(wallet.isWatching());
        Wallet watchingWallet = Wallet.fromWatchingKey(UNITTEST,
                wallet.getWatchingKey().dropPrivateBytes().dropParent(), ScriptType.P2PKH);
        assertTrue(watchingWallet.isWatching());
        wallet.encrypt(PASSWORD1);
        assertFalse(wallet.isWatching());
    }

    @Test
    public void watchingWallet() throws Exception {
        DeterministicKey watchKey = wallet.getWatchingKey();
        String serialized = watchKey.serializePubB58(UNITTEST);

        // Construct watching wallet.
        Wallet watchingWallet = Wallet.fromWatchingKey(UNITTEST,
                DeterministicKey.deserializeB58(null, serialized, UNITTEST), ScriptType.P2PKH);
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

        receiveATransaction(watchingWallet, LegacyAddress.fromKey(UNITTEST, myKey));
        assertEquals(COIN, watchingWallet.getBalance());
        assertEquals(COIN, watchingWallet.getBalance(Wallet.BalanceType.AVAILABLE));
        assertEquals(ZERO, watchingWallet.getBalance(Wallet.BalanceType.AVAILABLE_SPENDABLE));
    }

    @Test(expected = ECKey.MissingPrivateKeyException.class)
    public void watchingWalletWithCreationTime() {
        DeterministicKey watchKey = wallet.getWatchingKey();
        String serialized = watchKey.serializePubB58(UNITTEST);
        Wallet watchingWallet = Wallet.fromWatchingKeyB58(UNITTEST, serialized, 1415282801);
        DeterministicKey key2 = watchingWallet.freshReceiveKey();
        assertEquals(myKey, key2);

        ECKey key = wallet.freshKey(KeyChain.KeyPurpose.CHANGE);
        key2 = watchingWallet.freshKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key, key2);
        key.sign(Sha256Hash.ZERO_HASH);
        key2.sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void watchingScripts() {
        // Verify that pending transactions to watched addresses are relevant
        Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
        wallet.addWatchedAddress(watchedAddress);
        Coin value = valueOf(5, 0);
        Transaction t1 = createFakeTx(UNITTEST, value, watchedAddress);
        assertTrue(t1.getWalletOutputs(wallet).size() >= 1);
        assertTrue(wallet.isPendingTransactionRelevant(t1));
    }

    @Test(expected = InsufficientMoneyException.class)
    public void watchingScriptsConfirmed() throws Exception {
        Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
        wallet.addWatchedAddress(watchedAddress);
        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, CENT, watchedAddress);
        assertEquals(CENT, wallet.getBalance());

        // We can't spend watched balances
        wallet.createSend(OTHER_ADDRESS, CENT);
    }

    @Test
    public void watchingScriptsSentFrom() {
        int baseElements = wallet.getBloomFilterElementCount();

        Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
        wallet.addWatchedAddress(watchedAddress);
        assertEquals(baseElements + 1, wallet.getBloomFilterElementCount());

        Transaction t1 = createFakeTx(UNITTEST, CENT, watchedAddress);
        Transaction t2 = createFakeTx(UNITTEST, COIN, OTHER_ADDRESS);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, t1);
        assertEquals(baseElements + 2, wallet.getBloomFilterElementCount());
        Transaction st2 = new Transaction(UNITTEST);
        st2.addOutput(CENT, OTHER_ADDRESS);
        st2.addOutput(COIN, OTHER_ADDRESS);
        st2.addInput(t1.getOutput(0));
        st2.addInput(t2.getOutput(0));
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, st2);
        assertEquals(baseElements + 2, wallet.getBloomFilterElementCount());
        assertEquals(CENT, st2.getValueSentFromMe(wallet));
    }

    @Test
    public void watchingScriptsBloomFilter() {
        Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
        Transaction t1 = createFakeTx(UNITTEST, CENT, watchedAddress);
        TransactionOutPoint outPoint = new TransactionOutPoint(UNITTEST, 0, t1);
        wallet.addWatchedAddress(watchedAddress);

        // Note that this has a 1e-12 chance of failing this unit test due to a false positive
        assertFalse(wallet.getBloomFilter(1e-12).contains(outPoint.unsafeBitcoinSerialize()));

        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, t1);
        assertTrue(wallet.getBloomFilter(1e-12).contains(outPoint.unsafeBitcoinSerialize()));
    }

    @Test
    public void getWatchedAddresses() {
        Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
        wallet.addWatchedAddress(watchedAddress);
        List<Address> watchedAddresses = wallet.getWatchedAddresses();
        assertEquals(1, watchedAddresses.size());
        assertEquals(watchedAddress, watchedAddresses.get(0));
    }

    @Test
    public void removeWatchedAddresses() {
        List<Address> addressesForRemoval = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
            addressesForRemoval.add(watchedAddress);
            wallet.addWatchedAddress(watchedAddress);
        }

        wallet.removeWatchedAddresses(addressesForRemoval);
        for (Address addr : addressesForRemoval)
            assertFalse(wallet.isAddressWatched(addr));
    }

    @Test
    public void removeWatchedAddress() {
        Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
        wallet.addWatchedAddress(watchedAddress);
        wallet.removeWatchedAddress(watchedAddress);
        assertFalse(wallet.isAddressWatched(watchedAddress));
    }

    @Test
    public void removeScriptsBloomFilter() {
        List<Address> addressesForRemoval = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Address watchedAddress = LegacyAddress.fromKey(UNITTEST, new ECKey());
            addressesForRemoval.add(watchedAddress);
            wallet.addWatchedAddress(watchedAddress);
        }

        wallet.removeWatchedAddresses(addressesForRemoval);

        for (Address addr : addressesForRemoval) {
            Transaction t1 = createFakeTx(UNITTEST, CENT, addr);
            TransactionOutPoint outPoint = new TransactionOutPoint(UNITTEST, 0, t1);

            // Note that this has a 1e-12 chance of failing this unit test due to a false positive
            assertFalse(wallet.getBloomFilter(1e-12).contains(outPoint.unsafeBitcoinSerialize()));

            sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, t1);
            assertFalse(wallet.getBloomFilter(1e-12).contains(outPoint.unsafeBitcoinSerialize()));
        }
    }

    @Test
    public void marriedKeychainBloomFilter() throws Exception {
        createMarriedWallet(2, 2);
        Address address = wallet.currentReceiveAddress();

        assertTrue(wallet.getBloomFilter(0.001).contains(address.getHash()));

        Transaction t1 = createFakeTx(UNITTEST, CENT, address);
        TransactionOutPoint outPoint = new TransactionOutPoint(UNITTEST, 0, t1);

        assertFalse(wallet.getBloomFilter(0.001).contains(outPoint.unsafeBitcoinSerialize()));

        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, t1);
        assertTrue(wallet.getBloomFilter(0.001).contains(outPoint.unsafeBitcoinSerialize()));
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

        Transaction t1 = createFakeTx(UNITTEST, valueOf(5, 0), key);
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

        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN);
        Sha256Hash hash3 = Sha256Hash.of(f);
        assertEquals(hash2, hash3);  // File has NOT changed yet. Just new blocks with no txns - delayed.
        assertNull(results[0]);
        assertNull(results[1]);

        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, valueOf(5, 0), key);
        Sha256Hash hash4 = Sha256Hash.of(f);
        assertFalse(hash3.equals(hash4));  // File HAS changed.
        results[0] = results[1] = null;

        // A block that contains some random tx we don't care about.
        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, Coin.COIN, OTHER_ADDRESS);
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
        sendMoneyToWallet(BlockChain.NewBlockType.BEST_CHAIN, valueOf(5, 0), key2);
        Thread.sleep(2000); // Wait longer than autosave delay. TODO Fix the racyness.
        assertEquals(hash5, Sha256Hash.of(f)); // File has still NOT changed.
        assertNull(results[0]);
        assertNull(results[1]);
    }

    @Test
    public void spendOutputFromPendingTransaction() throws Exception {
        // We'll set up a wallet that receives a coin, then sends a coin of lesser value and keeps the change.
        Coin v1 = COIN;
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, v1);
        // First create our current transaction
        ECKey k2 = wallet.freshReceiveKey();
        Coin v2 = valueOf(0, 50);
        Transaction t2 = new Transaction(UNITTEST);
        TransactionOutput o2 = new TransactionOutput(UNITTEST, t2, v2, LegacyAddress.fromKey(UNITTEST, k2));
        t2.addOutput(o2);
        SendRequest req = SendRequest.forTx(t2);
        wallet.completeTx(req);

        // Commit t2, so it is placed in the pending pool
        wallet.commitTx(t2);
        assertEquals(0, wallet.getPoolSize(WalletTransaction.Pool.UNSPENT));
        assertEquals(1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        assertEquals(2, wallet.getTransactions(true).size());

        // Now try to the spend the output.
        ECKey k3 = new ECKey();
        Coin v3 = valueOf(0, 25);
        Transaction t3 = new Transaction(UNITTEST);
        t3.addOutput(v3, LegacyAddress.fromKey(UNITTEST, k3));
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
    public void replayWhilstPending() {
        // Check that if a pending transaction spends outputs of chain-included transactions, we mark them as spent.
        // See bug 345. This can happen if there is a pending transaction floating around and then you replay the
        // chain without emptying the memory pool (or refilling it from a peer).
        Coin value = COIN;
        Transaction tx1 = createFakeTx(UNITTEST, value, myAddress);
        Transaction tx2 = new Transaction(UNITTEST);
        tx2.addInput(tx1.getOutput(0));
        tx2.addOutput(valueOf(0, 9), OTHER_ADDRESS);
        // Add a change address to ensure this tx is relevant.
        tx2.addOutput(CENT, wallet.currentChangeAddress());
        wallet.receivePending(tx2, null);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx1);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(1, wallet.getPoolSize(Pool.SPENT));
        assertEquals(1, wallet.getPoolSize(Pool.PENDING));
        assertEquals(0, wallet.getPoolSize(Pool.UNSPENT));
    }

    @Test
    public void outOfOrderPendingTxns() {
        // Check that if there are two pending transactions which we receive out of order, they are marked as spent
        // correctly. For instance, we are watching a wallet, someone pays us (A) and we then pay someone else (B)
        // with a change address but the network delivers the transactions to us in order B then A.
        Coin value = COIN;
        Transaction a = createFakeTx(UNITTEST, value, myAddress);
        Transaction b = new Transaction(UNITTEST);
        b.addInput(a.getOutput(0));
        b.addOutput(CENT, OTHER_ADDRESS);
        Coin v = COIN.subtract(CENT);
        b.addOutput(v, wallet.currentChangeAddress());
        a = roundTripTransaction(UNITTEST, a);
        b = roundTripTransaction(UNITTEST, b);
        wallet.receivePending(b, null);
        assertEquals(v, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        wallet.receivePending(a, null);
        assertEquals(v, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void encryptionDecryptionAESBasic() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);

        assertEquals(EncryptionType.ENCRYPTED_SCRYPT_AES, encryptedWallet.getEncryptionType());
        assertTrue(encryptedWallet.checkPassword(PASSWORD1));
        assertTrue(encryptedWallet.checkAESKey(aesKey));
        assertFalse(encryptedWallet.checkPassword(WRONG_PASSWORD));
        assertNotNull("The keyCrypter is missing but should not be", keyCrypter);
        encryptedWallet.decrypt(aesKey);

        // Wallet should now be unencrypted.
        assertNull("Wallet is not an unencrypted wallet", encryptedWallet.getKeyCrypter());
        try {
            encryptedWallet.checkPassword(PASSWORD1);
            fail();
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void encryptionDecryptionPasswordBasic() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);

        assertTrue(encryptedWallet.isEncrypted());
        encryptedWallet.decrypt(PASSWORD1);
        assertFalse(encryptedWallet.isEncrypted());

        // Wallet should now be unencrypted.
        assertNull("Wallet is not an unencrypted wallet", encryptedWallet.getKeyCrypter());
        try {
            encryptedWallet.checkPassword(PASSWORD1);
            fail();
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void encryptionDecryptionBadPassword() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter wrongAesKey = keyCrypter.deriveKey(WRONG_PASSWORD);

        // Check the wallet is currently encrypted
        assertEquals("Wallet is not an encrypted wallet", EncryptionType.ENCRYPTED_SCRYPT_AES, encryptedWallet.getEncryptionType());
        assertFalse(encryptedWallet.checkAESKey(wrongAesKey));

        // Check that the wrong password does not decrypt the wallet.
        try {
            encryptedWallet.decrypt(wrongAesKey);
            fail("Incorrectly decoded wallet with wrong password");
        } catch (Wallet.BadWalletEncryptionKeyException e) {
            // Expected.
        }
    }

    @Test
    public void changePasswordTest() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);
        CharSequence newPassword = "My name is Tom";
        encryptedWallet.changeEncryptionPassword(PASSWORD1, newPassword);
        assertTrue(encryptedWallet.checkPassword(newPassword));
        assertFalse(encryptedWallet.checkPassword(WRONG_PASSWORD));
    }

    @Test
    public void changeAesKeyTest() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
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
    public void encryptionDecryptionCheckExceptions() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);

        // Check the wallet is currently encrypted
        assertEquals("Wallet is not an encrypted wallet", EncryptionType.ENCRYPTED_SCRYPT_AES, encryptedWallet.getEncryptionType());

        // Decrypt wallet.
        assertNotNull("The keyCrypter is missing but should not be", keyCrypter);
        encryptedWallet.decrypt(aesKey);

        // Try decrypting it again
        try {
            assertNotNull("The keyCrypter is missing but should not be", keyCrypter);
            encryptedWallet.decrypt(aesKey);
            fail("Should not be able to decrypt a decrypted wallet");
        } catch (IllegalStateException e) {
            // expected
        }
        assertNull("Wallet is not an unencrypted wallet", encryptedWallet.getKeyCrypter());

        // Encrypt wallet.
        encryptedWallet.encrypt(keyCrypter, aesKey);

        assertEquals("Wallet is not an encrypted wallet", EncryptionType.ENCRYPTED_SCRYPT_AES, encryptedWallet.getEncryptionType());

        // Try encrypting it again
        try {
            encryptedWallet.encrypt(keyCrypter, aesKey);
            fail("Should not be able to encrypt an encrypted wallet");
        } catch (IllegalStateException e) {
            // expected
        }
        assertEquals("Wallet is not an encrypted wallet", EncryptionType.ENCRYPTED_SCRYPT_AES, encryptedWallet.getEncryptionType());
    }

    @Test(expected = KeyCrypterException.class)
    public void addUnencryptedKeyToEncryptedWallet() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);

        ECKey key1 = new ECKey();
        encryptedWallet.importKey(key1);
    }

    @Test(expected = KeyCrypterException.class)
    public void addEncryptedKeyToUnencryptedWallet() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();

        ECKey key1 = new ECKey();
        key1 = key1.encrypt(keyCrypter, keyCrypter.deriveKey("PASSWORD!"));
        wallet.importKey(key1);
    }

    @Test(expected = KeyCrypterException.class)
    public void mismatchedCrypter() {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);
        KeyCrypter keyCrypter = encryptedWallet.getKeyCrypter();
        KeyParameter aesKey = keyCrypter.deriveKey(PASSWORD1);

        // Try added an ECKey that was encrypted with a differenct ScryptParameters (i.e. a non-homogenous key).
        // This is not allowed as the ScryptParameters is stored at the Wallet level.
        KeyCrypter keyCrypterDifferent = new KeyCrypterScrypt();
        ECKey ecKeyDifferent = new ECKey();
        ecKeyDifferent = ecKeyDifferent.encrypt(keyCrypterDifferent, aesKey);
        encryptedWallet.importKey(ecKeyDifferent);
    }

    @Test
    public void importAndEncrypt() throws InsufficientMoneyException {
        Wallet encryptedWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        encryptedWallet.encrypt(PASSWORD1);

        final ECKey key = new ECKey();
        encryptedWallet.importKeysAndEncrypt(Collections.singletonList(key), PASSWORD1);
        assertEquals(1, encryptedWallet.getImportedKeys().size());
        assertEquals(key.getPubKeyPoint(), encryptedWallet.getImportedKeys().get(0).getPubKeyPoint());
        sendMoneyToWallet(encryptedWallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, Coin.COIN, LegacyAddress.fromKey(UNITTEST, key));
        assertEquals(Coin.COIN, encryptedWallet.getBalance());
        SendRequest req = SendRequest.emptyWallet(OTHER_ADDRESS);
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
            txns[i] = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        }
        // Check that we spend transactions in order of reception.
        for (int i = 0; i < ITERATIONS; i++) {
            Transaction spend = wallet.createSend(OTHER_ADDRESS, COIN);
            assertEquals(spend.getInputs().size(), 1);
            assertEquals("Failed on iteration " + i, spend.getInput(0).getOutpoint().getHash(), txns[i].getTxId());
            wallet.commitTx(spend);
        }
    }

    @Test(expected = Wallet.ExceededMaxTransactionSize.class)
    public void respectMaxStandardSize() throws Exception {
        // Check that we won't create txns > 100kb. Average tx size is ~220 bytes so this would have to be enormous.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, valueOf(100, 0));
        Transaction tx = new Transaction(UNITTEST);
        byte[] bits = new byte[20];
        new Random().nextBytes(bits);
        Coin v = CENT;
        // 3100 outputs to a random address.
        for (int i = 0; i < 3100; i++) {
            tx.addOutput(v, LegacyAddress.fromPubKeyHash(UNITTEST, bits));
        }
        SendRequest req = SendRequest.forTx(tx);
        wallet.completeTx(req);
    }

    @Test
    public void opReturnOneOutputTest() throws Exception {
        // Tests basic send of transaction with one output that doesn't transfer any value but just writes OP_RETURN.
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(UNITTEST);
        Coin messagePrice = Coin.ZERO;
        Script script = ScriptBuilder.createOpReturnScript("hello world!".getBytes());
        tx.addOutput(messagePrice, script);
        SendRequest request = SendRequest.forTx(tx);
        request.ensureMinRequiredFee = true;
        wallet.completeTx(request);
    }

    @Test
    public void opReturnMaxBytes() throws Exception {
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(UNITTEST);
        Script script = ScriptBuilder.createOpReturnScript(new byte[80]);
        tx.addOutput(Coin.ZERO, script);
        SendRequest request = SendRequest.forTx(tx);
        request.ensureMinRequiredFee = true;
        wallet.completeTx(request);
    }

    @Test
    public void opReturnOneOutputWithValueTest() throws Exception {
        // Tests basic send of transaction with one output that destroys coins and has an OP_RETURN.
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(UNITTEST);
        Coin messagePrice = CENT;
        Script script = ScriptBuilder.createOpReturnScript("hello world!".getBytes());
        tx.addOutput(messagePrice, script);
        SendRequest request = SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test
    public void opReturnTwoOutputsTest() throws Exception {
        // Tests sending transaction where one output transfers BTC, the other one writes OP_RETURN.
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(UNITTEST);
        Coin messagePrice = Coin.ZERO;
        Script script = ScriptBuilder.createOpReturnScript("hello world!".getBytes());
        tx.addOutput(CENT, OTHER_ADDRESS);
        tx.addOutput(messagePrice, script);
        SendRequest request = SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.MultipleOpReturnRequested.class)
    public void twoOpReturnsPerTransactionTest() throws Exception {
        // Tests sending transaction where there are 2 attempts to write OP_RETURN scripts - this should fail and throw MultipleOpReturnRequested.
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(UNITTEST);
        Coin messagePrice = Coin.ZERO;
        Script script1 = ScriptBuilder.createOpReturnScript("hello world 1!".getBytes());
        Script script2 = ScriptBuilder.createOpReturnScript("hello world 2!".getBytes());
        tx.addOutput(messagePrice, script1);
        tx.addOutput(messagePrice, script2);
        SendRequest request = SendRequest.forTx(tx);
        request.ensureMinRequiredFee = true;
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.DustySendRequested.class)
    public void sendDustTest() throws InsufficientMoneyException {
        // Tests sending dust, should throw DustySendRequested.
        Transaction tx = new Transaction(UNITTEST);
        Coin dustThreshold = new TransactionOutput(UNITTEST, null, Coin.COIN, OTHER_ADDRESS).getMinNonDustValue();
        tx.addOutput(dustThreshold.subtract(SATOSHI), OTHER_ADDRESS);
        SendRequest request = SendRequest.forTx(tx);
        request.ensureMinRequiredFee = true;
        wallet.completeTx(request);
    }

    @Test
    public void sendMultipleCentsTest() throws Exception {
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        Transaction tx = new Transaction(UNITTEST);
        Coin c = CENT.subtract(SATOSHI);
        tx.addOutput(c, OTHER_ADDRESS);
        tx.addOutput(c, OTHER_ADDRESS);
        tx.addOutput(c, OTHER_ADDRESS);
        tx.addOutput(c, OTHER_ADDRESS);
        SendRequest request = SendRequest.forTx(tx);
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.DustySendRequested.class)
    public void sendDustAndOpReturnWithoutValueTest() throws Exception {
        // Tests sending dust and OP_RETURN without value, should throw DustySendRequested because sending sending dust is not allowed in any case.
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        Transaction tx = new Transaction(UNITTEST);
        tx.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript("hello world!".getBytes()));
        tx.addOutput(Coin.SATOSHI, OTHER_ADDRESS);
        SendRequest request = SendRequest.forTx(tx);
        request.ensureMinRequiredFee = true;
        wallet.completeTx(request);
    }

    @Test(expected = Wallet.DustySendRequested.class)
    public void sendDustAndMessageWithValueTest() throws Exception {
        // Tests sending dust and OP_RETURN with value, should throw DustySendRequested
        receiveATransaction(wallet, myAddress);
        Transaction tx = new Transaction(UNITTEST);
        tx.addOutput(Coin.CENT, ScriptBuilder.createOpReturnScript("hello world!".getBytes()));
        Coin dustThreshold = new TransactionOutput(UNITTEST, null, Coin.COIN, OTHER_ADDRESS).getMinNonDustValue();
        tx.addOutput(dustThreshold.subtract(SATOSHI), OTHER_ADDRESS);
        SendRequest request = SendRequest.forTx(tx);
        request.ensureMinRequiredFee = true;
        wallet.completeTx(request);
    }

    @Test
    public void sendRequestP2PKTest() {
        ECKey key = new ECKey();
        SendRequest req = SendRequest.to(UNITTEST, key, SATOSHI.multiply(12));
        assertArrayEquals(key.getPubKey(),
                ScriptPattern.extractKeyFromP2PK(req.tx.getOutputs().get(0).getScriptPubKey()));
    }

    @Test
    public void sendRequestP2PKHTest() {
        SendRequest req = SendRequest.to(OTHER_ADDRESS, SATOSHI.multiply(12));
        assertEquals(OTHER_ADDRESS, req.tx.getOutputs().get(0).getScriptPubKey().getToAddress(UNITTEST));
    }

    @Test
    public void feeSolverAndCoinSelectionTest_dustySendRequested() throws Exception {
        // Generate a few outputs to us that are far too small to spend reasonably
        Transaction tx1 = createFakeTx(UNITTEST, SATOSHI, myAddress);
        Transaction tx2 = createFakeTx(UNITTEST, SATOSHI, myAddress);
        assertNotEquals(tx1.getTxId(), tx2.getTxId());
        Transaction tx3 = createFakeTx(UNITTEST, SATOSHI.multiply(10), myAddress);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx1, tx2, tx3);

        // Not allowed to send dust.
        try {
            SendRequest request = SendRequest.to(OTHER_ADDRESS, SATOSHI);
            request.ensureMinRequiredFee = true;
            wallet.completeTx(request);
            fail();
        } catch (Wallet.DustySendRequested e) {
            // Expected.
        }
        // Spend it all without fee enforcement
        SendRequest req = SendRequest.to(OTHER_ADDRESS, SATOSHI.multiply(12));
        assertNotNull(wallet.sendCoinsOffline(req));
        assertEquals(ZERO, wallet.getBalance());
    }

    @Test
    public void coinSelection_coinTimesDepth() throws Exception {
        Transaction txCent = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT);
        for (int i = 0; i < 197; i++)
            sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN);
        Transaction txCoin = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        assertEquals(COIN.add(CENT), wallet.getBalance());

        assertTrue(txCent.getOutput(0).isMine(wallet));
        assertTrue(txCent.getOutput(0).isAvailableForSpending());
        assertEquals(199, txCent.getConfidence().getDepthInBlocks());
        assertTrue(txCoin.getOutput(0).isMine(wallet));
        assertTrue(txCoin.getOutput(0).isAvailableForSpending());
        assertEquals(1, txCoin.getConfidence().getDepthInBlocks());
        // txCent has higher coin*depth than txCoin...
        assertTrue(txCent.getOutput(0).getValue().multiply(txCent.getConfidence().getDepthInBlocks())
                .isGreaterThan(txCoin.getOutput(0).getValue().multiply(txCoin.getConfidence().getDepthInBlocks())));
        // ...so txCent should be selected
        Transaction spend1 = wallet.createSend(OTHER_ADDRESS, CENT);
        assertEquals(1, spend1.getInputs().size());
        assertEquals(CENT, spend1.getInput(0).getValue());

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertTrue(txCent.getOutput(0).isMine(wallet));
        assertTrue(txCent.getOutput(0).isAvailableForSpending());
        assertEquals(200, txCent.getConfidence().getDepthInBlocks());
        assertTrue(txCoin.getOutput(0).isMine(wallet));
        assertTrue(txCoin.getOutput(0).isAvailableForSpending());
        assertEquals(2, txCoin.getConfidence().getDepthInBlocks());
        // Now txCent and txCoin have exactly the same coin*depth...
        assertEquals(txCent.getOutput(0).getValue().multiply(txCent.getConfidence().getDepthInBlocks()),
                txCoin.getOutput(0).getValue().multiply(txCoin.getConfidence().getDepthInBlocks()));
        // ...so the larger txCoin should be selected
        Transaction spend2 = wallet.createSend(OTHER_ADDRESS, COIN);
        assertEquals(1, spend2.getInputs().size());
        assertEquals(COIN, spend2.getInput(0).getValue());

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN);
        assertTrue(txCent.getOutput(0).isMine(wallet));
        assertTrue(txCent.getOutput(0).isAvailableForSpending());
        assertEquals(201, txCent.getConfidence().getDepthInBlocks());
        assertTrue(txCoin.getOutput(0).isMine(wallet));
        assertTrue(txCoin.getOutput(0).isAvailableForSpending());
        assertEquals(3, txCoin.getConfidence().getDepthInBlocks());
        // Now txCent has lower coin*depth than txCoin...
        assertTrue(txCent.getOutput(0).getValue().multiply(txCent.getConfidence().getDepthInBlocks())
                .isLessThan(txCoin.getOutput(0).getValue().multiply(txCoin.getConfidence().getDepthInBlocks())));
        // ...so txCoin should be selected
        Transaction spend3 = wallet.createSend(OTHER_ADDRESS, COIN);
        assertEquals(1, spend3.getInputs().size());
        assertEquals(COIN, spend3.getInput(0).getValue());
    }

    @Test
    public void feeSolverAndCoinSelectionTests2() throws Exception {
        Transaction tx5 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);

        // Now test feePerKb
        SendRequest request15 = SendRequest.to(OTHER_ADDRESS, CENT);
        for (int i = 0; i < 29; i++)
            request15.tx.addOutput(CENT, OTHER_ADDRESS);
        assertTrue(request15.tx.unsafeBitcoinSerialize().length > 1000);
        request15.feePerKb = Transaction.DEFAULT_TX_FEE;
        request15.ensureMinRequiredFee = true;
        wallet.completeTx(request15);
        assertEquals(Coin.valueOf(121300), request15.tx.getFee());
        Transaction spend15 = request15.tx;
        assertEquals(31, spend15.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(1, spend15.getInputs().size());
        assertEquals(COIN, spend15.getInput(0).getValue());

        // Test ensureMinRequiredFee
        SendRequest request16 = SendRequest.to(OTHER_ADDRESS, CENT);
        request16.feePerKb = ZERO;
        request16.ensureMinRequiredFee = true;
        for (int i = 0; i < 29; i++)
            request16.tx.addOutput(CENT, OTHER_ADDRESS);
        assertTrue(request16.tx.unsafeBitcoinSerialize().length > 1000);
        wallet.completeTx(request16);
        // Just the reference fee should be added if feePerKb == 0
        // Hardcoded tx length because actual length may vary depending on actual signature length
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(1213).divide(1000), request16.tx.getFee());
        Transaction spend16 = request16.tx;
        assertEquals(31, spend16.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(1, spend16.getInputs().size());
        assertEquals(COIN, spend16.getInput(0).getValue());

        // Create a transaction whose max size could be up to 999 (if signatures were maximum size)
        SendRequest request17 = SendRequest.to(OTHER_ADDRESS, CENT);
        for (int i = 0; i < 22; i++)
            request17.tx.addOutput(CENT, OTHER_ADDRESS);
        request17.tx.addOutput(new TransactionOutput(UNITTEST, request17.tx, CENT, new byte[15]));
        request17.feePerKb = Transaction.DEFAULT_TX_FEE;
        request17.ensureMinRequiredFee = true;
        wallet.completeTx(request17);
        assertEquals(Coin.valueOf(99900), request17.tx.getFee());
        assertEquals(1, request17.tx.getInputs().size());
        // Calculate its max length to make sure it is indeed 999
        int theoreticalMaxLength17 = request17.tx.unsafeBitcoinSerialize().length + myKey.getPubKey().length + 75;
        for (TransactionInput in : request17.tx.getInputs())
            theoreticalMaxLength17 -= in.getScriptBytes().length;
        assertEquals(999, theoreticalMaxLength17);
        Transaction spend17 = request17.tx;
        {
            // Its actual size must be between 996 and 999 (inclusive) as signatures have a 3-byte size range (almost always)
            final int length = spend17.unsafeBitcoinSerialize().length;
            assertTrue(Integer.toString(length), length >= 996 && length <= 999);
        }
        // Now check that it got a fee of 1 since its max size is 999 (1kb).
        assertEquals(25, spend17.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(1, spend17.getInputs().size());
        assertEquals(COIN, spend17.getInput(0).getValue());

        // Create a transaction who's max size could be up to 1001 (if signatures were maximum size)
        SendRequest request18 = SendRequest.to(OTHER_ADDRESS, CENT);
        for (int i = 0; i < 22; i++)
            request18.tx.addOutput(CENT, OTHER_ADDRESS);
        request18.tx.addOutput(new TransactionOutput(UNITTEST, request18.tx, CENT, new byte[17]));
        request18.feePerKb = Transaction.DEFAULT_TX_FEE;
        request18.ensureMinRequiredFee = true;
        wallet.completeTx(request18);
        assertEquals(Coin.valueOf(100100), request18.tx.getFee());
        assertEquals(1, request18.tx.getInputs().size());
        // Calculate its max length to make sure it is indeed 1001
        Transaction spend18 = request18.tx;
        int theoreticalMaxLength18 = spend18.unsafeBitcoinSerialize().length + myKey.getPubKey().length + 75;
        for (TransactionInput in : spend18.getInputs())
            theoreticalMaxLength18 -= in.getScriptBytes().length;
        assertEquals(1001, theoreticalMaxLength18);
        // Its actual size must be between 998 and 1000 (inclusive) as signatures have a 3-byte size range (almost always)
        assertTrue(spend18.unsafeBitcoinSerialize().length >= 998);
        assertTrue(spend18.unsafeBitcoinSerialize().length <= 1001);
        // Now check that it did get a fee since its max size is 1000
        assertEquals(25, spend18.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(1, spend18.getInputs().size());
        assertEquals(COIN, spend18.getInput(0).getValue());

        // Now create a transaction that will spend COIN + fee, which makes it require both inputs
        assertEquals(wallet.getBalance(), CENT.add(COIN));
        SendRequest request19 = SendRequest.to(OTHER_ADDRESS, CENT);
        request19.feePerKb = ZERO;
        for (int i = 0; i < 99; i++)
            request19.tx.addOutput(CENT, OTHER_ADDRESS);
        // If we send now, we should only have to spend our COIN
        wallet.completeTx(request19);
        assertEquals(Coin.ZERO, request19.tx.getFee());
        assertEquals(1, request19.tx.getInputs().size());
        assertEquals(100, request19.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request19.tx.clearInputs();
        request19 = SendRequest.forTx(request19.tx);
        request19.feePerKb = Transaction.DEFAULT_TX_FEE;
        request19.shuffleOutputs = false;
        wallet.completeTx(request19);
        assertEquals(Coin.valueOf(374200), request19.tx.getFee());
        assertEquals(2, request19.tx.getInputs().size());
        assertEquals(COIN, request19.tx.getInput(0).getValue());
        assertEquals(CENT, request19.tx.getInput(1).getValue());

        // Create another transaction that will spend COIN + fee, which makes it require both inputs
        SendRequest request20 = SendRequest.to(OTHER_ADDRESS, CENT);
        request20.feePerKb = ZERO;
        for (int i = 0; i < 99; i++)
            request20.tx.addOutput(CENT, OTHER_ADDRESS);
        // If we send now, we shouldn't have a fee and should only have to spend our COIN
        wallet.completeTx(request20);
        assertEquals(ZERO, request20.tx.getFee());
        assertEquals(1, request20.tx.getInputs().size());
        assertEquals(100, request20.tx.getOutputs().size());
        // Now reset request19 and give it a fee per kb
        request20.tx.clearInputs();
        request20 = SendRequest.forTx(request20.tx);
        request20.feePerKb = Transaction.DEFAULT_TX_FEE;
        wallet.completeTx(request20);
        // 4kb tx.
        assertEquals(Coin.valueOf(374200), request20.tx.getFee());
        assertEquals(2, request20.tx.getInputs().size());
        assertEquals(COIN, request20.tx.getInput(0).getValue());
        assertEquals(CENT, request20.tx.getInput(1).getValue());

        // Same as request 19, but make the change 0 (so it doesn't force fee) and make us require min fee
        SendRequest request21 = SendRequest.to(OTHER_ADDRESS, CENT);
        request21.feePerKb = ZERO;
        request21.ensureMinRequiredFee = true;
        for (int i = 0; i < 99; i++)
            request21.tx.addOutput(CENT, OTHER_ADDRESS);
        //request21.tx.addOutput(CENT.subtract(Coin.valueOf(18880-10)), OTHER_ADDRESS); //fails because tx size is calculated with a change output
        request21.tx.addOutput(CENT.subtract(Coin.valueOf(18880)), OTHER_ADDRESS); //3739 bytes, fee 5048 sat/kb
        //request21.tx.addOutput(CENT.subtract(Coin.valueOf(500000)), OTHER_ADDRESS); //3774 bytes, fee 5003 sat/kb
        // If we send without a feePerKb, we should still require REFERENCE_DEFAULT_MIN_TX_FEE because we have an output < 0.01
        wallet.completeTx(request21);
        // Hardcoded tx length because actual length may vary depending on actual signature length
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(3776).divide(1000), request21.tx.getFee());
        assertEquals(2, request21.tx.getInputs().size());
        assertEquals(COIN, request21.tx.getInput(0).getValue());
        assertEquals(CENT, request21.tx.getInput(1).getValue());

        // Test feePerKb when we aren't using ensureMinRequiredFee
        SendRequest request25 = SendRequest.to(OTHER_ADDRESS, CENT);
        request25.feePerKb = ZERO;
        for (int i = 0; i < 70; i++)
            request25.tx.addOutput(CENT, OTHER_ADDRESS);
        // If we send now, we shouldn't need a fee and should only have to spend our COIN
        wallet.completeTx(request25);
        assertEquals(ZERO, request25.tx.getFee());
        assertEquals(1, request25.tx.getInputs().size());
        assertEquals(72, request25.tx.getOutputs().size());
        // Now reset request25 and give it a fee per kb
        request25.tx.clearInputs();
        request25 = SendRequest.forTx(request25.tx);
        request25.feePerKb = Transaction.DEFAULT_TX_FEE;
        request25.shuffleOutputs = false;
        wallet.completeTx(request25);
        assertEquals(Coin.valueOf(279000), request25.tx.getFee());
        assertEquals(2, request25.tx.getInputs().size());
        assertEquals(COIN, request25.tx.getInput(0).getValue());
        assertEquals(CENT, request25.tx.getInput(1).getValue());

        // Spend our CENT output.
        Transaction spendTx5 = new Transaction(UNITTEST);
        spendTx5.addOutput(CENT, OTHER_ADDRESS);
        spendTx5.addInput(tx5.getOutput(0));
        wallet.signTransaction(SendRequest.forTx(spendTx5));

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, spendTx5);
        assertEquals(COIN, wallet.getBalance());

        // Ensure change is discarded if it is dust
        SendRequest request26 = SendRequest.to(OTHER_ADDRESS, CENT);
        for (int i = 0; i < 98; i++)
            request26.tx.addOutput(CENT, OTHER_ADDRESS);
        // Hardcoded tx length because actual length may vary depending on actual signature length
        Coin fee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(3560).divide(1000);
        Coin dustThresholdMinusOne = new TransactionOutput(UNITTEST, null, Coin.COIN, OTHER_ADDRESS).getMinNonDustValue().subtract(SATOSHI);
        request26.tx.addOutput(CENT.subtract(fee.add(dustThresholdMinusOne)),
                OTHER_ADDRESS);
        assertTrue(request26.tx.unsafeBitcoinSerialize().length > 1000);
        request26.feePerKb = SATOSHI;
        request26.ensureMinRequiredFee = true;
        wallet.completeTx(request26);
        assertEquals(fee.add(dustThresholdMinusOne), request26.tx.getFee());
        Transaction spend26 = request26.tx;
        assertEquals(100, spend26.getOutputs().size());
        // We optimize for priority, so the output selected should be the largest one
        assertEquals(1, spend26.getInputs().size());
        assertEquals(COIN, spend26.getInput(0).getValue());
    }

    @Test
    public void recipientPaysFees() throws Exception {
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);

        // Simplest recipientPaysFees use case
        Coin valueToSend = CENT.divide(2);
        SendRequest request = SendRequest.to(OTHER_ADDRESS, valueToSend);
        request.feePerKb = Transaction.DEFAULT_TX_FEE;
        request.ensureMinRequiredFee = true;
        request.recipientsPayFees = true;
        request.shuffleOutputs = false;
        wallet.completeTx(request);
        // Hardcoded tx length because actual length may vary depending on actual signature length
        Coin fee = request.feePerKb.multiply(227).divide(1000);
        assertEquals(fee, request.tx.getFee());
        Transaction spend = request.tx;
        assertEquals(2, spend.getOutputs().size());
        assertEquals(valueToSend.subtract(fee), spend.getOutput(0).getValue());
        assertEquals(COIN.subtract(valueToSend), spend.getOutput(1).getValue());
        assertEquals(1, spend.getInputs().size());
        assertEquals(COIN, spend.getInput(0).getValue());

        // Fee is split between the 2 outputs
        SendRequest request2 = SendRequest.to(OTHER_ADDRESS, valueToSend);
        request2.tx.addOutput(valueToSend, OTHER_ADDRESS);
        request2.feePerKb = Transaction.DEFAULT_TX_FEE;
        request2.ensureMinRequiredFee = true;
        request2.recipientsPayFees = true;
        request2.shuffleOutputs = false;
        wallet.completeTx(request2);
        // Hardcoded tx length because actual length may vary depending on actual signature length
        Coin fee2 = request2.feePerKb.multiply(261).divide(1000);
        assertEquals(fee2, request2.tx.getFee());
        Transaction spend2 = request2.tx;
        assertEquals(3, spend2.getOutputs().size());
        assertEquals(valueToSend.subtract(fee2.divide(2)), spend2.getOutput(0).getValue());
        assertEquals(valueToSend.subtract(fee2.divide(2)), spend2.getOutput(1).getValue());
        assertEquals(COIN.subtract(valueToSend.multiply(2)), spend2.getOutput(2).getValue());
        assertEquals(1, spend2.getInputs().size());
        assertEquals(COIN, spend2.getInput(0).getValue());

        // Fee is split between the 3 outputs. Division has a remainder which is taken from the first output
        SendRequest request3 = SendRequest.to(OTHER_ADDRESS, valueToSend);
        request3.tx.addOutput(valueToSend, OTHER_ADDRESS);
        request3.tx.addOutput(valueToSend, OTHER_ADDRESS);
        request3.feePerKb = Transaction.DEFAULT_TX_FEE;
        request3.ensureMinRequiredFee = true;
        request3.recipientsPayFees = true;
        request3.shuffleOutputs = false;
        wallet.completeTx(request3);
        // Hardcoded tx length because actual length may vary depending on actual signature length
        Coin fee3 = request3.feePerKb.multiply(295).divide(1000);
        assertEquals(fee3, request3.tx.getFee());
        Transaction spend3 = request3.tx;
        assertEquals(4, spend3.getOutputs().size());
        // 1st output pays the fee division remainder
        assertEquals(valueToSend.subtract(fee3.divideAndRemainder(3)[0]).subtract(fee3.divideAndRemainder(3)[1]),
                spend3.getOutput(0).getValue());
        assertEquals(valueToSend.subtract(fee3.divide(3)), spend3.getOutput(1).getValue());
        assertEquals(valueToSend.subtract(fee3.divide(3)), spend3.getOutput(2).getValue());
        assertEquals(COIN.subtract(valueToSend.multiply(3)), spend3.getOutput(3).getValue());
        assertEquals(1, spend3.getInputs().size());
        assertEquals(COIN, spend3.getInput(0).getValue());

        // Output when subtracted fee is dust
        // Hardcoded tx length because actual length may vary depending on actual signature length
        Coin fee4 = Transaction.DEFAULT_TX_FEE.multiply(227).divide(1000);
        Coin dustThreshold = new TransactionOutput(UNITTEST, null, Coin.COIN, OTHER_ADDRESS).getMinNonDustValue();
        valueToSend = fee4.add(dustThreshold).subtract(SATOSHI);
        SendRequest request4 = SendRequest.to(OTHER_ADDRESS, valueToSend);
        request4.feePerKb = Transaction.DEFAULT_TX_FEE;
        request4.ensureMinRequiredFee = true;
        request4.recipientsPayFees = true;
        request4.shuffleOutputs = false;
        try {
            wallet.completeTx(request4);
            fail("Expected CouldNotAdjustDownwards exception");
        } catch (Wallet.CouldNotAdjustDownwards e) {
        }

        // Change is dust, so it is incremented to min non dust value. First output value is reduced to compensate.
        // Hardcoded tx length because actual length may vary depending on actual signature length
        Coin fee5 = Transaction.DEFAULT_TX_FEE.multiply(261).divide(1000);
        valueToSend = COIN.divide(2).subtract(Coin.MICROCOIN);
        SendRequest request5 = SendRequest.to(OTHER_ADDRESS, valueToSend);
        request5.tx.addOutput(valueToSend, OTHER_ADDRESS);
        request5.feePerKb = Transaction.DEFAULT_TX_FEE;
        request5.ensureMinRequiredFee = true;
        request5.recipientsPayFees = true;
        request5.shuffleOutputs = false;
        wallet.completeTx(request5);
        assertEquals(fee5, request5.tx.getFee());
        Transaction spend5 = request5.tx;
        assertEquals(3, spend5.getOutputs().size());
        Coin valueSubtractedFromFirstOutput = dustThreshold
                .subtract(COIN.subtract(valueToSend.multiply(2)));
        assertEquals(valueToSend.subtract(fee5.divide(2)).subtract(valueSubtractedFromFirstOutput),
                spend5.getOutput(0).getValue());
        assertEquals(valueToSend.subtract(fee5.divide(2)), spend5.getOutput(1).getValue());
        assertEquals(dustThreshold, spend5.getOutput(2).getValue());
        assertEquals(1, spend5.getInputs().size());
        assertEquals(COIN, spend5.getInput(0).getValue());

        // Change is dust, so it is incremented to min non dust value. First output value is about to be reduced to
        // compensate, but after subtracting some satoshis, first output is dust.
        // Hardcoded tx length because actual length may vary depending on actual signature length
        Coin fee6 = Transaction.DEFAULT_TX_FEE.multiply(261).divide(1000);
        Coin valueToSend1 = fee6.divide(2).add(dustThreshold).add(Coin.MICROCOIN);
        Coin valueToSend2 = COIN.subtract(valueToSend1).subtract(Coin.MICROCOIN.multiply(2));
        SendRequest request6 = SendRequest.to(OTHER_ADDRESS, valueToSend1);
        request6.tx.addOutput(valueToSend2, OTHER_ADDRESS);
        request6.feePerKb = Transaction.DEFAULT_TX_FEE;
        request6.ensureMinRequiredFee = true;
        request6.recipientsPayFees = true;
        request6.shuffleOutputs = false;
        try {
            wallet.completeTx(request6);
            fail("Expected CouldNotAdjustDownwards exception");
        } catch (Wallet.CouldNotAdjustDownwards e) {
        }
    }

    @Test
    public void transactionGetFeeTest() throws Exception {
        // Prepare wallet to spend
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, OTHER_ADDRESS), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);

        // Create a transaction
        SendRequest request = SendRequest.to(OTHER_ADDRESS, CENT);
        request.feePerKb = Transaction.DEFAULT_TX_FEE;
        wallet.completeTx(request);
        assertEquals(Coin.valueOf(22700), request.tx.getFee());
    }

    @Test
    public void witnessTransactionGetFeeTest() throws Exception {
        Wallet mySegwitWallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2WPKH);
        Address mySegwitAddress = mySegwitWallet.freshReceiveAddress(ScriptType.P2WPKH);

        // Prepare wallet to spend
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, OTHER_SEGWIT_ADDRESS), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(UNITTEST, COIN, mySegwitAddress);
        mySegwitWallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);

        // Create a transaction
        SendRequest request = SendRequest.to(OTHER_SEGWIT_ADDRESS, CENT);
        request.feePerKb = Transaction.DEFAULT_TX_FEE;
        mySegwitWallet.completeTx(request);

        // Fee test, absolute and per virtual kilobyte
        Coin fee = request.tx.getFee();
        int vsize = request.tx.getVsize();
        Coin feePerVkb = fee.multiply(1000).divide(vsize);
        assertEquals(Coin.valueOf(14100), fee);
        assertEquals(Transaction.DEFAULT_TX_FEE, feePerVkb);
    }

    @Test
    public void lowerThanDefaultFee() throws InsufficientMoneyException {
        int feeFactor = 200;
        Coin fee = Transaction.DEFAULT_TX_FEE.divide(feeFactor);
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        SendRequest req = SendRequest.to(myAddress, Coin.CENT);
        req.feePerKb = fee;
        wallet.completeTx(req);
        assertEquals(Coin.valueOf(22700).divide(feeFactor), req.tx.getFee());
        wallet.commitTx(req.tx);
        SendRequest emptyReq = SendRequest.emptyWallet(myAddress);
        emptyReq.feePerKb = fee;
        emptyReq.ensureMinRequiredFee = true;
        emptyReq.emptyWallet = true;
        emptyReq.allowUnconfirmed();
        wallet.completeTx(emptyReq);
        final Coin feePerKb = emptyReq.tx.getFee().multiply(1000).divide(emptyReq.tx.getVsize());
        assertThat((double) feePerKb.toSat(), closeTo(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.toSat(),20));
        wallet.commitTx(emptyReq.tx);
    }

    @Test
    public void higherThanDefaultFee() throws InsufficientMoneyException {
        int feeFactor = 10;
        Coin fee = Transaction.DEFAULT_TX_FEE.multiply(feeFactor);
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        SendRequest req = SendRequest.to(myAddress, Coin.CENT);
        req.feePerKb = fee;
        wallet.completeTx(req);
        assertEquals(Coin.valueOf(22700).multiply(feeFactor), req.tx.getFee());
        wallet.commitTx(req.tx);
        SendRequest emptyReq = SendRequest.emptyWallet(myAddress);
        emptyReq.feePerKb = fee;
        emptyReq.emptyWallet = true;
        emptyReq.allowUnconfirmed();
        wallet.completeTx(emptyReq);
        assertEquals(Coin.valueOf(342000), emptyReq.tx.getFee());
        wallet.commitTx(emptyReq.tx);
    }

    @Test
    public void testCompleteTxWithExistingInputs() throws Exception {
        // Tests calling completeTx with a SendRequest that already has a few inputs in it

        // Generate a few outputs to us
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, OTHER_ADDRESS), BigInteger.ONE, 1);
        Transaction tx1 = createFakeTx(UNITTEST, COIN, myAddress);
        wallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        Transaction tx2 = createFakeTx(UNITTEST, COIN, myAddress);
        assertNotEquals(tx1.getTxId(), tx2.getTxId());
        wallet.receiveFromBlock(tx2, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        Transaction tx3 = createFakeTx(UNITTEST, CENT, myAddress);
        wallet.receiveFromBlock(tx3, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 2);

        SendRequest request1 = SendRequest.to(OTHER_ADDRESS, CENT);
        // If we just complete as-is, we will use one of the COIN outputs to get higher priority,
        // resulting in a change output
        request1.shuffleOutputs = false;
        wallet.completeTx(request1);
        assertEquals(1, request1.tx.getInputs().size());
        assertEquals(2, request1.tx.getOutputs().size());
        assertEquals(CENT, request1.tx.getOutput(0).getValue());
        assertEquals(COIN.subtract(CENT), request1.tx.getOutput(1).getValue());

        // Now create an identical request2 and add an unsigned spend of the CENT output
        SendRequest request2 = SendRequest.to(OTHER_ADDRESS, CENT);
        request2.tx.addInput(tx3.getOutput(0));
        // Now completeTx will result in one input, one output
        wallet.completeTx(request2);
        assertEquals(1, request2.tx.getInputs().size());
        assertEquals(1, request2.tx.getOutputs().size());
        assertEquals(CENT, request2.tx.getOutput(0).getValue());
        // Make sure it was properly signed
        request2.tx.getInput(0).getScriptSig().correctlySpends(
                request2.tx, 0, null, null, tx3.getOutput(0).getScriptPubKey(), Script.ALL_VERIFY_FLAGS);

        // However, if there is no connected output, we will grab a COIN output anyway and add the CENT to fee
        SendRequest request3 = SendRequest.to(OTHER_ADDRESS, CENT);
        request3.tx.addInput(new TransactionInput(UNITTEST, request3.tx, new byte[]{}, new TransactionOutPoint(UNITTEST, 0, tx3.getTxId())));
        // Now completeTx will result in two inputs, two outputs and a fee of a CENT
        // Note that it is simply assumed that the inputs are correctly signed, though in fact the first is not
        request3.shuffleOutputs = false;
        wallet.completeTx(request3);
        assertEquals(2, request3.tx.getInputs().size());
        assertEquals(2, request3.tx.getOutputs().size());
        assertEquals(CENT, request3.tx.getOutput(0).getValue());
        assertEquals(COIN.subtract(CENT), request3.tx.getOutput(1).getValue());

        SendRequest request4 = SendRequest.to(OTHER_ADDRESS, CENT);
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
    public void exceptionsDoNotBlockAllListeners() {
        // Check that if a wallet listener throws an exception, the others still run.
        wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> {
            log.info("onCoinsReceived 1");
            throw new RuntimeException("barf");
        });
        final AtomicInteger flag = new AtomicInteger();
        wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> {
            log.info("onCoinsReceived 2");
            flag.incrementAndGet();
        });

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        log.info("Wait for user thread");
        Threading.waitForUserCode();
        log.info("... and test flag.");
        assertEquals(1, flag.get());
    }

    @Test
    public void testEmptyRandomWallet() throws Exception {
        // Add a random set of outputs
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, OTHER_ADDRESS), BigInteger.ONE, 1);
        Random rng = new Random();
        for (int i = 0; i < rng.nextInt(100) + 1; i++) {
            Transaction tx = createFakeTx(UNITTEST, Coin.valueOf(rng.nextInt((int) COIN.value)), myAddress);
            wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, i);
        }
        SendRequest request = SendRequest.emptyWallet(OTHER_ADDRESS);
        wallet.completeTx(request);
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
    }

    @Test
    public void testEmptyWallet() throws Exception {
        // Add exactly 0.01
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, OTHER_ADDRESS), BigInteger.ONE, 1);
        Transaction tx = createFakeTx(UNITTEST, CENT, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        SendRequest request = SendRequest.emptyWallet(OTHER_ADDRESS);
        wallet.completeTx(request);
        assertEquals(ZERO, request.tx.getFee());
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(CENT, request.tx.getOutput(0).getValue());

        // Add 1 confirmed cent and 1 unconfirmed cent. Verify only one cent is emptied because of the coin selection
        // policies that are in use by default.
        block = new StoredBlock(makeSolvedTestBlock(blockStore, OTHER_ADDRESS), BigInteger.ONE, 2);
        tx = createFakeTx(UNITTEST, CENT, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        tx = createFakeTx(UNITTEST, CENT, myAddress);
        wallet.receivePending(tx, null);
        request = SendRequest.emptyWallet(OTHER_ADDRESS);
        wallet.completeTx(request);
        assertEquals(ZERO, request.tx.getFee());
        wallet.commitTx(request.tx);
        assertEquals(ZERO, wallet.getBalance());
        assertEquals(CENT, request.tx.getOutput(0).getValue());

        // Add an unsendable value
        block = new StoredBlock(block.getHeader().createNextBlock(OTHER_ADDRESS), BigInteger.ONE, 3);
        Coin dustThresholdMinusOne = new TransactionOutput(UNITTEST, null, Coin.COIN, OTHER_ADDRESS).getMinNonDustValue().subtract(SATOSHI);
        tx = createFakeTx(UNITTEST, dustThresholdMinusOne, myAddress);
        wallet.receiveFromBlock(tx, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);
        try {
            request = SendRequest.emptyWallet(OTHER_ADDRESS);
            wallet.completeTx(request);
            assertEquals(ZERO, request.tx.getFee());
            fail();
        } catch (Wallet.CouldNotAdjustDownwards e) {}
    }

    @Test
    public void childPaysForParent() {
        // Receive confirmed balance to play with.
        Transaction toMe = createFakeTxWithoutChangeAddress(UNITTEST, COIN, myAddress);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, toMe);
        assertEquals(Coin.COIN, wallet.getBalance(BalanceType.ESTIMATED_SPENDABLE));
        assertEquals(Coin.COIN, wallet.getBalance(BalanceType.AVAILABLE_SPENDABLE));
        // Receive unconfirmed coin without fee.
        Transaction toMeWithoutFee = createFakeTxWithoutChangeAddress(UNITTEST, COIN, myAddress);
        wallet.receivePending(toMeWithoutFee, null);
        assertEquals(Coin.COIN.multiply(2), wallet.getBalance(BalanceType.ESTIMATED_SPENDABLE));
        assertEquals(Coin.COIN, wallet.getBalance(BalanceType.AVAILABLE_SPENDABLE));
        // Craft a child-pays-for-parent transaction.
        final Coin feeRaise = MILLICOIN;
        final SendRequest sendRequest = SendRequest.childPaysForParent(wallet, toMeWithoutFee, feeRaise);
        wallet.signTransaction(sendRequest);
        wallet.commitTx(sendRequest.tx);
        assertEquals(Transaction.Purpose.RAISE_FEE, sendRequest.tx.getPurpose());
        assertEquals(Coin.COIN.multiply(2).subtract(feeRaise), wallet.getBalance(BalanceType.ESTIMATED_SPENDABLE));
        assertEquals(Coin.COIN, wallet.getBalance(BalanceType.AVAILABLE_SPENDABLE));
    }

    @Test
    public void keyRotationRandom() throws Exception {
        Utils.setMockClock();
        // Start with an empty wallet (no HD chain).
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        // Watch out for wallet-initiated broadcasts.
        MockTransactionBroadcaster broadcaster = new MockTransactionBroadcaster(wallet);
        // Send three cents to two different random keys, then add a key and mark the initial keys as compromised.
        ECKey key1 = new ECKey();
        key1.setCreationTimeSeconds(Utils.currentTimeSeconds() - (86400 * 2));
        ECKey key2 = new ECKey();
        key2.setCreationTimeSeconds(Utils.currentTimeSeconds() - 86400);
        wallet.importKey(key1);
        wallet.importKey(key2);
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, LegacyAddress.fromKey(UNITTEST, key1));
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, LegacyAddress.fromKey(UNITTEST, key2));
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, LegacyAddress.fromKey(UNITTEST, key2));
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
        assertEquals(Coin.valueOf(49100), tx.getFee());
        assertEquals(THREE_CENTS, tx.getValueSentFromMe(wallet));
        assertEquals(THREE_CENTS.subtract(tx.getFee()), tx.getValueSentToMe(wallet));
        // TX sends to one of our addresses (for now we ignore married wallets).
        final Address toAddress = tx.getOutput(0).getScriptPubKey().getToAddress(UNITTEST);
        final ECKey rotatingToKey = wallet.findKeyFromPubKeyHash(toAddress.getHash(), toAddress.getOutputScriptType());
        assertNotNull(rotatingToKey);
        assertFalse(wallet.isKeyRotating(rotatingToKey));
        assertEquals(3, tx.getInputs().size());
        // It confirms.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx);

        // Now receive some more money to the newly derived address via a new block and check that nothing happens.
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, toAddress);
        assertTrue(wallet.doMaintenance(null, true).get().isEmpty());
        assertEquals(0, broadcaster.size());

        // Receive money via a new block on key1 and ensure it shows up as a maintenance task.
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, LegacyAddress.fromKey(UNITTEST, key1));
        wallet.doMaintenance(null, true);
        tx = broadcaster.waitForTransactionAndSucceed();
        assertNotNull(wallet.findKeyFromPubKeyHash(tx.getOutput(0).getScriptPubKey().getPubKeyHash(),
                toAddress.getOutputScriptType()));
        log.info("Unexpected thing: {}", tx);
        assertEquals(Coin.valueOf(19300), tx.getFee());
        assertEquals(1, tx.getInputs().size());
        assertEquals(1, tx.getOutputs().size());
        assertEquals(CENT, tx.getValueSentFromMe(wallet));
        assertEquals(CENT.subtract(tx.getFee()), tx.getValueSentToMe(wallet));

        assertEquals(Transaction.Purpose.KEY_ROTATION, tx.getPurpose());

        // We don't attempt to race an attacker against unconfirmed transactions.

        // Now round-trip the wallet and check the protobufs are storing the data correctly.
        wallet = roundTrip(wallet);

        tx = wallet.getTransaction(tx.getTxId());
        checkNotNull(tx);
        assertEquals(Transaction.Purpose.KEY_ROTATION, tx.getPurpose());
        // Have to divide here to avoid mismatch due to second-level precision in serialisation.
        assertEquals(compromiseTime.getTime() / 1000, wallet.getKeyRotationTime().getTime() / 1000);

        // Make a normal spend and check it's all ok.
        wallet.sendCoins(broadcaster, OTHER_ADDRESS, wallet.getBalance());
        tx = broadcaster.waitForTransaction();
        assertArrayEquals(OTHER_ADDRESS.getHash(), tx.getOutput(0).getScriptPubKey().getPubKeyHash());
    }

    private Wallet roundTrip(Wallet wallet) throws UnreadableWalletException {
        int numActiveKeyChains = wallet.getActiveKeyChains().size();
        DeterministicKeyChain activeKeyChain = wallet.getActiveKeyChain();
        int numKeys = activeKeyChain.getKeys(false, true).size();
        int numIssuedInternal = activeKeyChain.getIssuedInternalKeys();
        int numIssuedExternal = activeKeyChain.getIssuedExternalKeys();
        DeterministicKey rootKey = wallet.getActiveKeyChain().getRootKey();
        DeterministicKey watchingKey = activeKeyChain.getWatchingKey();
        HDPath accountPath = activeKeyChain.getAccountPath();
        ScriptType outputScriptType = activeKeyChain.getOutputScriptType();

        Protos.Wallet protos = new WalletProtobufSerializer().walletToProto(wallet);
        Wallet roundTrippedWallet = new WalletProtobufSerializer().readWallet(UNITTEST, null, protos);

        assertEquals(numActiveKeyChains, roundTrippedWallet.getActiveKeyChains().size());
        DeterministicKeyChain roundTrippedActiveKeyChain = roundTrippedWallet.getActiveKeyChain();
        assertEquals(numKeys, roundTrippedActiveKeyChain.getKeys(false, true).size());
        assertEquals(numIssuedInternal, roundTrippedActiveKeyChain.getIssuedInternalKeys());
        assertEquals(numIssuedExternal, roundTrippedActiveKeyChain.getIssuedExternalKeys());
        assertEquals(rootKey, roundTrippedWallet.getActiveKeyChain().getRootKey());
        assertEquals(watchingKey, roundTrippedActiveKeyChain.getWatchingKey());
        assertEquals(accountPath, roundTrippedActiveKeyChain.getAccountPath());
        assertEquals(outputScriptType, roundTrippedActiveKeyChain.getOutputScriptType());
        return roundTrippedWallet;
    }

    @Test
    public void keyRotationHD() throws Exception {
        // Test that if we rotate an HD chain, a new one is created and all arrivals on the old keys are moved.
        Utils.setMockClock();
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        ECKey key1 = wallet.freshReceiveKey();
        ECKey key2 = wallet.freshReceiveKey();
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, LegacyAddress.fromKey(UNITTEST, key1));
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, LegacyAddress.fromKey(UNITTEST, key2));
        DeterministicKey watchKey1 = wallet.getWatchingKey();

        // A day later, we get compromised.
        Utils.rollMockClock(86400);
        wallet.setKeyRotationTime(Utils.currentTimeSeconds());

        List<Transaction> txns = wallet.doMaintenance(null, false).get();
        assertEquals(1, txns.size());
        DeterministicKey watchKey2 = wallet.getWatchingKey();
        assertNotEquals(watchKey1, watchKey2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void importOfHDKeyForbidden() {
        wallet.importKey(wallet.freshReceiveKey());
    }

    //@Test   //- this test is slow, disable for now.
    public void fragmentedReKeying() {
        // Send lots of small coins and check the fee is correct.
        ECKey key = wallet.freshReceiveKey();
        Address address = LegacyAddress.fromKey(UNITTEST, key);
        Utils.setMockClock();
        Utils.rollMockClock(86400);
        for (int i = 0; i < 800; i++) {
            sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, address);
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

    private static final byte[] EMPTY_SIG = {};

    @Test
    public void completeTxPartiallySignedWithDummySigs() throws Exception {
        byte[] dummySig = TransactionSignature.dummy().encodeToBitcoin();
        completeTxPartiallySigned(Wallet.MissingSigsMode.USE_DUMMY_SIG, dummySig);
    }

    @Test
    public void completeTxPartiallySignedWithEmptySig() throws Exception {
        completeTxPartiallySigned(Wallet.MissingSigsMode.USE_OP_ZERO, EMPTY_SIG);
    }

    @Test (expected = ECKey.MissingPrivateKeyException.class)
    public void completeTxPartiallySignedThrows() throws Exception {
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, myKey);
        SendRequest req = SendRequest.emptyWallet(OTHER_ADDRESS);
        wallet.completeTx(req);
        // Delete the sigs
        for (TransactionInput input : req.tx.getInputs())
            input.clearScriptBytes();
        Wallet watching = Wallet.fromWatchingKey(UNITTEST, wallet.getWatchingKey().dropParent().dropPrivateBytes(),
                ScriptType.P2PKH);
        watching.freshReceiveKey();
        watching.completeTx(SendRequest.forTx(req.tx));
    }

    @Test
    public void completeTxPartiallySignedMarriedWithDummySigs() throws Exception {
        byte[] dummySig = TransactionSignature.dummy().encodeToBitcoin();
        completeTxPartiallySignedMarried(Wallet.MissingSigsMode.USE_DUMMY_SIG, dummySig);
    }

    @Test
    public void completeTxPartiallySignedMarriedWithEmptySig() throws Exception {
        completeTxPartiallySignedMarried(Wallet.MissingSigsMode.USE_OP_ZERO, EMPTY_SIG);
    }

    @Test (expected = TransactionSigner.MissingSignatureException.class)
    public void completeTxPartiallySignedMarriedThrows() throws Exception {
        completeTxPartiallySignedMarried(Wallet.MissingSigsMode.THROW, EMPTY_SIG);
    }

    @Test (expected = TransactionSigner.MissingSignatureException.class)
    public void completeTxPartiallySignedMarriedThrowsByDefault() throws Exception {
        createMarriedWallet(2, 2, false);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN, myAddress);

        SendRequest req = SendRequest.emptyWallet(OTHER_ADDRESS);
        wallet.completeTx(req);
    }

    public void completeTxPartiallySignedMarried(Wallet.MissingSigsMode missSigMode, byte[] expectedSig) throws Exception {
        // create married wallet without signer
        createMarriedWallet(2, 2, false);
        myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN, myAddress);

        SendRequest req = SendRequest.emptyWallet(OTHER_ADDRESS);
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
        ECKey pub = ECKey.fromPublicOnly(priv);
        wallet.importKey(pub);
        ECKey priv2 = wallet.freshReceiveKey();
        // Send three transactions, with one being an address type and the other being a raw CHECKSIG type pubkey only,
        // and the final one being a key we do have. We expect the first two inputs to be dummy values and the last
        // to be signed correctly.
        Transaction t1 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, LegacyAddress.fromKey(UNITTEST, pub));
        Transaction t2 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, pub);
        Transaction t3 = sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, CENT, priv2);

        SendRequest req = SendRequest.emptyWallet(OTHER_ADDRESS);
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
                input.getScriptSig().correctlySpends(
                        req.tx, i, null, null, t3.getOutput(0).getScriptPubKey(), Script.ALL_VERIFY_FLAGS);
            }
        }
        assertTrue(TransactionSignature.isEncodingCanonical(dummySig));
    }

    @Test
    public void riskAnalysis() {
        // Send a tx that is considered risky to the wallet, verify it doesn't show up in the balances.
        final Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        final AtomicBoolean bool = new AtomicBoolean();
        wallet.setRiskAnalyzer((wallet, wtx, dependencies) -> {
            RiskAnalysis.Result result = RiskAnalysis.Result.OK;
            if (wtx.getTxId().equals(tx.getTxId()))
                result = RiskAnalysis.Result.NON_STANDARD;
            final RiskAnalysis.Result finalResult = result;
            return () -> {
                bool.set(true);
                return finalResult;
            };
        });
        assertTrue(wallet.isPendingTransactionRelevant(tx));
        assertEquals(Coin.ZERO, wallet.getBalance());
        assertEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        wallet.receivePending(tx, null);
        assertEquals(Coin.ZERO, wallet.getBalance());
        assertEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertTrue(bool.get());
        // Confirm it in the same manner as how Bloom filtered blocks do. Verify it shows up.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx);
        assertEquals(COIN, wallet.getBalance());
    }

    @Test
    public void transactionInBlockNotification() {
        final Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        StoredBlock block = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS, tx).storedBlock;
        wallet.receivePending(tx, null);
        boolean notification = wallet.notifyTransactionIsInBlock(tx.getTxId(), block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        assertTrue(notification);

        final Transaction tx2 = createFakeTx(UNITTEST, COIN, OTHER_ADDRESS);
        wallet.receivePending(tx2, null);
        StoredBlock block2 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS + 1, tx2).storedBlock;
        boolean notification2 = wallet.notifyTransactionIsInBlock(tx2.getTxId(), block2, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        assertFalse(notification2);
    }

    @Test
    public void duplicatedBlock() {
        final Transaction tx = createFakeTx(UNITTEST, COIN, myAddress);
        StoredBlock block = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS, tx).storedBlock;
        wallet.notifyNewBestBlock(block);
        wallet.notifyNewBestBlock(block);
    }

    @Test
    public void keyEvents() {
        // Check that we can register an event listener, generate some keys and the callbacks are invoked properly.
        wallet = new Wallet(UNITTEST, KeyChainGroup.builder(UNITTEST).fromRandom(ScriptType.P2PKH).build());
        final List<ECKey> keys = new LinkedList<>();
        wallet.addKeyChainEventListener(Threading.SAME_THREAD, keys::addAll);
        wallet.freshReceiveKey();
        assertEquals(1, keys.size());
    }

    @Test
    public void upgradeToDeterministic_P2PKH_to_P2WPKH_unencrypted() {
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        assertFalse(wallet.isEncrypted());
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2PKH));
        assertTrue(wallet.isDeterministicUpgradeRequired(ScriptType.P2WPKH));
        assertEquals(ScriptType.P2PKH, wallet.currentReceiveAddress().getOutputScriptType());
        assertEquals(ScriptType.P2PKH, wallet.freshReceiveAddress().getOutputScriptType());

        wallet.upgradeToDeterministic(ScriptType.P2WPKH, null);
        assertFalse(wallet.isEncrypted());
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2PKH));
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2WPKH));
        assertEquals(ScriptType.P2WPKH, wallet.currentReceiveAddress().getOutputScriptType());
        assertEquals(ScriptType.P2WPKH, wallet.freshReceiveAddress().getOutputScriptType());
    }

    @Test
    public void upgradeToDeterministic_P2PKH_to_P2WPKH_encrypted() {
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        assertFalse(wallet.isEncrypted());
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2PKH));
        assertTrue(wallet.isDeterministicUpgradeRequired(ScriptType.P2WPKH));

        KeyParameter aesKey = new KeyCrypterScrypt(SCRYPT_ITERATIONS).deriveKey("abc");
        wallet.encrypt(new KeyCrypterScrypt(), aesKey);
        assertTrue(wallet.isEncrypted());
        assertEquals(ScriptType.P2PKH, wallet.currentReceiveAddress().getOutputScriptType());
        assertEquals(ScriptType.P2PKH, wallet.freshReceiveAddress().getOutputScriptType());
        try {
            wallet.upgradeToDeterministic(ScriptType.P2WPKH, null);
            fail();
        } catch (DeterministicUpgradeRequiresPassword e) {
            // Expected.
        }

        wallet.upgradeToDeterministic(ScriptType.P2WPKH, aesKey);
        assertTrue(wallet.isEncrypted());
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2PKH));
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2WPKH));
        assertEquals(ScriptType.P2WPKH, wallet.currentReceiveAddress().getOutputScriptType());
        assertEquals(ScriptType.P2WPKH, wallet.freshReceiveAddress().getOutputScriptType());
    }

    @Test
    public void upgradeToDeterministic_noDowngrade_unencrypted() {
        wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2WPKH);
        assertFalse(wallet.isEncrypted());
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2PKH));
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2WPKH));
        assertEquals(ScriptType.P2WPKH, wallet.currentReceiveAddress().getOutputScriptType());
        assertEquals(ScriptType.P2WPKH, wallet.freshReceiveAddress().getOutputScriptType());

        wallet.upgradeToDeterministic(ScriptType.P2PKH, null);
        assertFalse(wallet.isEncrypted());
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2PKH));
        assertFalse(wallet.isDeterministicUpgradeRequired(ScriptType.P2WPKH));
        assertEquals(ScriptType.P2WPKH, wallet.currentReceiveAddress().getOutputScriptType());
        assertEquals(ScriptType.P2WPKH, wallet.freshReceiveAddress().getOutputScriptType());
    }

    @Test(expected = IllegalStateException.class)
    public void shouldNotAddTransactionSignerThatIsNotReady() {
        wallet.addTransactionSigner(new NopTransactionSigner(false));
    }

    @Test
    public void watchingMarriedWallet() throws Exception {
        DeterministicKey watchKey = wallet.getWatchingKey();
        String serialized = watchKey.serializePubB58(UNITTEST);
        Wallet wallet = Wallet.fromWatchingKeyB58(UNITTEST, serialized, 0);
        blockStore = new MemoryBlockStore(UNITTEST);
        chain = new BlockChain(UNITTEST, wallet, blockStore);

        final DeterministicKeyChain keyChain = DeterministicKeyChain.builder().random(new SecureRandom()).build();
        DeterministicKey partnerKey = DeterministicKey.deserializeB58(null, keyChain.getWatchingKey().serializePubB58(UNITTEST), UNITTEST);

        TransactionSigner signer = new TransactionSigner() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public boolean signInputs(ProposedTransaction propTx, KeyBag keyBag) {
                assertEquals(propTx.partialTx.getInputs().size(), propTx.keyPaths.size());
                HDPath externalZeroLeaf = DeterministicKeyChain.ACCOUNT_ZERO_PATH
                        .extend(DeterministicKeyChain.EXTERNAL_SUBPATH)
                        .extend(ChildNumber.ZERO);
                for (TransactionInput input : propTx.partialTx.getInputs()) {
                    HDPath keypath = HDPath.M(propTx.keyPaths.get(input.getConnectedOutput().getScriptPubKey()));
                    assertNotNull(keypath);
                    assertEquals(externalZeroLeaf.list(), keypath.list());
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

        Address myAddress = wallet.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        sendMoneyToWallet(wallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN, myAddress);

        SendRequest req = SendRequest.emptyWallet(OTHER_ADDRESS);
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
        SendRequest req = SendRequest.to(UNITTEST, key, SATOSHI.multiply(12));
        wallet.sendCoins(req);
    }

    @Test
    public void sendCoinsWithBroadcasterTest() throws InsufficientMoneyException {
        ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        receiveATransactionAmount(wallet, myAddress, Coin.COIN);
        MockTransactionBroadcaster broadcaster = new MockTransactionBroadcaster(wallet);
        wallet.setTransactionBroadcaster(broadcaster);
        SendRequest req = SendRequest.to(UNITTEST, key, Coin.CENT);
        wallet.sendCoins(req);
    }

    @Test
    public void createBasicWithKeys() {
        ECKey key = ECKey.fromPrivate(ByteUtils.HEX.decode("00905b93f990267f4104f316261fc10f9f983551f9ef160854f40102eb71cffdcc"));
        Wallet wallet = Wallet.createBasic(UNITTEST);
        wallet.importKey(key);
        assertEquals(1, wallet.getImportedKeys().size());
        assertEquals(key, wallet.getImportedKeys().get(0));
    }

    @Test
    public void reset() {
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN, myAddress);
        assertNotEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertNotEquals(0, wallet.getTransactions(false).size());
        assertNotEquals(0, wallet.getUnspents().size());
        wallet.reset();
        assertEquals(Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertEquals(0, wallet.getTransactions(false).size());
        assertEquals(0, wallet.getUnspents().size());
    }

    @Test
    public void totalReceivedSent() throws Exception {
        // Receive 4 BTC in 2 separate transactions
        Transaction toMe1 = createFakeTxWithoutChangeAddress(UNITTEST, COIN.multiply(2), myAddress);
        Transaction toMe2 = createFakeTxWithoutChangeAddress(UNITTEST, COIN.multiply(2), myAddress);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, toMe1, toMe2);

        // Check we calculate the total received correctly
        assertEquals(Coin.COIN.multiply(4), wallet.getTotalReceived());

        // Send 3 BTC in a single transaction
        SendRequest req = SendRequest.to(OTHER_ADDRESS, Coin.COIN.multiply(3));
        wallet.completeTx(req);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, req.tx);

        // Check that we still have the same totalReceived, since the above tx will have sent us change back
        assertEquals(Coin.COIN.multiply(4),wallet.getTotalReceived());
        assertEquals(Coin.COIN.multiply(3),wallet.getTotalSent());

        // TODO: test shared wallet calculation here
    }

    @Test
    public void testIrrelevantDoubleSpend() throws Exception {
        Transaction tx0 = createFakeTx(UNITTEST);
        Transaction tx1 = createFakeTx(UNITTEST);

        Transaction tx2 = new Transaction(UNITTEST);
        tx2.addInput(tx0.getOutput(0));
        tx2.addOutput(COIN, myAddress);
        tx2.addOutput(COIN, OTHER_ADDRESS);

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx2, tx1, tx0);

        // tx3 and tx4 double spend each other
        Transaction tx3 = new Transaction(UNITTEST);
        tx3.addInput(tx1.getOutput(0));
        tx3.addOutput(COIN, myAddress);
        tx3.addOutput(COIN, OTHER_ADDRESS);
        wallet.receivePending(tx3, null);

        // tx4 also spends irrelevant output from tx2
        Transaction tx4 = new Transaction(UNITTEST);
        tx4.addInput(tx1.getOutput(0)); // spends same output
        tx4.addInput(tx2.getOutput(1));
        tx4.addOutput(COIN, OTHER_ADDRESS);

        // tx4 does not actually get added to wallet here since it by itself is irrelevant
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx4);

        // since tx4 is not saved, tx2 output 1 will have bad spentBy
        wallet = roundTrip(wallet);

        assertTrue(wallet.isConsistent());
    }

    @Test
    public void overridingDeadTxTest() throws Exception {
        Transaction tx0 = createFakeTx(UNITTEST);

        Transaction tx1 = new Transaction(UNITTEST);
        tx1.addInput(tx0.getOutput(0));
        tx1.addOutput(COIN, OTHER_ADDRESS);
        tx1.addOutput(COIN, OTHER_ADDRESS);
        tx1.addOutput(COIN, myAddress); // to save this in wallet

        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx0, tx1);

        // tx2, tx3 and tx4 double spend each other
        Transaction tx2 = new Transaction(UNITTEST);
        tx2.addInput(tx1.getOutput(0));
        tx2.addInput(tx1.getOutput(1));
        tx2.addOutput(COIN, myAddress);
        tx2.addOutput(COIN, OTHER_ADDRESS);
        wallet.receivePending(tx2, null);

        // irrelevant to the wallet
        Transaction tx3 = new Transaction(UNITTEST);
        tx3.addInput(tx1.getOutput(0)); // spends same output as tx2
        tx3.addOutput(COIN, OTHER_ADDRESS);

        // irrelevant to the wallet
        Transaction tx4 = new Transaction(UNITTEST);
        tx4.addInput(tx1.getOutput(1)); // spends different output, but also in tx2
        tx4.addOutput(COIN, OTHER_ADDRESS);

        assertUnspent(tx1);
        assertPending(tx2);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx3);
        assertUnspent(tx1);
        assertDead(tx2);
        assertEquals(2, wallet.transactions.size()); // tx3 not saved
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, tx4);
        assertUnspent(tx1);
        assertDead(tx2);
        assertEquals(2, wallet.transactions.size()); // tx4 not saved

        // this will fail if tx4 does not get disconnected from tx1
        wallet = roundTrip(wallet);
        assertTrue(wallet.isConsistent());
    }

    @Test
    public void scriptTypeKeyChainRestrictions() {
        // Set up chains: basic chain, P2PKH deterministric chain, P2WPKH deterministic chain.
        DeterministicKeyChain p2pkhChain = DeterministicKeyChain.builder().random(new SecureRandom())
                .outputScriptType(ScriptType.P2PKH).build();
        DeterministicKeyChain p2wpkhChain = DeterministicKeyChain.builder().random(new SecureRandom())
                .outputScriptType(ScriptType.P2WPKH).build();
        KeyChainGroup kcg = KeyChainGroup.builder(UNITTEST).addChain(p2pkhChain).addChain(p2wpkhChain).build();
        Wallet wallet = new Wallet(UNITTEST, kcg);

        // Set up one key from each chain.
        ECKey importedKey = new ECKey();
        wallet.importKey(importedKey);
        ECKey p2pkhKey = p2pkhChain.getKey(KeyPurpose.RECEIVE_FUNDS);
        ECKey p2wpkhKey = p2wpkhChain.getKey(KeyPurpose.RECEIVE_FUNDS);

        // Test imported key: it's not limited to script type.
        assertTrue(wallet.isAddressMine(LegacyAddress.fromKey(UNITTEST, importedKey)));
        assertTrue(wallet.isAddressMine(SegwitAddress.fromKey(UNITTEST, importedKey)));
        assertEquals(importedKey, wallet.findKeyFromAddress(LegacyAddress.fromKey(UNITTEST, importedKey)));
        assertEquals(importedKey, wallet.findKeyFromAddress(SegwitAddress.fromKey(UNITTEST, importedKey)));

        // Test key from P2PKH chain: it's limited to P2PKH addresses
        assertTrue(wallet.isAddressMine(LegacyAddress.fromKey(UNITTEST, p2pkhKey)));
        assertFalse(wallet.isAddressMine(SegwitAddress.fromKey(UNITTEST, p2pkhKey)));
        assertEquals(p2pkhKey, wallet.findKeyFromAddress(LegacyAddress.fromKey(UNITTEST, p2pkhKey)));
        assertNull(wallet.findKeyFromAddress(SegwitAddress.fromKey(UNITTEST, p2pkhKey)));

        // Test key from P2WPKH chain: it's limited to P2WPKH addresses
        assertFalse(wallet.isAddressMine(LegacyAddress.fromKey(UNITTEST, p2wpkhKey)));
        assertTrue(wallet.isAddressMine(SegwitAddress.fromKey(UNITTEST, p2wpkhKey)));
        assertNull(wallet.findKeyFromAddress(LegacyAddress.fromKey(UNITTEST, p2wpkhKey)));
        assertEquals(p2wpkhKey, wallet.findKeyFromAddress(SegwitAddress.fromKey(UNITTEST, p2wpkhKey)));
    }

    @Test
    public void roundtripViaMnemonicCode() {
        Wallet wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2WPKH);
        List<String> mnemonicCode = wallet.getKeyChainSeed().getMnemonicCode();
        final DeterministicSeed clonedSeed = new DeterministicSeed(mnemonicCode, null, "",
                wallet.getEarliestKeyCreationTime());
        Wallet clone = Wallet.fromSeed(UNITTEST, clonedSeed, ScriptType.P2WPKH);
        assertEquals(wallet.currentReceiveKey(), clone.currentReceiveKey());
        assertEquals(wallet.freshReceiveAddress(ScriptType.P2PKH),
                clone.freshReceiveAddress(ScriptType.P2PKH));
    }

    @Test
    public void oneTxTwoWallets() {
        Wallet wallet1 = Wallet.createDeterministic(UNITTEST, ScriptType.P2WPKH);
        Wallet wallet2 = Wallet.createDeterministic(UNITTEST, ScriptType.P2WPKH);
        Address address1 = wallet1.freshReceiveAddress(ScriptType.P2PKH);
        Address address2 = wallet2.freshReceiveAddress(ScriptType.P2PKH);

        // Both wallet1 and wallet2 receive coins in the same tx
        Transaction tx0 = createFakeTx(UNITTEST);
        Transaction tx1 = new Transaction(UNITTEST);
        tx1.addInput(tx0.getOutput(0));
        tx1.addOutput(COIN, address1); // to wallet1
        tx1.addOutput(COIN, address2); // to wallet2
        tx1.addOutput(COIN, OTHER_ADDRESS);
        wallet1.receivePending(tx1, null);
        wallet2.receivePending(tx1, null);

        // Confirm transactions in both wallets
        StoredBlock block = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS, tx1).storedBlock;
        wallet1.notifyTransactionIsInBlock(tx1.getTxId(), block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);
        wallet2.notifyTransactionIsInBlock(tx1.getTxId(), block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 1);

        assertEquals(COIN, wallet1.getTotalReceived());
        assertEquals(COIN, wallet2.getTotalReceived());

        // Spend two outputs from the same tx from two different wallets
        SendRequest sendReq = SendRequest.to(OTHER_ADDRESS, valueOf(2, 0));
        sendReq.tx.addInput(tx1.getOutput(0));
        sendReq.tx.addInput(tx1.getOutput(1));

        // Wallet1 sign input 0
        TransactionInput inputW1 = sendReq.tx.getInput(0);
        ECKey sigKey1 = inputW1.getOutpoint().getConnectedKey(wallet1);
        Script scriptCode1 = ScriptBuilder.createP2PKHOutputScript(sigKey1);
        TransactionSignature txSig1 = sendReq.tx.calculateWitnessSignature(0, sigKey1, scriptCode1,
                inputW1.getValue(), Transaction.SigHash.ALL, false);
        inputW1.setScriptSig(ScriptBuilder.createEmpty());
        inputW1.setWitness(TransactionWitness.redeemP2WPKH(txSig1, sigKey1));

        // Wallet2 sign input 1
        TransactionInput inputW2 = sendReq.tx.getInput(1);
        ECKey sigKey2 = inputW2.getOutpoint().getConnectedKey(wallet2);
        Script scriptCode2 = ScriptBuilder.createP2PKHOutputScript(sigKey2);
        TransactionSignature txSig2 = sendReq.tx.calculateWitnessSignature(0, sigKey2, scriptCode2,
                inputW2.getValue(), Transaction.SigHash.ALL, false);
        inputW2.setScriptSig(ScriptBuilder.createEmpty());
        inputW2.setWitness(TransactionWitness.redeemP2WPKH(txSig2, sigKey2));

        wallet1.commitTx(sendReq.tx);
        wallet2.commitTx(sendReq.tx);
        assertEquals(ZERO, wallet1.getBalance());
        assertEquals(ZERO, wallet2.getBalance());

        assertTrue(wallet1.isConsistent());
        assertTrue(wallet2.isConsistent());

        Transaction txW1 = wallet1.getTransaction(tx1.getTxId());
        Transaction txW2 = wallet2.getTransaction(tx1.getTxId());

        assertEquals(txW1, tx1);
        assertNotSame(txW1, tx1);
        assertEquals(txW2, tx1);
        assertNotSame(txW2, tx1);
        assertEquals(txW1, txW2);
        assertNotSame(txW1, txW2);
    }
}
