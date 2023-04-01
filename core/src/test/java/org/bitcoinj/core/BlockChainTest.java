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

package org.bitcoinj.core;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.BalanceType;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.CompletableFuture;

import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.base.Coin.FIFTY_COINS;
import static org.bitcoinj.base.Coin.ZERO;
import static org.bitcoinj.base.Coin.valueOf;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// Handling of chain splits/reorgs are in ChainSplitTests.

public class BlockChainTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private Wallet testNetWallet;
    private MemoryBlockStore testNetStore;
    private BlockChain testNetChain;
    private Address coinbaseTo;

    private static final TestNet3Params TESTNET = TestNet3Params.get();

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();
        TimeUtils.setMockClock(); // Use mock clock
        Context.propagate(new Context(100, Coin.ZERO, false, false));
        testNetWallet = Wallet.createDeterministic(TESTNET, ScriptType.P2PKH);
        testNetStore = new MemoryBlockStore(TESTNET.getGenesisBlock());
        testNetChain = new BlockChain(TESTNET, testNetWallet, testNetStore);
        coinbaseTo = testNetWallet.currentReceiveKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
    }

    @Test
    public void testBasicChaining() throws Exception {
        // Check that we can plug a few blocks together and the futures work.
        CompletableFuture<StoredBlock> future = testNetChain.getHeightFuture(2);
        // Block 1 from the testnet.
        Block b1 = getBlock1();
        assertTrue(testNetChain.add(b1));
        assertFalse(future.isDone());
        // Block 2 from the testnet.
        Block b2 = getBlock2();

        // Let's try adding an invalid block.
        long n = b2.getNonce();
        try {
            b2.setNonce(12345);
            testNetChain.add(b2);
            fail();
        } catch (VerificationException e) {
            b2.setNonce(n);
        }

        // Now it works because we reset the nonce.
        assertTrue(testNetChain.add(b2));
        assertTrue(future.isDone());
        assertEquals(2, future.get().getHeight());
    }

    @Test
    public void receiveCoins() throws Exception {
        Context.propagate(new Context(100, Coin.ZERO, false, true));
        int height = 1;
        // Quick check that we can actually receive coins.
        Transaction tx1 = createFakeTx(TESTNET,
                                       COIN,
                                       testNetWallet.currentReceiveKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET));
        Block b1 = createFakeBlock(testNetStore, height, tx1).block;
        testNetChain.add(b1);
        assertTrue(testNetWallet.getBalance().signum() > 0);
    }

    @Test
    public void unconnectedBlocks() throws Exception {
        Context.propagate(new Context(100, Coin.ZERO, false, true));
        Block b1 = TESTNET.getGenesisBlock().createNextBlock(coinbaseTo);
        Block b2 = b1.createNextBlock(coinbaseTo);
        Block b3 = b2.createNextBlock(coinbaseTo);
        // Connected.
        assertTrue(testNetChain.add(b1));
        // Unconnected but stored. The head of the chain is still b1.
        assertFalse(testNetChain.add(b3));
        assertEquals(testNetChain.getChainHead().getHeader(), b1.cloneAsHeader());
        // Add in the middle block.
        assertTrue(testNetChain.add(b2));
        assertEquals(testNetChain.getChainHead().getHeader(), b3.cloneAsHeader());
    }

    @Test
    public void difficultyTransitions() throws Exception {
        NetworkParameters UNITTEST = UnitTestParams.get();
        BlockChain unitTestChain = new BlockChain(UNITTEST,
                Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH),
                new MemoryBlockStore(UNITTEST.getGenesisBlock()));

        // Add a bunch of blocks in a loop until we reach a difficulty transition point. The unit test params have an
        // artificially shortened period.
        Block prev = UNITTEST.getGenesisBlock();
        TimeUtils.setMockClock();
        for (int height = 0; height < UNITTEST.getInterval() - 1; height++) {
            Block newBlock = prev.createNextBlock(coinbaseTo, 1, TimeUtils.currentTime(), height);
            assertTrue(unitTestChain.add(newBlock));
            prev = newBlock;
            // The fake chain should seem to be "fast" for the purposes of difficulty calculations.
            TimeUtils.rollMockClock(Duration.ofSeconds(2));
        }
        // Now add another block that has no difficulty adjustment, it should be rejected.
        try {
            unitTestChain.add(prev.createNextBlock(coinbaseTo, 1, TimeUtils.currentTime(), UNITTEST.getInterval()));
            fail();
        } catch (VerificationException e) {
        }
        // Create a new block with the right difficulty target given our blistering speed relative to the huge amount
        // of time it's supposed to take (set in the unit test network parameters).
        Block b = prev.createNextBlock(coinbaseTo, 1, TimeUtils.currentTime(), UNITTEST.getInterval() + 1);
        b.setDifficultyTarget(0x201fFFFFL);
        b.solve();
        assertTrue(unitTestChain.add(b));
        // Successfully traversed a difficulty transition period.
    }

    private static class TweakableTestNet3Params extends TestNet3Params {
        public void setMaxTarget(BigInteger limit) {
            maxTarget = limit;
        }
    }

    @Test
    public void badDifficulty() throws Exception {
        TweakableTestNet3Params TWEAKABLE_TESTNET = new TweakableTestNet3Params();

        assertTrue(testNetChain.add(getBlock1()));
        Block b2 = getBlock2();
        assertTrue(testNetChain.add(b2));
        Block bad = new Block(TWEAKABLE_TESTNET, Block.BLOCK_VERSION_GENESIS);
        // Merkle root can be anything here, doesn't matter.
        bad.setMerkleRoot(Sha256Hash.wrap("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        // Nonce was just some number that made the hash < difficulty limit set below, it can be anything.
        bad.setNonce(140548933);
        bad.setTime(Instant.ofEpochSecond(1279242649));
        bad.setPrevBlockHash(b2.getHash());
        // We're going to make this block so easy 50% of solutions will pass, and check it gets rejected for having a
        // bad difficulty target. Unfortunately the encoding mechanism means we cannot make one that accepts all
        // solutions.
        bad.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
        try {
            testNetChain.add(bad);
            // The difficulty target above should be rejected on the grounds of being easier than the networks
            // allowable difficulty.
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage(), e.getCause().getMessage().contains("Difficulty target is bad"));
        }

        // Accept any level of difficulty now.
        BigInteger oldVal = TWEAKABLE_TESTNET.getMaxTarget();
        TWEAKABLE_TESTNET.setMaxTarget(new BigInteger("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16));
        try {
            testNetChain.add(bad);
            // We should not get here as the difficulty target should not be changing at this point.
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage(), e.getCause().getMessage().contains("Unexpected change in difficulty"));
        }
        TWEAKABLE_TESTNET.setMaxTarget(oldVal);

        // TODO: Test difficulty change is not out of range when a transition period becomes valid.
    }

    /**
     * Test that version 2 blocks are rejected once version 3 blocks are a super
     * majority.
     */
    @Test
    public void badBip66Version() throws Exception {
        testDeprecatedBlockVersion(Block.BLOCK_VERSION_BIP34, Block.BLOCK_VERSION_BIP66);
    }

    /**
     * Test that version 3 blocks are rejected once version 4 blocks are a super
     * majority.
     */
    @Test
    public void badBip65Version() throws Exception {
        testDeprecatedBlockVersion(Block.BLOCK_VERSION_BIP66, Block.BLOCK_VERSION_BIP65);
    }

    private void testDeprecatedBlockVersion(final long deprecatedVersion, final long newVersion)
            throws Exception {
        Context.propagate(new Context(100, Coin.ZERO, false, true));

        // Build a historical chain of version 3 blocks
        Instant time = Instant.ofEpochSecond(1231006505);
        int height = 0;
        FakeTxBuilder.BlockPair chainHead = null;

        // Put in just enough v2 blocks to be a minority
        for (height = 0; height < (TESTNET.getMajorityWindow() - TESTNET.getMajorityRejectBlockOutdated()); height++) {
            chainHead = FakeTxBuilder.createFakeBlock(testNetStore, deprecatedVersion, time, height);
            testNetChain.add(chainHead.block);
            time = time.plus(1, ChronoUnit.MINUTES);
        }
        // Fill the rest of the window with v3 blocks
        for (; height < TESTNET.getMajorityWindow(); height++) {
            chainHead = FakeTxBuilder.createFakeBlock(testNetStore, newVersion, time, height);
            testNetChain.add(chainHead.block);
            time = time.plus(1, ChronoUnit.MINUTES);
        }

        chainHead = FakeTxBuilder.createFakeBlock(testNetStore, deprecatedVersion, time, height);
        // Trying to add a new v2 block should result in rejection
        thrown.expect(VerificationException.BlockVersionOutOfDate.class);
        try {
            testNetChain.add(chainHead.block);
        } catch(final VerificationException ex) {
            throw (Exception) ex.getCause();
        }
    }

    @Test
    public void duplicates() throws Exception {
        Context.propagate(new Context(100, Coin.ZERO, false, true));
        // Adding a block twice should not have any effect, in particular it should not send the block to the wallet.
        Block b1 = TESTNET.getGenesisBlock().createNextBlock(coinbaseTo);
        Block b2 = b1.createNextBlock(coinbaseTo);
        Block b3 = b2.createNextBlock(coinbaseTo);
        assertTrue(testNetChain.add(b1));
        assertEquals(b1, testNetChain.getChainHead().getHeader());
        assertTrue(testNetChain.add(b2));
        assertEquals(b2, testNetChain.getChainHead().getHeader());
        assertTrue(testNetChain.add(b3));
        assertEquals(b3, testNetChain.getChainHead().getHeader());
        assertTrue(testNetChain.add(b2)); // add old block
        assertEquals(b3, testNetChain.getChainHead().getHeader()); // block didn't change, duplicate was spotted
    }

    @Test
    public void intraBlockDependencies() throws Exception {
        Context.propagate(new Context(100, Coin.ZERO, false, true));
        // Covers issue 166 in which transactions that depend on each other inside a block were not always being
        // considered relevant.
        Address somebodyElse = new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        Block b1 = TESTNET.getGenesisBlock().createNextBlock(somebodyElse);
        ECKey key = testNetWallet.freshReceiveKey();
        Address addr = key.toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        // Create a tx that gives us some coins, and another that spends it to someone else in the same block.
        Transaction t1 = FakeTxBuilder.createFakeTx(TESTNET, COIN, addr);
        Transaction t2 = new Transaction(TESTNET);
        t2.addInput(t1.getOutputs().get(0));
        t2.addOutput(valueOf(2, 0), somebodyElse);
        b1.addTransaction(t1);
        b1.addTransaction(t2);
        b1.solve();
        testNetChain.add(b1);
        assertEquals(Coin.ZERO, testNetWallet.getBalance());
    }

    @Test
    public void coinbaseTransactionAvailability() throws Exception {
        Context.propagate(new Context(100, Coin.ZERO, false, true));
        // Check that a coinbase transaction is only available to spend after NetworkParameters.getSpendableCoinbaseDepth() blocks.

        // Create a second wallet to receive the coinbase spend.
        Wallet wallet2 = Wallet.createDeterministic(TESTNET, ScriptType.P2PKH);
        ECKey receiveKey = wallet2.freshReceiveKey();
        int height = 1;
        testNetChain.addWallet(wallet2);

        Address addressToSendTo = receiveKey.toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);

        // Create a block, sending the coinbase to the coinbaseTo address (which is in the wallet).
        Block b1 = TESTNET.getGenesisBlock().createNextBlockWithCoinbase(Block.BLOCK_VERSION_GENESIS, testNetWallet.currentReceiveKey().getPubKey(), height++);
        testNetChain.add(b1);
        final Transaction coinbaseTransaction = b1.getTransactions().get(0);

        // Check a transaction has been received.
        assertNotNull(coinbaseTransaction);

        // The coinbase tx is not yet available to spend.
        assertEquals(Coin.ZERO, testNetWallet.getBalance());
        assertEquals(FIFTY_COINS, testNetWallet.getBalance(BalanceType.ESTIMATED));
        assertFalse(coinbaseTransaction.isMature());

        // Attempt to spend the coinbase - this should fail as the coinbase is not mature yet.
        try {
            testNetWallet.createSend(addressToSendTo, valueOf(49, 0));
            fail();
        } catch (InsufficientMoneyException e) {
        }

        // Check that the coinbase is unavailable to spend for the next spendableCoinbaseDepth - 2 blocks.
        for (int i = 0; i < TESTNET.getSpendableCoinbaseDepth() - 2; i++) {
            // Non relevant tx - just for fake block creation.
            Transaction tx2 = createFakeTx(TESTNET, COIN, new ECKey().toAddress(ScriptType.P2PKH, TESTNET.network()));

            Block b2 = createFakeBlock(testNetStore, height++, tx2).block;
            testNetChain.add(b2);

            // Wallet still does not have the coinbase transaction available for spend.
            assertEquals(Coin.ZERO, testNetWallet.getBalance());
            assertEquals(FIFTY_COINS, testNetWallet.getBalance(BalanceType.ESTIMATED));

            // The coinbase transaction is still not mature.
            assertFalse(coinbaseTransaction.isMature());

            // Attempt to spend the coinbase - this should fail.
            try {
                testNetWallet.createSend(addressToSendTo, valueOf(49, 0));
                fail();
            } catch (InsufficientMoneyException e) {
            }
        }

        // Give it one more block - should now be able to spend coinbase transaction. Non relevant tx.
        Transaction tx3 = createFakeTx(TESTNET, COIN, new ECKey().toAddress(ScriptType.P2PKH, TESTNET.network()));
        Block b3 = createFakeBlock(testNetStore, height++, tx3).block;
        testNetChain.add(b3);

        // Wallet now has the coinbase transaction available for spend.
        assertEquals(FIFTY_COINS, testNetWallet.getBalance());
        assertEquals(FIFTY_COINS, testNetWallet.getBalance(BalanceType.ESTIMATED));
        assertTrue(coinbaseTransaction.isMature());

        // Create a spend with the coinbase BTC to the address in the second wallet - this should now succeed.
        Transaction coinbaseSend2 = testNetWallet.createSend(addressToSendTo, valueOf(49, 0));
        assertNotNull(coinbaseSend2);

        // Commit the coinbaseSpend to the first wallet and check the balances decrement.
        testNetWallet.commitTx(coinbaseSend2);
        assertEquals(COIN, testNetWallet.getBalance(BalanceType.ESTIMATED));
        // Available balance is zero as change has not been received from a block yet.
        assertEquals(ZERO, testNetWallet.getBalance(BalanceType.AVAILABLE));

        // Give it one more block - change from coinbaseSpend should now be available in the first wallet.
        Block b4 = createFakeBlock(testNetStore, height++, coinbaseSend2).block;
        testNetChain.add(b4);
        assertEquals(COIN, testNetWallet.getBalance(BalanceType.AVAILABLE));

        // Check the balances in the second wallet.
        assertEquals(valueOf(49, 0), wallet2.getBalance(BalanceType.ESTIMATED));
        assertEquals(valueOf(49, 0), wallet2.getBalance(BalanceType.AVAILABLE));
    }

    // Some blocks from the test net.
    private static Block getBlock2() throws Exception {
        Block b2 = new Block(TESTNET, Block.BLOCK_VERSION_GENESIS);
        b2.setMerkleRoot(Sha256Hash.wrap("20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2"));
        b2.setNonce(875942400L);
        b2.setTime(Instant.ofEpochSecond(1296688946L));
        b2.setDifficultyTarget(0x1d00ffff);
        b2.setPrevBlockHash(Sha256Hash.wrap("00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206"));
        assertEquals("000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820", b2.getHashAsString());
        b2.verifyHeader();
        return b2;
    }

    private static Block getBlock1() throws Exception {
        Block b1 = new Block(TESTNET, Block.BLOCK_VERSION_GENESIS);
        b1.setMerkleRoot(Sha256Hash.wrap("f0315ffc38709d70ad5647e22048358dd3745f3ce3874223c80a7c92fab0c8ba"));
        b1.setNonce(1924588547);
        b1.setTime(Instant.ofEpochSecond(1296688928));
        b1.setDifficultyTarget(0x1d00ffff);
        b1.setPrevBlockHash(Sha256Hash.wrap("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        assertEquals("00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206", b1.getHashAsString());
        b1.verifyHeader();
        return b1;
    }

    @Test
    public void estimatedBlockTime() throws Exception {
        NetworkParameters MAINNET = MainNetParams.get();
        BlockChain prod = new BlockChain(MAINNET, new MemoryBlockStore(MAINNET.getGenesisBlock()));
        Instant t = prod.estimateBlockTimeInstant(200000);
        // The actual date of block 200,000 was 2012-09-22 10:47:00
        Instant expected = Instant.from(DateTimeFormatter.ISO_INSTANT.parse("2012-10-23T15:35:05Z"));
        assertEquals(expected, t);
    }

    @Test
    public void falsePositives() {
        double decay = AbstractBlockChain.FP_ESTIMATOR_ALPHA;
        assertTrue(0 == testNetChain.getFalsePositiveRate()); // Exactly
        testNetChain.trackFalsePositives(55);
        assertEquals(decay * 55, testNetChain.getFalsePositiveRate(), 1e-4);
        testNetChain.trackFilteredTransactions(550);
        double rate1 = testNetChain.getFalsePositiveRate();
        // Run this scenario a few more time for the filter to converge
        for (int i = 1 ; i < 10 ; i++) {
            testNetChain.trackFalsePositives(55);
            testNetChain.trackFilteredTransactions(550);
        }

        // Ensure we are within 10%
        assertEquals(0.1, testNetChain.getFalsePositiveRate(), 0.01);

        // Check that we get repeatable results after a reset
        testNetChain.resetFalsePositiveEstimate();
        assertTrue(0 == testNetChain.getFalsePositiveRate()); // Exactly

        testNetChain.trackFalsePositives(55);
        assertEquals(decay * 55, testNetChain.getFalsePositiveRate(), 1e-4);
        testNetChain.trackFilteredTransactions(550);
        assertEquals(rate1, testNetChain.getFalsePositiveRate(), 1e-4);
    }

    @Test
    public void rollbackBlockStore() throws Exception {
        Context.propagate(new Context(100, Coin.ZERO, false, true));
        // This test simulates an issue on Android, that causes the VM to crash while receiving a block, so that the
        // block store is persisted but the wallet is not.
        Block b1 = TESTNET.getGenesisBlock().createNextBlock(coinbaseTo);
        Block b2 = b1.createNextBlock(coinbaseTo);
        // Add block 1, no frills.
        assertTrue(testNetChain.add(b1));
        assertEquals(b1.cloneAsHeader(), testNetChain.getChainHead().getHeader());
        assertEquals(1, testNetChain.getBestChainHeight());
        assertEquals(1, testNetWallet.getLastBlockSeenHeight());
        // Add block 2 while wallet is disconnected, to simulate crash.
        testNetChain.removeWallet(testNetWallet);
        assertTrue(testNetChain.add(b2));
        assertEquals(b2.cloneAsHeader(), testNetChain.getChainHead().getHeader());
        assertEquals(2, testNetChain.getBestChainHeight());
        assertEquals(1, testNetWallet.getLastBlockSeenHeight());
        // Add wallet back. This will detect the height mismatch and repair the damage done.
        testNetChain.addWallet(testNetWallet);
        assertEquals(b1.cloneAsHeader(), testNetChain.getChainHead().getHeader());
        assertEquals(1, testNetChain.getBestChainHeight());
        assertEquals(1, testNetWallet.getLastBlockSeenHeight());
        // Now add block 2 correctly.
        assertTrue(testNetChain.add(b2));
        assertEquals(b2.cloneAsHeader(), testNetChain.getChainHead().getHeader());
        assertEquals(2, testNetChain.getBestChainHeight());
        assertEquals(2, testNetWallet.getLastBlockSeenHeight());
    }
}
