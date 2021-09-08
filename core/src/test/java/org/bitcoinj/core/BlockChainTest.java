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

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.BalanceType;

import com.google.common.util.concurrent.ListenableFuture;
import org.junit.rules.ExpectedException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import static org.bitcoinj.core.Coin.*;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;
import static org.junit.Assert.*;

// Handling of chain splits/reorgs are in ChainSplitTests.

public class BlockChainTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private BlockChain testNetChain;

    private Wallet wallet;
    private BlockChain chain;
    private BlockStore blockStore;
    private Address coinbaseTo;

    private final StoredBlock[] block = new StoredBlock[1];
    private Transaction coinbaseTransaction;

    private static class TweakableTestNet3Params extends TestNet3Params {
        public void setMaxTarget(BigInteger limit) {
            maxTarget = limit;
        }
    }
    private static final TweakableTestNet3Params TESTNET = new TweakableTestNet3Params();
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private void resetBlockStore() {
        blockStore = new MemoryBlockStore(UNITTEST);
    }

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();
        Utils.setMockClock(); // Use mock clock
        Context.propagate(new Context(TESTNET, 100, Coin.ZERO, false));
        testNetChain = new BlockChain(TESTNET, Wallet.createDeterministic(TESTNET, Script.ScriptType.P2PKH), new MemoryBlockStore(TESTNET));
        Context.propagate(new Context(UNITTEST, 100, Coin.ZERO, false));
        wallet = new Wallet(Context.get()) {
            @Override
            public void receiveFromBlock(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType,
                                         int relativityOffset) throws VerificationException {
                super.receiveFromBlock(tx, block, blockType, relativityOffset);
                BlockChainTest.this.block[0] = block;
                if (isTransactionRelevant(tx) && tx.isCoinBase()) {
                    BlockChainTest.this.coinbaseTransaction = tx;
                }
            }
        };
        wallet.freshReceiveKey();

        resetBlockStore();
        chain = new BlockChain(UNITTEST, wallet, blockStore);

        coinbaseTo = LegacyAddress.fromKey(UNITTEST, wallet.currentReceiveKey());
    }

    @Test
    public void testBasicChaining() throws Exception {
        // Check that we can plug a few blocks together and the futures work.
        ListenableFuture<StoredBlock> future = testNetChain.getHeightFuture(2);
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
        int height = 1;
        // Quick check that we can actually receive coins.
        Transaction tx1 = createFakeTx(UNITTEST,
                                       COIN,
                                       LegacyAddress.fromKey(UNITTEST, wallet.currentReceiveKey()));
        Block b1 = createFakeBlock(blockStore, height, tx1).block;
        chain.add(b1);
        assertTrue(wallet.getBalance().signum() > 0);
    }

    @Test
    public void unconnectedBlocks() throws Exception {
        Block b1 = UNITTEST.getGenesisBlock().createNextBlock(coinbaseTo);
        Block b2 = b1.createNextBlock(coinbaseTo);
        Block b3 = b2.createNextBlock(coinbaseTo);
        // Connected.
        assertTrue(chain.add(b1));
        // Unconnected but stored. The head of the chain is still b1.
        assertFalse(chain.add(b3));
        assertEquals(chain.getChainHead().getHeader(), b1.cloneAsHeader());
        // Add in the middle block.
        assertTrue(chain.add(b2));
        assertEquals(chain.getChainHead().getHeader(), b3.cloneAsHeader());
    }

    @Test
    public void difficultyTransitions() throws Exception {
        // Add a bunch of blocks in a loop until we reach a difficulty transition point. The unit test params have an
        // artificially shortened period.
        Block prev = UNITTEST.getGenesisBlock();
        Utils.setMockClock();
        for (int height = 0; height < UNITTEST.getInterval() - 1; height++) {
            Block newBlock = prev.createNextBlock(coinbaseTo, 1, Utils.currentTimeSeconds(), height);
            assertTrue(chain.add(newBlock));
            prev = newBlock;
            // The fake chain should seem to be "fast" for the purposes of difficulty calculations.
            Utils.rollMockClock(2);
        }
        // Now add another block that has no difficulty adjustment, it should be rejected.
        try {
            chain.add(prev.createNextBlock(coinbaseTo, 1, Utils.currentTimeSeconds(), UNITTEST.getInterval()));
            fail();
        } catch (VerificationException e) {
        }
        // Create a new block with the right difficulty target given our blistering speed relative to the huge amount
        // of time it's supposed to take (set in the unit test network parameters).
        Block b = prev.createNextBlock(coinbaseTo, 1, Utils.currentTimeSeconds(), UNITTEST.getInterval() + 1);
        b.setDifficultyTarget(0x201fFFFFL);
        b.solve();
        assertTrue(chain.add(b));
        // Successfully traversed a difficulty transition period.
    }

    @Test
    public void badDifficulty() throws Exception {
        assertTrue(testNetChain.add(getBlock1()));
        Block b2 = getBlock2();
        assertTrue(testNetChain.add(b2));
        Block bad = new Block(TESTNET, Block.BLOCK_VERSION_GENESIS);
        // Merkle root can be anything here, doesn't matter.
        bad.setMerkleRoot(Sha256Hash.wrap("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        // Nonce was just some number that made the hash < difficulty limit set below, it can be anything.
        bad.setNonce(140548933);
        bad.setTime(1279242649);
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
        BigInteger oldVal = TESTNET.getMaxTarget();
        TESTNET.setMaxTarget(new BigInteger("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16));
        try {
            testNetChain.add(bad);
            // We should not get here as the difficulty target should not be changing at this point.
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage(), e.getCause().getMessage().contains("Unexpected change in difficulty"));
        }
        TESTNET.setMaxTarget(oldVal);

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
        final BlockStore versionBlockStore = new MemoryBlockStore(UNITTEST);
        final BlockChain versionChain = new BlockChain(UNITTEST, versionBlockStore);

        // Build a historical chain of version 3 blocks
        long timeSeconds = 1231006505;
        int height = 0;
        FakeTxBuilder.BlockPair chainHead = null;

        // Put in just enough v2 blocks to be a minority
        for (height = 0; height < (UNITTEST.getMajorityWindow() - UNITTEST.getMajorityRejectBlockOutdated()); height++) {
            chainHead = FakeTxBuilder.createFakeBlock(versionBlockStore, deprecatedVersion, timeSeconds, height);
            versionChain.add(chainHead.block);
            timeSeconds += 60;
        }
        // Fill the rest of the window with v3 blocks
        for (; height < UNITTEST.getMajorityWindow(); height++) {
            chainHead = FakeTxBuilder.createFakeBlock(versionBlockStore, newVersion, timeSeconds, height);
            versionChain.add(chainHead.block);
            timeSeconds += 60;
        }

        chainHead = FakeTxBuilder.createFakeBlock(versionBlockStore, deprecatedVersion, timeSeconds, height);
        // Trying to add a new v2 block should result in rejection
        thrown.expect(VerificationException.BlockVersionOutOfDate.class);
        try {
            versionChain.add(chainHead.block);
        } catch(final VerificationException ex) {
            throw (Exception) ex.getCause();
        }
    }

    @Test
    public void duplicates() throws Exception {
        // Adding a block twice should not have any effect, in particular it should not send the block to the wallet.
        Block b1 = UNITTEST.getGenesisBlock().createNextBlock(coinbaseTo);
        Block b2 = b1.createNextBlock(coinbaseTo);
        Block b3 = b2.createNextBlock(coinbaseTo);
        assertTrue(chain.add(b1));
        assertEquals(b1, block[0].getHeader());
        assertTrue(chain.add(b2));
        assertEquals(b2, block[0].getHeader());
        assertTrue(chain.add(b3));
        assertEquals(b3, block[0].getHeader());
        assertEquals(b3, chain.getChainHead().getHeader());
        assertTrue(chain.add(b2));
        assertEquals(b3, chain.getChainHead().getHeader());
        // Wallet was NOT called with the new block because the duplicate add was spotted.
        assertEquals(b3, block[0].getHeader());
    }

    @Test
    public void intraBlockDependencies() throws Exception {
        // Covers issue 166 in which transactions that depend on each other inside a block were not always being
        // considered relevant.
        Address somebodyElse = LegacyAddress.fromKey(UNITTEST, new ECKey());
        Block b1 = UNITTEST.getGenesisBlock().createNextBlock(somebodyElse);
        ECKey key = wallet.freshReceiveKey();
        Address addr = LegacyAddress.fromKey(UNITTEST, key);
        // Create a tx that gives us some coins, and another that spends it to someone else in the same block.
        Transaction t1 = FakeTxBuilder.createFakeTx(UNITTEST, COIN, addr);
        Transaction t2 = new Transaction(UNITTEST);
        t2.addInput(t1.getOutputs().get(0));
        t2.addOutput(valueOf(2, 0), somebodyElse);
        b1.addTransaction(t1);
        b1.addTransaction(t2);
        b1.solve();
        chain.add(b1);
        assertEquals(Coin.ZERO, wallet.getBalance());
    }

    @Test
    public void coinbaseTransactionAvailability() throws Exception {
        // Check that a coinbase transaction is only available to spend after NetworkParameters.getSpendableCoinbaseDepth() blocks.

        // Create a second wallet to receive the coinbase spend.
        Wallet wallet2 = Wallet.createDeterministic(UNITTEST, Script.ScriptType.P2PKH);
        ECKey receiveKey = wallet2.freshReceiveKey();
        int height = 1;
        chain.addWallet(wallet2);

        Address addressToSendTo = LegacyAddress.fromKey(UNITTEST, receiveKey);

        // Create a block, sending the coinbase to the coinbaseTo address (which is in the wallet).
        Block b1 = UNITTEST.getGenesisBlock().createNextBlockWithCoinbase(Block.BLOCK_VERSION_GENESIS, wallet.currentReceiveKey().getPubKey(), height++);
        chain.add(b1);

        // Check a transaction has been received.
        assertNotNull(coinbaseTransaction);

        // The coinbase tx is not yet available to spend.
        assertEquals(Coin.ZERO, wallet.getBalance());
        assertEquals(wallet.getBalance(BalanceType.ESTIMATED), FIFTY_COINS);
        assertTrue(!coinbaseTransaction.isMature());

        // Attempt to spend the coinbase - this should fail as the coinbase is not mature yet.
        try {
            wallet.createSend(addressToSendTo, valueOf(49, 0));
            fail();
        } catch (InsufficientMoneyException e) {
        }

        // Check that the coinbase is unavailable to spend for the next spendableCoinbaseDepth - 2 blocks.
        for (int i = 0; i < UNITTEST.getSpendableCoinbaseDepth() - 2; i++) {
            // Non relevant tx - just for fake block creation.
            Transaction tx2 = createFakeTx(UNITTEST, COIN, LegacyAddress.fromKey(UNITTEST, new ECKey()));

            Block b2 = createFakeBlock(blockStore, height++, tx2).block;
            chain.add(b2);

            // Wallet still does not have the coinbase transaction available for spend.
            assertEquals(Coin.ZERO, wallet.getBalance());
            assertEquals(wallet.getBalance(BalanceType.ESTIMATED), FIFTY_COINS);

            // The coinbase transaction is still not mature.
            assertTrue(!coinbaseTransaction.isMature());

            // Attempt to spend the coinbase - this should fail.
            try {
                wallet.createSend(addressToSendTo, valueOf(49, 0));
                fail();
            } catch (InsufficientMoneyException e) {
            }
        }

        // Give it one more block - should now be able to spend coinbase transaction. Non relevant tx.
        Transaction tx3 = createFakeTx(UNITTEST, COIN, LegacyAddress.fromKey(UNITTEST, new ECKey()));
        Block b3 = createFakeBlock(blockStore, height++, tx3).block;
        chain.add(b3);

        // Wallet now has the coinbase transaction available for spend.
        assertEquals(wallet.getBalance(), FIFTY_COINS);
        assertEquals(wallet.getBalance(BalanceType.ESTIMATED), FIFTY_COINS);
        assertTrue(coinbaseTransaction.isMature());

        // Create a spend with the coinbase BTC to the address in the second wallet - this should now succeed.
        Transaction coinbaseSend2 = wallet.createSend(addressToSendTo, valueOf(49, 0));
        assertNotNull(coinbaseSend2);

        // Commit the coinbaseSpend to the first wallet and check the balances decrement.
        wallet.commitTx(coinbaseSend2);
        assertEquals(wallet.getBalance(BalanceType.ESTIMATED), COIN);
        // Available balance is zero as change has not been received from a block yet.
        assertEquals(wallet.getBalance(BalanceType.AVAILABLE), ZERO);

        // Give it one more block - change from coinbaseSpend should now be available in the first wallet.
        Block b4 = createFakeBlock(blockStore, height++, coinbaseSend2).block;
        chain.add(b4);
        assertEquals(wallet.getBalance(BalanceType.AVAILABLE), COIN);

        // Check the balances in the second wallet.
        assertEquals(wallet2.getBalance(BalanceType.ESTIMATED), valueOf(49, 0));
        assertEquals(wallet2.getBalance(BalanceType.AVAILABLE), valueOf(49, 0));
    }

    // Some blocks from the test net.
    private static Block getBlock2() throws Exception {
        Block b2 = new Block(TESTNET, Block.BLOCK_VERSION_GENESIS);
        b2.setMerkleRoot(Sha256Hash.wrap("20222eb90f5895556926c112bb5aa0df4ab5abc3107e21a6950aec3b2e3541e2"));
        b2.setNonce(875942400L);
        b2.setTime(1296688946L);
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
        b1.setTime(1296688928);
        b1.setDifficultyTarget(0x1d00ffff);
        b1.setPrevBlockHash(Sha256Hash.wrap("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        assertEquals("00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206", b1.getHashAsString());
        b1.verifyHeader();
        return b1;
    }

    @Test
    public void estimatedBlockTime() throws Exception {
        BlockChain prod = new BlockChain(new Context(MAINNET), new MemoryBlockStore(MAINNET));
        Date d = prod.estimateBlockTime(200000);
        // The actual date of block 200,000 was 2012-09-22 10:47:00
        assertEquals(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).parse("2012-10-23T08:35:05.000-0700"), d);
    }

    @Test
    public void falsePositives() throws Exception {
        double decay = AbstractBlockChain.FP_ESTIMATOR_ALPHA;
        assertTrue(0 == chain.getFalsePositiveRate()); // Exactly
        chain.trackFalsePositives(55);
        assertEquals(decay * 55, chain.getFalsePositiveRate(), 1e-4);
        chain.trackFilteredTransactions(550);
        double rate1 = chain.getFalsePositiveRate();
        // Run this scenario a few more time for the filter to converge
        for (int i = 1 ; i < 10 ; i++) {
            chain.trackFalsePositives(55);
            chain.trackFilteredTransactions(550);
        }

        // Ensure we are within 10%
        assertEquals(0.1, chain.getFalsePositiveRate(), 0.01);

        // Check that we get repeatable results after a reset
        chain.resetFalsePositiveEstimate();
        assertTrue(0 == chain.getFalsePositiveRate()); // Exactly

        chain.trackFalsePositives(55);
        assertEquals(decay * 55, chain.getFalsePositiveRate(), 1e-4);
        chain.trackFilteredTransactions(550);
        assertEquals(rate1, chain.getFalsePositiveRate(), 1e-4);
    }

    @Test
    public void rollbackBlockStore() throws Exception {
        // This test simulates an issue on Android, that causes the VM to crash while receiving a block, so that the
        // block store is persisted but the wallet is not.
        Block b1 = UNITTEST.getGenesisBlock().createNextBlock(coinbaseTo);
        Block b2 = b1.createNextBlock(coinbaseTo);
        // Add block 1, no frills.
        assertTrue(chain.add(b1));
        assertEquals(b1.cloneAsHeader(), chain.getChainHead().getHeader());
        assertEquals(1, chain.getBestChainHeight());
        assertEquals(1, wallet.getLastBlockSeenHeight());
        // Add block 2 while wallet is disconnected, to simulate crash.
        chain.removeWallet(wallet);
        assertTrue(chain.add(b2));
        assertEquals(b2.cloneAsHeader(), chain.getChainHead().getHeader());
        assertEquals(2, chain.getBestChainHeight());
        assertEquals(1, wallet.getLastBlockSeenHeight());
        // Add wallet back. This will detect the height mismatch and repair the damage done.
        chain.addWallet(wallet);
        assertEquals(b1.cloneAsHeader(), chain.getChainHead().getHeader());
        assertEquals(1, chain.getBestChainHeight());
        assertEquals(1, wallet.getLastBlockSeenHeight());
        // Now add block 2 correctly.
        assertTrue(chain.add(b2));
        assertEquals(b2.cloneAsHeader(), chain.getChainHead().getHeader());
        assertEquals(2, chain.getBestChainHeight());
        assertEquals(2, wallet.getLastBlockSeenHeight());
    }
}
