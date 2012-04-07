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
import com.google.bitcoin.utils.BriefLogFormatter;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static com.google.bitcoin.core.TestUtils.createFakeBlock;
import static com.google.bitcoin.core.TestUtils.createFakeTx;
import static org.junit.Assert.*;

// Handling of chain splits/reorgs are in ChainSplitTests.

public class BlockChainTest {
    private static final NetworkParameters testNet = NetworkParameters.testNet();
    private BlockChain testNetChain;

    private Wallet wallet;
    private BlockChain chain;
    private BlockStore blockStore;
    private Address coinbaseTo;
    private NetworkParameters unitTestParams;
    private final StoredBlock[] block = new StoredBlock[1];

    private void resetBlockStore() {
        blockStore = new MemoryBlockStore(unitTestParams);
    }

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();
        testNetChain = new BlockChain(testNet, new Wallet(testNet), new MemoryBlockStore(testNet));
        unitTestParams = NetworkParameters.unitTests();
        wallet = new Wallet(unitTestParams) {
            @Override
            public void receiveFromBlock(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType) throws VerificationException, ScriptException {
                super.receiveFromBlock(tx, block, blockType);
                BlockChainTest.this.block[0] = block;
            }
        };
        wallet.addKey(new ECKey());

        resetBlockStore();
        chain = new BlockChain(unitTestParams, wallet, blockStore);

        coinbaseTo = wallet.keychain.get(0).toAddress(unitTestParams);

    }

    @Test
    public void testBasicChaining() throws Exception {
        // Check that we can plug a few blocks together.
        // Block 1 from the testnet.
        Block b1 = getBlock1();
        assertTrue(testNetChain.add(b1));
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
    }

    @Test
    public void receiveCoins() throws Exception {
        // Quick check that we can actually receive coins.
        Transaction tx1 = createFakeTx(unitTestParams,
                                       Utils.toNanoCoins(1, 0),
                                       wallet.keychain.get(0).toAddress(unitTestParams));
        Block b1 = createFakeBlock(unitTestParams, blockStore, tx1).block;
        chain.add(b1);
        assertTrue(wallet.getBalance().compareTo(BigInteger.ZERO) > 0);
    }

    @Test
    public void merkleRoots() throws Exception {
        // Test that merkle root verification takes place when a relevant transaction is present and doesn't when
        // there isn't any such tx present (as an optimization).
        Transaction tx1 = createFakeTx(unitTestParams,
                                       Utils.toNanoCoins(1, 0),
                                       wallet.keychain.get(0).toAddress(unitTestParams));
        Block b1 = createFakeBlock(unitTestParams, blockStore, tx1).block;
        chain.add(b1);
        resetBlockStore();
        Sha256Hash hash = b1.getMerkleRoot();
        b1.setMerkleRoot(Sha256Hash.ZERO_HASH);
        try {
            chain.add(b1);
            fail();
        } catch (VerificationException e) {
            // Expected.
            b1.setMerkleRoot(hash);
        }
        // Now add a second block with no relevant transactions and then break it.
        Transaction tx2 = createFakeTx(unitTestParams, Utils.toNanoCoins(1, 0),
                                       new ECKey().toAddress(unitTestParams));
        Block b2 = createFakeBlock(unitTestParams, blockStore, tx2).block;
        hash = b2.getMerkleRoot();
        b2.setMerkleRoot(Sha256Hash.ZERO_HASH);
        b2.solve();
        chain.add(b2);  // Broken block is accepted because its contents don't matter to us.
    }

    @Test
    public void unconnectedBlocks() throws Exception {
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinbaseTo);
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
        Block prev = unitTestParams.genesisBlock;
        Block.fakeClock = System.currentTimeMillis() / 1000;
        for (int i = 0; i < unitTestParams.interval - 1; i++) {
            Block newBlock = prev.createNextBlock(coinbaseTo, Block.fakeClock);
            assertTrue(chain.add(newBlock));
            prev = newBlock;
            // The fake chain should seem to be "fast" for the purposes of difficulty calculations.
            Block.fakeClock += 2;
        }
        // Now add another block that has no difficulty adjustment, it should be rejected.
        try {
            chain.add(prev.createNextBlock(coinbaseTo));
            fail();
        } catch (VerificationException e) {
        }
        // Create a new block with the right difficulty target given our blistering speed relative to the huge amount
        // of time it's supposed to take (set in the unit test network parameters).
        Block b = prev.createNextBlock(coinbaseTo, Block.fakeClock);
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
        NetworkParameters params2 = NetworkParameters.testNet();
        Block bad = new Block(params2);
        // Merkle root can be anything here, doesn't matter.
        bad.setMerkleRoot(new Sha256Hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
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
            assertTrue(e.getMessage(), e.getMessage().indexOf("Difficulty target is bad") >= 0);
        }

        // Accept any level of difficulty now.
        params2.proofOfWorkLimit = new BigInteger
                ("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
        try {
            testNetChain.add(bad);
            // We should not get here as the difficulty target should not be changing at this point.
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage(), e.getMessage().indexOf("Unexpected change in difficulty") >= 0);
        }

        // TODO: Test difficulty change is not out of range when a transition period becomes valid.
    }

    @Test
    public void duplicates() throws Exception {
        // Adding a block twice should not have any effect, in particular it should not send the block to the wallet.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinbaseTo);
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
        Address somebodyElse = new ECKey().toAddress(unitTestParams);
        Block b1 = unitTestParams.genesisBlock.createNextBlock(somebodyElse);
        ECKey key = new ECKey();
        wallet.addKey(key);
        Address addr = key.toAddress(unitTestParams);
        // Create a tx that gives us some coins, and another that spends it to someone else in the same block.
        Transaction t1 = TestUtils.createFakeTx(unitTestParams, Utils.toNanoCoins(1, 0), addr);
        Transaction t2 = new Transaction(unitTestParams);
        t2.addInput(t1.getOutputs().get(0));
        t2.addOutput(Utils.toNanoCoins(2, 0), somebodyElse);
        b1.addTransaction(t1);
        b1.addTransaction(t2);
        b1.solve();
        chain.add(b1);
        assertEquals(BigInteger.ZERO, wallet.getBalance());
    }

    // Some blocks from the test net.
    private Block getBlock2() throws Exception {
        Block b2 = new Block(testNet);
        b2.setMerkleRoot(new Sha256Hash("addc858a17e21e68350f968ccd384d6439b64aafa6c193c8b9dd66320470838b"));
        b2.setNonce(2642058077L);
        b2.setTime(1296734343L);
        b2.setPrevBlockHash(new Sha256Hash("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604"));
        assertEquals("000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f", b2.getHashAsString());
        b2.verifyHeader();
        return b2;
    }

    private Block getBlock1() throws Exception {
        Block b1 = new Block(testNet);
        b1.setMerkleRoot(new Sha256Hash("0e8e58ecdacaa7b3c6304a35ae4ffff964816d2b80b62b58558866ce4e648c10"));
        b1.setNonce(236038445);
        b1.setTime(1296734340);
        b1.setPrevBlockHash(new Sha256Hash("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"));
        assertEquals("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604", b1.getHashAsString());
        b1.verifyHeader();
        return b1;
    }
}
