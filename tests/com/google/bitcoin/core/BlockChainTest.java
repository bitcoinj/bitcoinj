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

import com.google.bitcoin.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

// Tests still to write:
//   - Fragmented chains can be joined together.
//   - Longest testNetChain is selected based on total difficulty not length.
//   - Many more ...
public class BlockChainTest {
    private static final NetworkParameters testNet = NetworkParameters.testNet();
    private BlockChain testNetChain;

    private Wallet wallet;
    private BlockChain chain;
    private Address coinbaseTo;
    private NetworkParameters unitTestParams;
    private Address someOtherGuy;

    @Before
    public void setUp() {
        testNetChain = new BlockChain(testNet, new Wallet(testNet), new MemoryBlockStore(testNet));

        unitTestParams = NetworkParameters.unitTests();
        wallet = new Wallet(unitTestParams);
        wallet.addKey(new ECKey());
        chain = new BlockChain(unitTestParams, wallet, new MemoryBlockStore(unitTestParams));

        coinbaseTo = wallet.keychain.get(0).toAddress(unitTestParams);
        someOtherGuy = new ECKey().toAddress(unitTestParams);
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
    public void testUnconnectedBlocks() throws Exception {
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
    public void testForking1() throws Exception {
        // Check that if the block chain forks, we end up using the right chain. Only tests inbound transactions
        // (receiving coins). Checking that we understand reversed spends is in testForking2.

        // TODO: Change this test to not use coinbase transactions as they are special (maturity rules).
        final boolean[] reorgHappened = new boolean[1];
        reorgHappened[0] = false;
        wallet.addEventListener(new WalletEventListener() {
            @Override
            public void onReorganize() {
                reorgHappened[0] = true;
            }
        });

        // Start by building a couple of blocks on top of the genesis block.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinbaseTo);
        Block b2 = b1.createNextBlock(coinbaseTo);
        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));
        assertFalse(reorgHappened[0]);
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
        assertEquals("100.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // Now we add another block to make the alternative chain longer.
        assertTrue(chain.add(b3.createNextBlock(someOtherGuy)));
        assertTrue(reorgHappened[0]);  // Re-org took place.
        reorgHappened[0] = false;
        //
        //     genesis -> b1 -> b2
        //                  \-> b3 -> b4
        //
        // We lost some coins! b2 is no longer a part of the best chain so our balance should drop to 50 again.
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // ... and back to the first chain.
        Block b5 = b2.createNextBlock(coinbaseTo);
        Block b6 = b5.createNextBlock(coinbaseTo);
        assertTrue(chain.add(b5));
        assertTrue(chain.add(b6));
        //
        //     genesis -> b1 -> b2 -> b5 -> b6
        //                  \-> b3 -> b4
        //
        assertTrue(reorgHappened[0]);
        assertEquals("200.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
    }

    @Test
    public void testForking2() throws Exception {
        // Check that if the chain forks and new coins are received in the alternate chain our balance goes up.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(someOtherGuy);
        Block b2 = b1.createNextBlock(someOtherGuy);
        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));
        //     genesis -> b1 -> b2
        //                  \-> b3 -> b4
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        Block b3 = b1.createNextBlock(coinbaseTo);
        Block b4 = b3.createNextBlock(someOtherGuy);
        assertTrue(chain.add(b3));
        assertTrue(chain.add(b4));
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
    }

    @Test
    public void testForking3() throws Exception {
        // Check that we can handle our own spends being rolled back by a fork.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinbaseTo);
        chain.add(b1);
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        Address dest = new ECKey().toAddress(unitTestParams);
        Transaction spend = wallet.createSend(dest, Utils.toNanoCoins(10, 0));
        wallet.confirmSend(spend);
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
        // b4 causes a re-org that should make our spend go inactive. Because the inputs are already spent our balance
        // drops to zero again.
        assertEquals(BigInteger.ZERO, wallet.getBalance());
        // Not pending .... we don't know if our spend will EVER become active again (if there's an attack it may not).
        assertEquals(0, wallet.getPendingTransactions().size());
    }

    @Test
    public void testForking4() throws Exception {
        // Check that we can handle external spends on an inactive chain becoming active. An external spend is where
        // we see a transaction that spends our own coins but we did not broadcast it ourselves. This happens when
        // keys are being shared between wallets.
        Block b1 = unitTestParams.genesisBlock.createNextBlock(coinbaseTo);
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
    public void testDifficultyTransitions() throws Exception {
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
    public void testBadDifficulty() throws Exception {
        assertTrue(testNetChain.add(getBlock1()));
        Block b2 = getBlock2();
        assertTrue(testNetChain.add(b2));
        NetworkParameters params2 = NetworkParameters.testNet();
        Block bad = new Block(params2);
        // Merkle root can be anything here, doesn't matter.
        bad.setMerkleRoot(Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
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

    // Some blocks from the test net.
    private Block getBlock2() throws Exception {
        Block b2 = new Block(testNet);
        b2.setMerkleRoot(Hex.decode("addc858a17e21e68350f968ccd384d6439b64aafa6c193c8b9dd66320470838b"));
        b2.setNonce(2642058077L);
        b2.setTime(1296734343L);
        b2.setPrevBlockHash(Hex.decode("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604"));
        assertEquals("000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f", b2.getHashAsString());
        b2.verify();
        return b2;
    }

    private Block getBlock1() throws Exception {
        Block b1 = new Block(testNet);
        b1.setMerkleRoot(Hex.decode("0e8e58ecdacaa7b3c6304a35ae4ffff964816d2b80b62b58558866ce4e648c10"));
        b1.setNonce(236038445);
        b1.setTime(1296734340);
        b1.setPrevBlockHash(Hex.decode("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"));
        assertEquals("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604", b1.getHashAsString());
        b1.verify();
        return b1;
    }
}
