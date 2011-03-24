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
//   - Rest of checkDifficultyTransitions: verify we don't accept invalid transitions.
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

    @Before
    public void setUp() {
        testNetChain = new BlockChain(testNet, new Wallet(testNet));

        unitTestParams = NetworkParameters.unitTests();
        wallet = new Wallet(unitTestParams);
        wallet.addKey(new ECKey());
        coinbaseTo = wallet.keychain.get(0).toAddress(unitTestParams);
        chain = new BlockChain(unitTestParams, wallet);
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

    private Block createNextBlock(Address to, Block prev) throws VerificationException {
        return createNextBlock(to, prev, Block.EASIEST_DIFFICULTY_TARGET, System.currentTimeMillis() / 1000);
    }

    private Block createNextBlock(Address to, Block prev, long difficultyTarget,
                                  long time) throws VerificationException {
        Block b = new Block(prev.params);
        b.setDifficultyTarget(difficultyTarget);
        b.addCoinbaseTransaction(to);
        b.setPrevBlockHash(prev.getHash());
        b.setTime(time);
        b.solve();
        b.verify();
        return b;
    }

    @Test
    public void testUnconnectedBlocks() throws Exception {
        Block b1 = createNextBlock(coinbaseTo, unitTestParams.genesisBlock);
        Block b2 = createNextBlock(coinbaseTo, b1);
        Block b3 = createNextBlock(coinbaseTo, b2);
        // Connected.
        assertTrue(chain.add(b1));
        // Unconnected.
        assertFalse(chain.add(b3));
    }

    @Test
    public void testForking() throws Exception {
        // Check that if the block chain forks, we end up using the right one.
        // Start by building a couple of blocks on top of the genesis block.
        final boolean[] flags = new boolean[1];
        flags[0] = false;
        wallet.addEventListener(new WalletEventListener() {
            @Override
            public void onReorganize() {
                flags[0] = true;
            }
        });

        Block b1 = createNextBlock(coinbaseTo, unitTestParams.genesisBlock);
        Block b2 = createNextBlock(coinbaseTo, b1);
        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));
        assertFalse(flags[0]);
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
        Address someOtherGuy = new ECKey().toAddress(unitTestParams);
        Block b3 = createNextBlock(someOtherGuy, b1);
        assertTrue(chain.add(b3));
        assertFalse(flags[0]);  // No re-org took place.
        assertEquals("100.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // Now we add another block to make the alternative chain longer.
        assertTrue(chain.add(createNextBlock(someOtherGuy, b3)));
        assertTrue(flags[0]);  // Re-org took place.
        flags[0] = false;
        //
        //     genesis -> b1 -> b2
        //                  \-> b3 -> b4
        //
        // We lost some coins! b2 is no longer a part of the best chain so our balance should drop to 50 again.
        if (false) {
            // These tests do not pass currently, as wallet handling of re-orgs isn't implemented.
            assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
            // ... and back to the first testNetChain
            Block b5 = createNextBlock(coinbaseTo, b2);
            Block b6 = createNextBlock(coinbaseTo, b5);
            assertTrue(chain.add(b5));
            assertTrue(chain.add(b6));
            //
            //     genesis -> b1 -> b2 -> b5 -> b6
            //                  \-> b3 -> b4
            //
            assertEquals("200.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        }
    }

    @Test
    public void testDifficultyTransitions() throws Exception {
        // Add a bunch of blocks in a loop until we reach a difficulty transition point. The unit test params have an
        // artificially shortened period.
        Block prev = unitTestParams.genesisBlock;
        Block.fakeClock = System.currentTimeMillis() / 1000;
        for (int i = 0; i < unitTestParams.interval - 1; i++) {
            Block newBlock = createNextBlock(coinbaseTo, prev, Block.EASIEST_DIFFICULTY_TARGET, Block.fakeClock);
            assertTrue(chain.add(newBlock));
            prev = newBlock;
            // The fake chain should seem to be "fast" for the purposes of difficulty calculations.
            Block.fakeClock += 2;
        }
        // Now add another block that has no difficulty adjustment, it should be rejected.
        try {
            chain.add(createNextBlock(coinbaseTo, prev));
            fail();
        } catch (VerificationException e) {
        }
        // Create a new block with the right difficulty target given our blistering speed relative to the huge amount
        // of time it's supposed to take (set in the unit test network parameters).
        Block b = createNextBlock(coinbaseTo, prev, 0x201fFFFFL, Block.fakeClock);
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
