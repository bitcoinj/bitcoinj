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
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// Tests still to write:
//   - Rest of checkDifficultyTransitions: verify we don't accept invalid transitions.
//   - Fragmented chains can be joined together.
//   - Longest chain is selected based on total difficulty not length.
//   - Many more ...
public class BlockChainTest {
    private static final NetworkParameters params = NetworkParameters.testNet();
    private BlockChain chain;

    @Before
    public void setUp() {
        Wallet wallet = new Wallet(params);
        chain = new BlockChain(params, wallet);
    }

    @Test
    public void testBasicChaining() throws Exception {
        // Check that we can plug a few blocks together.
        // Block 1 from the testnet.
        Block b1 = getBlock1();
        assertTrue(chain.add(b1));
        // Block 2 from the testnet.
        Block b2 = getBlock2();

        // Let's try adding an invalid block.
        long n = b2.getNonce();
        try {
            b2.setNonce(12345);
            chain.add(b2);
            fail();
        } catch (VerificationException e) {
            b2.setNonce(n);
        }
        assertTrue(chain.add(b2));
    }

    private Block createNextBlock(Address to, Block prev) throws VerificationException {
        Block b = new Block(prev.params);
        b.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
        b.addCoinbaseTransaction(to);
        b.setPrevBlockHash(prev.getHash());
        b.solve();
        b.verify();
        return b;
    }

    @Test @Ignore
    public void testForking() throws Exception {
        // Check that if the block chain forks, we end up using the right one.
        NetworkParameters unitTestParams = NetworkParameters.unitTests();
        Wallet wallet = new Wallet(unitTestParams);
        wallet.addKey(new ECKey());
        Address coinbaseTo = wallet.keychain.get(0).toAddress(unitTestParams);
        // Start by building a couple of blocks on top of the genesis block.
        Block b1 = createNextBlock(coinbaseTo, unitTestParams.genesisBlock);
        Block b2 = createNextBlock(coinbaseTo, b1);
        chain = new BlockChain(unitTestParams, wallet);
        chain.add(b1);
        chain.add(b2);
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
        chain.add(b3);
        assertEquals("100.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // Now we add another block to make the alternative chain longer.
        chain.add(createNextBlock(someOtherGuy, b3));
        //
        //     genesis -> b1 -> b2
        //                  \-> b3 -> b4
        //
        // We lost some coins! b2 is no longer a part of the best chain so our balance should drop to 50 again.
        assertEquals("50.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        // ... and back to the first chain
        Block b5 = createNextBlock(coinbaseTo, b2);
        Block b6 = createNextBlock(coinbaseTo, b5);
        chain.add(b5);
        chain.add(b6);
        //
        //     genesis -> b1 -> b2 -> b5 -> b6
        //                  \-> b3 -> b4
        //
        assertEquals("200.00", Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
    }

    @Test
    public void testBadDifficulty() throws Exception {
        assertTrue(chain.add(getBlock1()));
        Block b2 = getBlock2();
        assertTrue(chain.add(b2));
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
            chain.add(bad);
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
            chain.add(bad);
            // We should not get here as the difficulty target should not be changing at this point.
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage(), e.getMessage().indexOf("Unexpected change in difficulty") >= 0);
        }

        // TODO: Test difficulty change is not out of range when a transition period becomes valid.
    }

    private Block getBlock2() throws Exception {
        Block b2 = new Block(params);
        b2.setMerkleRoot(Hex.decode("addc858a17e21e68350f968ccd384d6439b64aafa6c193c8b9dd66320470838b"));
        b2.setNonce(2642058077L);
        b2.setTime(1296734343L);
        b2.setPrevBlockHash(Hex.decode("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604"));
        assertEquals("000000037b21cac5d30fc6fda2581cf7b2612908aed2abbcc429c45b0557a15f", b2.getHashAsString());
        b2.verify();
        return b2;
    }

    private Block getBlock1() throws Exception {
        Block b1 = new Block(params);
        b1.setMerkleRoot(Hex.decode("0e8e58ecdacaa7b3c6304a35ae4ffff964816d2b80b62b58558866ce4e648c10"));
        b1.setNonce(236038445);
        b1.setTime(1296734340);
        b1.setPrevBlockHash(Hex.decode("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"));
        assertEquals("000000033cc282bc1fa9dcae7a533263fd7fe66490f550d80076433340831604", b1.getHashAsString());
        b1.verify();
        return b1;
    }
}
