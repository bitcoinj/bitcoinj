/*
 * Copyright 2012 Google Inc.
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

import com.google.bitcoin.store.FullPrunedBlockStore;
import com.google.bitcoin.store.MemoryFullPrunedBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import org.junit.Before;
import org.junit.Test;

import java.lang.ref.WeakReference;

import static org.junit.Assert.*;

/**
 * We don't do any wallet tests here, we leave that to {@link ChainSplitTest}
 */

public class FullPrunedBlockChainTest {
    // The size of spendableOutputs
    private static final int MAX_BLOCK_HEIGHT = 5;
    
    private NetworkParameters unitTestParams;
    private Wallet wallet;
    private Address walletAddress;
    private FullPrunedBlockChain chain;
    private FullPrunedBlockStore store;
    private ECKey someOtherGuyKey;
    private Block testBase;
    private TransactionOutPoint[] spendableOutputs;

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.init();
        unitTestParams = NetworkParameters.unitTests();
        unitTestParams.interval = 10000;
        
        wallet = new Wallet(unitTestParams);
        wallet.addKey(new ECKey());
        walletAddress = wallet.keychain.get(0).toAddress(unitTestParams);
        
        store = new MemoryFullPrunedBlockStore(unitTestParams, MAX_BLOCK_HEIGHT);
        chain = new FullPrunedBlockChain(unitTestParams, wallet, store);
        
        someOtherGuyKey = new ECKey();
        byte[] someOtherGuyPubKey = someOtherGuyKey.getPubKey();
        
        spendableOutputs = new TransactionOutPoint[unitTestParams.getSpendableCoinbaseDepth() + MAX_BLOCK_HEIGHT];
        // Build some blocks on genesis block for later spending
        // Be lazy to give a simple list of inputs for use, though we could use inputs generated during tests
        testBase = unitTestParams.genesisBlock.createNextBlockWithCoinbase(someOtherGuyPubKey);
        chain.add(testBase);
        spendableOutputs[0] = new TransactionOutPoint(unitTestParams, 0, testBase.getTransactions().get(0).getHash());
        for (int i = 1; i < unitTestParams.getSpendableCoinbaseDepth() + MAX_BLOCK_HEIGHT; i++) {
            testBase = testBase.createNextBlockWithCoinbase(someOtherGuyPubKey);
            chain.add(testBase);
            spendableOutputs[i] = new TransactionOutPoint(unitTestParams, 0, testBase.getTransactions().get(0).getHash().duplicate());
        }
    }
    
    @Test
    public void testForkSpends() throws Exception {
        // Check that if the block chain forks, we end up using the right chain.
        // And check that transactions that get spent on one fork or another

        // In order for this to be triggered, the reorg has to effect us,
        // so use walletAddress when creating new blocks as much as possible
        final boolean[] reorgHappened = new boolean[1];
        reorgHappened[0] = false;
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onReorganize(Wallet wallet) {
                reorgHappened[0] = true;
            }
        });
        
        // Start by building a couple of blocks on top of the testBase block.
        Block b1 = testBase.createNextBlock(walletAddress, spendableOutputs[0]);
        Block b2 = b1.createNextBlock(walletAddress, spendableOutputs[1]);
        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));
        assertFalse(reorgHappened[0]);
        // We now have the following chain (which output is spent is in parentheses):
        //     testBase -> b1 (0) -> b2 (1)
        //
        // so fork like this:
        //
        //     testBase -> b1 (0) -> b2 (1)
        //                       \-> b3 (1)
        //
        // Nothing should happen at this point. We saw b2 first so it takes priority.
        Block b3 = b1.createNextBlock(walletAddress, spendableOutputs[1]);
        assertTrue(chain.add(b3));
        assertFalse(reorgHappened[0]);  // No re-org took place.
        // Now we add another block to make the alternative chain longer.
        Block b4 = b3.createNextBlock(walletAddress, spendableOutputs[2]);
        assertTrue(chain.add(b4));
        assertTrue(reorgHappened[0]);  // Re-org took place.
        reorgHappened[0] = false;
        //
        //     testBase -> b1 (0) -> b2 (1)
        //                       \-> b3 (1) -> b4 (2)
        //
        // ... and back to the first chain.
        Block b5 = b2.createNextBlock(walletAddress, spendableOutputs[2]);
        Block b6 = b5.createNextBlock(walletAddress, spendableOutputs[3]);
        assertTrue(chain.add(b5));
        assertTrue(chain.add(b6));
        //
        //     testBase -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        //                       \-> b3 (1) -> b4 (2)
        //
        assertTrue(reorgHappened[0]);
        reorgHappened[0] = false;
        // Try to create a fork that double-spends
        //     testBase -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        //                       \-> b3 (1) -> b4 (2)
        //                                           \-> b7 (2) -> b8 (4)
        //
        Block b7 = b4.createNextBlock(new ECKey().toAddress(unitTestParams), spendableOutputs[2]);
        Block b8 = b7.createNextBlock(walletAddress, spendableOutputs[4]);
        try{
            chain.add(b7); // This is allowed to fail as there is no guarantee that a fork's inputs will be verified
            chain.add(b8);
            fail();
        } catch(VerificationException e) {
            // b7 should fail verification because it double-spends output 2.
        } catch (Exception e) {
            throw new RuntimeException(e);  // Should not happen.
        }
        assertFalse(reorgHappened[0]);
    }
    
    @Test
    public void testFinalizedBlocks() throws Exception {
        // Check that we aren't accidentally leaving any references
        // to the full StoredUndoableBlock's lying around (ie memory leaks)
        
        WeakReference<StoredTransactionOutput> out =
                new WeakReference<StoredTransactionOutput>(store.getTransactionOutput(spendableOutputs[0].getHash(), spendableOutputs[1].getIndex()));
        // Create a chain longer than MAX_BLOCK_HEIGHT
        Block block1 = testBase.createNextBlock(walletAddress, spendableOutputs[0]);
        chain.add(block1);
        WeakReference<StoredUndoableBlock> undoBlock = new WeakReference<StoredUndoableBlock>(store.getUndoBlock(block1.getHash()));
        assertTrue(undoBlock.get() != null);
        assertTrue(undoBlock.get().getTransactions() == null);
        WeakReference<TransactionOutputChanges> changes = new WeakReference<TransactionOutputChanges>(undoBlock.get().getTxOutChanges());
        assertTrue(changes.get() != null);
        Block rollingBlock = block1;
        for (int i = 0; i < MAX_BLOCK_HEIGHT; i++) {
            rollingBlock = rollingBlock.createNextBlock(null);
            chain.add(rollingBlock);
        }
        // Try to get the garbage collector to run
        System.gc();
        assertTrue(undoBlock.get() == null);
        assertTrue(changes.get() == null);
        assertTrue(out.get() == null);
    }
}
