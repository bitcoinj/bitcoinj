/*
 * Copyright 2012 Google Inc.
 * Copyright 2012 Matt Corallo.
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
import com.google.bitcoin.store.FullPrunedBlockStore;
import com.google.bitcoin.store.MemoryFullPrunedBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.List;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * We don't do any wallet tests here, we leave that to {@link ChainSplitTest}
 */

public class FullPrunedBlockChainTest {
    private static final Logger log = LoggerFactory.getLogger(FullPrunedBlockChainTest.class);

    // The number of undoable blocks to keep around
    private static final int UNDOABLE_BLOCKS_STORED = 10;
    
    private NetworkParameters unitTestParams;
    private FullPrunedBlockChain chain;
    private FullPrunedBlockStore store;

    private int oldInterval;

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.init();
        unitTestParams = NetworkParameters.unitTests();
        oldInterval = unitTestParams.interval;
        unitTestParams.interval = 10000;
        
        store = new MemoryFullPrunedBlockStore(unitTestParams, UNDOABLE_BLOCKS_STORED);
        chain = new FullPrunedBlockChain(unitTestParams, store);
    }

    @After
    public void tearDown() {
        unitTestParams.interval = oldInterval;
    }
    
    @Test
    public void testGeneratedChain() throws Exception {
        // Tests various test cases from FullBlockTestGenerator
        FullBlockTestGenerator generator = new FullBlockTestGenerator(unitTestParams);
        List<BlockAndValidity> blockList = generator.getBlocksToTest(false);
        for (BlockAndValidity block : blockList) {
            boolean threw = false;
            try {
                if (chain.add(block.block) != block.connects) {
                    log.error("Block didn't match connects flag on block " + block.blockName);
                    fail();
                }
            } catch (VerificationException e) {
                threw = true;
                if (!block.throwsException) {
                    log.error("Block didn't match throws flag on block " + block.blockName);
                    fail();
                }
                if (block.connects) {
                    log.error("Block didn't match connects flag on block " + block.blockName);
                    fail();
                }
            }
            if (!threw && block.throwsException) {
                log.error("Block didn't match throws flag on block " + block.blockName);
                fail();
            }
            if (!chain.getChainHead().getHeader().getHash().equals(block.hashChainTipAfterBlock)) {
                log.error("New block head didn't match the correct value after block " + block.blockName);
                fail();
            }
        }
    }
    
    @Test
    public void testFinalizedBlocks() throws Exception {
        // Check that we aren't accidentally leaving any references
        // to the full StoredUndoableBlock's lying around (ie memory leaks)
        
        ECKey outKey = new ECKey();
        
        // Build some blocks on genesis block to create a spendable output
        Block rollingBlock = unitTestParams.genesisBlock.createNextBlockWithCoinbase(outKey.getPubKey());
        chain.add(rollingBlock);
        TransactionOutPoint spendableOutput = new TransactionOutPoint(unitTestParams, 0, rollingBlock.getTransactions().get(0).getHash());
        byte[] spendableOutputScriptPubKey = rollingBlock.getTransactions().get(0).getOutputs().get(0).getScriptBytes();
        for (int i = 1; i < unitTestParams.getSpendableCoinbaseDepth(); i++) {
            rollingBlock = rollingBlock.createNextBlockWithCoinbase(outKey.getPubKey());
            chain.add(rollingBlock);
        }
        
        WeakReference<StoredTransactionOutput> out = new WeakReference<StoredTransactionOutput>
                                       (store.getTransactionOutput(spendableOutput.getHash(), spendableOutput.getIndex()));
        rollingBlock = rollingBlock.createNextBlock(null);
        
        Transaction t = new Transaction(unitTestParams);
        // Entirely invalid scriptPubKey
        t.addOutput(new TransactionOutput(unitTestParams, t, Utils.toNanoCoins(50, 0), new byte[] {}));
        addInputToTransaction(t, spendableOutput, spendableOutputScriptPubKey, outKey);
        rollingBlock.addTransaction(t);
        rollingBlock.solve();
        
        chain.add(rollingBlock);
        WeakReference<StoredUndoableBlock> undoBlock = new WeakReference<StoredUndoableBlock>(store.getUndoBlock(rollingBlock.getHash()));

        StoredUndoableBlock storedUndoableBlock = undoBlock.get();
        assertTrue(storedUndoableBlock != null);
        assertTrue(storedUndoableBlock.getTransactions() == null);
        WeakReference<TransactionOutputChanges> changes = new WeakReference<TransactionOutputChanges>(storedUndoableBlock.getTxOutChanges());
        assertTrue(changes.get() != null);
        storedUndoableBlock = null;   // Blank the reference so it can be GCd.
        
        // Create a chain longer than UNDOABLE_BLOCKS_STORED
        for (int i = 0; i < UNDOABLE_BLOCKS_STORED; i++) {
            rollingBlock = rollingBlock.createNextBlock(null);
            chain.add(rollingBlock);
        }
        // Try to get the garbage collector to run
        System.gc();
        assertTrue(undoBlock.get() == null);
        assertTrue(changes.get() == null);
        assertTrue(out.get() == null);
    }
    
    private void addInputToTransaction(Transaction t, TransactionOutPoint prevOut, byte[] prevOutScriptPubKey, ECKey sigKey) throws ScriptException {
        TransactionInput input = new TransactionInput(unitTestParams, t, new byte[]{}, prevOut);
        t.addInput(input);

        Sha256Hash hash = t.hashTransactionForSignature(0, prevOutScriptPubKey, SigHash.ALL, false);

        // Sign input
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(73);
            bos.write(sigKey.sign(hash).encodeToDER());
            bos.write(SigHash.ALL.ordinal() + 1);
            byte[] signature = bos.toByteArray();
            
            input.setScriptBytes(Script.createInputScript(signature));
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }
}
