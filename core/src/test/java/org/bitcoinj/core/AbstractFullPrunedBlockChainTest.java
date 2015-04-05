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

package org.bitcoinj.core;

import com.google.common.collect.Lists;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.FullPrunedBlockStore;
import org.bitcoinj.utils.BlockFileLoader;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.WalletTransaction;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.core.Coin.FIFTY_COINS;
import static org.junit.Assert.*;

/**
 * We don't do any wallet tests here, we leave that to {@link ChainSplitTest}
 */

public abstract class AbstractFullPrunedBlockChainTest {
    private static final Logger log = LoggerFactory.getLogger(AbstractFullPrunedBlockChainTest.class);

    protected NetworkParameters params;
    protected FullPrunedBlockChain chain;
    protected FullPrunedBlockStore store;
    protected Context context;

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.init();
        params = new UnitTestParams() {
            @Override public int getInterval() {
                return 10000;
            }
        };
        context = new Context(params);
    }

    public abstract FullPrunedBlockStore createStore(NetworkParameters params, int blockCount)
        throws BlockStoreException;

    public abstract void resetStore(FullPrunedBlockStore store) throws BlockStoreException;

    @Test
    public void testGeneratedChain() throws Exception {
        // Tests various test cases from FullBlockTestGenerator
        FullBlockTestGenerator generator = new FullBlockTestGenerator(params);
        RuleList blockList = generator.getBlocksToTest(false, false, null);
        
        store = createStore(params, blockList.maximumReorgBlockCount);
        chain = new FullPrunedBlockChain(params, store);

        for (Rule rule : blockList.list) {
            if (!(rule instanceof FullBlockTestGenerator.BlockAndValidity))
                continue;
            FullBlockTestGenerator.BlockAndValidity block = (FullBlockTestGenerator.BlockAndValidity) rule;
            log.info("Testing rule " + block.ruleName + " with block hash " + block.block.getHash());
            boolean threw = false;
            try {
                if (chain.add(block.block) != block.connects) {
                    log.error("Block didn't match connects flag on block " + block.ruleName);
                    fail();
                }
            } catch (VerificationException e) {
                threw = true;
                if (!block.throwsException) {
                    log.error("Block didn't match throws flag on block " + block.ruleName);
                    throw e;
                }
                if (block.connects) {
                    log.error("Block didn't match connects flag on block " + block.ruleName);
                    fail();
                }
            }
            if (!threw && block.throwsException) {
                log.error("Block didn't match throws flag on block " + block.ruleName);
                fail();
            }
            if (!chain.getChainHead().getHeader().getHash().equals(block.hashChainTipAfterBlock)) {
                log.error("New block head didn't match the correct value after block " + block.ruleName);
                fail();
            }
            if (chain.getChainHead().getHeight() != block.heightAfterBlock) {
                log.error("New block head didn't match the correct height after block " + block.ruleName);
                fail();
            }
        }
        try {
            store.close();
        } catch (Exception e) {}
    }

    @Test
    public void skipScripts() throws Exception {
        store = createStore(params, 10);
        chain = new FullPrunedBlockChain(params, store);

        // Check that we aren't accidentally leaving any references
        // to the full StoredUndoableBlock's lying around (ie memory leaks)

        ECKey outKey = new ECKey();

        // Build some blocks on genesis block to create a spendable output
        Block rollingBlock = params.getGenesisBlock().createNextBlockWithCoinbase(outKey.getPubKey());
        chain.add(rollingBlock);
        TransactionOutput spendableOutput = rollingBlock.getTransactions().get(0).getOutput(0);
        for (int i = 1; i < params.getSpendableCoinbaseDepth(); i++) {
            rollingBlock = rollingBlock.createNextBlockWithCoinbase(outKey.getPubKey());
            chain.add(rollingBlock);
        }

        rollingBlock = rollingBlock.createNextBlock(null);
        Transaction t = new Transaction(params);
        t.addOutput(new TransactionOutput(params, t, FIFTY_COINS, new byte[] {}));
        TransactionInput input = t.addInput(spendableOutput);
        // Invalid script.
        input.setScriptBytes(new byte[]{});
        rollingBlock.addTransaction(t);
        rollingBlock.solve();
        chain.setRunScripts(false);
        try {
            chain.add(rollingBlock);
        } catch (VerificationException e) {
            fail();
        }
        try {
            store.close();
        } catch (Exception e) {}
    }

    @Test
    public void testFinalizedBlocks() throws Exception {
        final int UNDOABLE_BLOCKS_STORED = 10;
        store = createStore(params, UNDOABLE_BLOCKS_STORED);
        chain = new FullPrunedBlockChain(params, store);
        
        // Check that we aren't accidentally leaving any references
        // to the full StoredUndoableBlock's lying around (ie memory leaks)
        
        ECKey outKey = new ECKey();
        
        // Build some blocks on genesis block to create a spendable output
        Block rollingBlock = params.getGenesisBlock().createNextBlockWithCoinbase(outKey.getPubKey());
        chain.add(rollingBlock);
        TransactionOutPoint spendableOutput = new TransactionOutPoint(params, 0, rollingBlock.getTransactions().get(0).getHash());
        byte[] spendableOutputScriptPubKey = rollingBlock.getTransactions().get(0).getOutputs().get(0).getScriptBytes();
        for (int i = 1; i < params.getSpendableCoinbaseDepth(); i++) {
            rollingBlock = rollingBlock.createNextBlockWithCoinbase(outKey.getPubKey());
            chain.add(rollingBlock);
        }
        
        WeakReference<UTXO> out = new WeakReference<UTXO>
                                       (store.getTransactionOutput(spendableOutput.getHash(), spendableOutput.getIndex()));
        rollingBlock = rollingBlock.createNextBlock(null);
        
        Transaction t = new Transaction(params);
        // Entirely invalid scriptPubKey
        t.addOutput(new TransactionOutput(params, t, FIFTY_COINS, new byte[]{}));
        t.addSignedInput(spendableOutput, new Script(spendableOutputScriptPubKey), outKey);
        rollingBlock.addTransaction(t);
        rollingBlock.solve();
        
        chain.add(rollingBlock);
        WeakReference<StoredUndoableBlock> undoBlock = new WeakReference<StoredUndoableBlock>(store.getUndoBlock(rollingBlock.getHash()));

        StoredUndoableBlock storedUndoableBlock = undoBlock.get();
        assertNotNull(storedUndoableBlock);
        assertNull(storedUndoableBlock.getTransactions());
        WeakReference<TransactionOutputChanges> changes = new WeakReference<TransactionOutputChanges>(storedUndoableBlock.getTxOutChanges());
        assertNotNull(changes.get());
        storedUndoableBlock = null;   // Blank the reference so it can be GCd.
        
        // Create a chain longer than UNDOABLE_BLOCKS_STORED
        for (int i = 0; i < UNDOABLE_BLOCKS_STORED; i++) {
            rollingBlock = rollingBlock.createNextBlock(null);
            chain.add(rollingBlock);
        }
        // Try to get the garbage collector to run
        System.gc();
        assertNull(undoBlock.get());
        assertNull(changes.get());
        assertNull(out.get());
        try {
            store.close();
        } catch (Exception e) {}
    }
    
    @Test
    public void testFirst100KBlocks() throws Exception {
        NetworkParameters params = MainNetParams.get();
        Context context = new Context(params);
        File blockFile = new File(getClass().getResource("first-100k-blocks.dat").getFile());
        BlockFileLoader loader = new BlockFileLoader(params, Arrays.asList(blockFile));
        
        store = createStore(params, 10);
        resetStore(store);
        chain = new FullPrunedBlockChain(context, store);
        for (Block block : loader)
            chain.add(block);
        try {
            store.close();
        } catch (Exception e) {}
    }

    @Test
    public void testGetOpenTransactionOutputs() throws Exception {
        final int UNDOABLE_BLOCKS_STORED = 10;
        store = createStore(params, UNDOABLE_BLOCKS_STORED);
        chain = new FullPrunedBlockChain(params, store);

        // Check that we aren't accidentally leaving any references
        // to the full StoredUndoableBlock's lying around (ie memory leaks)
        ECKey outKey = new ECKey();

        // Build some blocks on genesis block to create a spendable output
        Block rollingBlock = params.getGenesisBlock().createNextBlockWithCoinbase(outKey.getPubKey());
        chain.add(rollingBlock);
        Transaction transaction = rollingBlock.getTransactions().get(0);
        TransactionOutPoint spendableOutput = new TransactionOutPoint(params, 0, transaction.getHash());
        byte[] spendableOutputScriptPubKey = transaction.getOutputs().get(0).getScriptBytes();
        for (int i = 1; i < params.getSpendableCoinbaseDepth(); i++) {
            rollingBlock = rollingBlock.createNextBlockWithCoinbase(outKey.getPubKey());
            chain.add(rollingBlock);
        }
        rollingBlock = rollingBlock.createNextBlock(null);

        // Create bitcoin spend of 1 BTC.
        ECKey toKey = new ECKey();
        Coin amount = Coin.valueOf(100000000);
        Address address = new Address(params, toKey.getPubKeyHash());
        Coin totalAmount = Coin.ZERO;

        Transaction t = new Transaction(params);
        t.addOutput(new TransactionOutput(params, t, amount, toKey));
        t.addSignedInput(spendableOutput, new Script(spendableOutputScriptPubKey), outKey);
        rollingBlock.addTransaction(t);
        rollingBlock.solve();
        chain.add(rollingBlock);
        totalAmount = totalAmount.add(amount);

        List<UTXO> outputs = store.getOpenTransactionOutputs(Lists.newArrayList(address));
        assertNotNull(outputs);
        assertEquals("Wrong Number of Outputs", 1, outputs.size());
        UTXO output = outputs.get(0);
        assertEquals("The address is not equal", address.toString(), output.getAddress());
        assertEquals("The amount is not equal", totalAmount, output.getValue());

        outputs = null;
        output = null;
        try {
            store.close();
        } catch (Exception e) {}
    }

    @Test
    public void testUTXOProviderWithWallet() throws Exception {
        final int UNDOABLE_BLOCKS_STORED = 10;
        store = createStore(params, UNDOABLE_BLOCKS_STORED);
        chain = new FullPrunedBlockChain(params, store);

        // Check that we aren't accidentally leaving any references
        // to the full StoredUndoableBlock's lying around (ie memory leaks)
        ECKey outKey = new ECKey();

        // Build some blocks on genesis block to create a spendable output.
        Block rollingBlock = params.getGenesisBlock().createNextBlockWithCoinbase(outKey.getPubKey());
        chain.add(rollingBlock);
        Transaction transaction = rollingBlock.getTransactions().get(0);
        TransactionOutPoint spendableOutput = new TransactionOutPoint(params, 0, transaction.getHash());
        byte[] spendableOutputScriptPubKey = transaction.getOutputs().get(0).getScriptBytes();
        for (int i = 1; i < params.getSpendableCoinbaseDepth(); i++) {
            rollingBlock = rollingBlock.createNextBlockWithCoinbase(outKey.getPubKey());
            chain.add(rollingBlock);
        }
        rollingBlock = rollingBlock.createNextBlock(null);

        // Create 1 BTC spend to a key in this wallet (to ourselves).
        Wallet wallet = new Wallet(params);
        assertEquals("Available balance is incorrect", Coin.ZERO, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        assertEquals("Estimated balance is incorrect", Coin.ZERO, wallet.getBalance(Wallet.BalanceType.ESTIMATED));

        wallet.setUTXOProvider(store);
        ECKey toKey = wallet.freshReceiveKey();
        Coin amount = Coin.valueOf(100000000);

        Transaction t = new Transaction(params);
        t.addOutput(new TransactionOutput(params, t, amount, toKey));
        t.addSignedInput(spendableOutput, new Script(spendableOutputScriptPubKey), outKey);
        rollingBlock.addTransaction(t);
        rollingBlock.solve();
        chain.add(rollingBlock);

        // Create another spend of 1/2 the value of BTC we have available using the wallet (store coin selector).
        ECKey toKey2 = new ECKey();
        Coin amount2 = amount.divide(2);
        Address address2 = new Address(params, toKey2.getPubKeyHash());
        Wallet.SendRequest req = Wallet.SendRequest.to(address2, amount2);
        wallet.completeTx(req);
        wallet.commitTx(req.tx);
        Coin fee = req.fee;

        // There should be one pending tx (our spend).
        assertEquals("Wrong number of PENDING.4", 1, wallet.getPoolSize(WalletTransaction.Pool.PENDING));
        Coin totalPendingTxAmount = Coin.ZERO;
        for (Transaction tx : wallet.getPendingTransactions()) {
            totalPendingTxAmount = totalPendingTxAmount.add(tx.getValueSentToMe(wallet));
        }

        // The availbale balance should be the 0 (as we spent the 1 BTC that's pending) and estimated should be 1/2 - fee BTC
        assertEquals("Available balance is incorrect", Coin.ZERO, wallet.getBalance(Wallet.BalanceType.AVAILABLE));
        assertEquals("Estimated balance is incorrect", amount2.subtract(fee), wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        assertEquals("Pending tx amount is incorrect", amount2.subtract(fee), totalPendingTxAmount);
        try {
            store.close();
        } catch (Exception e) {}
    }
}
