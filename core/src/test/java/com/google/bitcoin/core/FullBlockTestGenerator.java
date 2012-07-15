package com.google.bitcoin.core;

import com.google.bitcoin.core.Transaction.SigHash;
import com.google.common.base.Preconditions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

class BlockAndValidity {
    Block block;
    boolean connects;
    boolean throwsException;
    Sha256Hash hashChainTipAfterBlock;
    String blockName;
    public BlockAndValidity(Block block, boolean connects, boolean throwsException, Sha256Hash hashChainTipAfterBlock, String blockName) {
        if (connects && throwsException)
            throw new RuntimeException("A block cannot connect if an exception was thrown while adding it.");
        this.block = block;
        this.connects = connects;
        this.throwsException = throwsException;
        this.hashChainTipAfterBlock = hashChainTipAfterBlock;
        this.blockName = blockName;
    }
}

class TransactionOutPointWithValue {
    public TransactionOutPoint outpoint;
    public BigInteger value;
    Script scriptPubKey;
    public TransactionOutPointWithValue(TransactionOutPoint outpoint, BigInteger value, Script scriptPubKey) {
        this.outpoint = outpoint;
        this.value = value;
        this.scriptPubKey = scriptPubKey;
    }
}

public class FullBlockTestGenerator {
    // Used by BitcoindComparisonTool and FullPrunedBlockChainTest to create test cases
    private NetworkParameters params;
    private ECKey coinbaseOutKey;
    private byte[] coinbaseOutKeyPubKey;
    
    public FullBlockTestGenerator(NetworkParameters params) {
        this.params = params;
        coinbaseOutKey = new ECKey();
        coinbaseOutKeyPubKey = coinbaseOutKey.getPubKey();
        Utils.rollMockClock(0); // Set a mock clock for timestamp tests
    }

    public List<BlockAndValidity> getBlocksToTest(boolean addExpensiveBlocks) throws ScriptException, ProtocolException, IOException {
        List<BlockAndValidity> blocks = new LinkedList<BlockAndValidity>();
        
        Queue<TransactionOutPointWithValue> spendableOutputs = new LinkedList<TransactionOutPointWithValue>();
        
        int chainHeadHeight = 1;
        Block chainHead = params.genesisBlock.createNextBlockWithCoinbase(coinbaseOutKeyPubKey);
        blocks.add(new BlockAndValidity(chainHead, true, false, chainHead.getHash(), "Initial Block"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, chainHead.getTransactions().get(0).getHash()),
                Utils.toNanoCoins(50, 0), chainHead.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        for (int i = 1; i < params.getSpendableCoinbaseDepth(); i++) {
            chainHead = chainHead.createNextBlockWithCoinbase(coinbaseOutKeyPubKey);
            chainHeadHeight++;
            blocks.add(new BlockAndValidity(chainHead, true, false, chainHead.getHash(), "Initial Block chain output generation"));
            spendableOutputs.offer(new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 0, chainHead.getTransactions().get(0).getHash()),
                    Utils.toNanoCoins(50, 0), chainHead.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        }
        
        // Start by building a couple of blocks on top of the genesis block.
        Block b1 = createNextBlock(chainHead, chainHeadHeight + 1, spendableOutputs.poll(), null);
        blocks.add(new BlockAndValidity(b1, true, false, b1.getHash(), "b1"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b1.getTransactions().get(0).getHash()),
                b1.getTransactions().get(0).getOutputs().get(0).getValue(),
                b1.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out1 = spendableOutputs.poll();
        Block b2 = createNextBlock(b1, chainHeadHeight + 2, out1, null);
        blocks.add(new BlockAndValidity(b2, true, false, b2.getHash(), "b2"));
        // Make sure nothing funky happens if we try to re-add b2
        blocks.add(new BlockAndValidity(b2, true, false, b2.getHash(), "b2"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b2.getTransactions().get(0).getHash()),
                b2.getTransactions().get(0).getOutputs().get(0).getValue(),
                b2.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        // We now have the following chain (which output is spent is in parentheses):
        //     genesis -> b1 (0) -> b2 (1)
        //
        // so fork like this:
        //
        //     genesis -> b1 (0) -> b2 (1)
        //                      \-> b3 (1)
        //
        // Nothing should happen at this point. We saw b2 first so it takes priority.
        Block b3 = createNextBlock(b1, chainHeadHeight + 2, out1, null);
        blocks.add(new BlockAndValidity(b3, true, false, b2.getHash(), "b3"));
        // Make sure nothing breaks if we add b3 twice
        blocks.add(new BlockAndValidity(b3, true, false, b2.getHash(), "b3"));
        // Now we add another block to make the alternative chain longer.
        TransactionOutPointWithValue out2 = spendableOutputs.poll();

        Block b4 = createNextBlock(b3, chainHeadHeight + 3, out2, null);
        blocks.add(new BlockAndValidity(b4, true, false, b4.getHash(), "b4"));
        //
        //     genesis -> b1 (0) -> b2 (1)
        //                      \-> b3 (1) -> b4 (2)
        //
        // ... and back to the first chain.
        Block b5 = createNextBlock(b2, chainHeadHeight + 3, out2, null);
        blocks.add(new BlockAndValidity(b5, true, false, b4.getHash(), "b5"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b5.getTransactions().get(0).getHash()),
                b5.getTransactions().get(0).getOutputs().get(0).getValue(),
                b5.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out3 = spendableOutputs.poll();
        
        Block b6 = createNextBlock(b5, chainHeadHeight + 4, out3, null);
        blocks.add(new BlockAndValidity(b6, true, false, b6.getHash(), "b6"));
        //
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        //                      \-> b3 (1) -> b4 (2)
        //

        // Try to create a fork that double-spends
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        //                                          \-> b7 (2) -> b8 (4)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b7 = createNextBlock(b5, chainHeadHeight + 5, out2, null);
        blocks.add(new BlockAndValidity(b7, true, false, b6.getHash(), "b7"));
        
        TransactionOutPointWithValue out4 = spendableOutputs.poll();

        Block b8 = createNextBlock(b7, chainHeadHeight + 6, out4, null);
        blocks.add(new BlockAndValidity(b8, false, true, b6.getHash(), "b8"));
        
        // Try to create a block that has too much fee
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        //                                                    \-> b9 (4)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b9 = createNextBlock(b6, chainHeadHeight + 5, out4, BigInteger.valueOf(1));
        blocks.add(new BlockAndValidity(b9, false, true, b6.getHash(), "b9"));
        
        // Create a fork that ends in a block with too much fee (the one that causes the reorg)
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b10 (3) -> b11 (4)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b10 = createNextBlock(b5, chainHeadHeight + 4, out3, null);
        blocks.add(new BlockAndValidity(b10, true, false, b6.getHash(), "b10"));
        
        Block b11 = createNextBlock(b10, chainHeadHeight + 5, out4, BigInteger.valueOf(1));
        blocks.add(new BlockAndValidity(b11, false, true, b6.getHash(), "b11"));
        
        // Try again, but with a valid fork first
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b14 (5)
        //                                              (b12 added last)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b12 = createNextBlock(b5, chainHeadHeight + 4, out3, null);
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b12.getTransactions().get(0).getHash()),
                b12.getTransactions().get(0).getOutputs().get(0).getValue(),
                b12.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        Block b13 = createNextBlock(b12, chainHeadHeight + 5, out4, null);
        blocks.add(new BlockAndValidity(b13, false, false, b6.getHash(), "b13"));
        // Make sure we dont die if an orphan gets added twice
        blocks.add(new BlockAndValidity(b13, false, false, b6.getHash(), "b13"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b13.getTransactions().get(0).getHash()),
                b13.getTransactions().get(0).getOutputs().get(0).getValue(),
                b13.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));

        TransactionOutPointWithValue out5 = spendableOutputs.poll();

        Block b14 = createNextBlock(b13, chainHeadHeight + 6, out5, BigInteger.valueOf(1));
        // This will be "validly" added, though its actually invalid, it will just be marked orphan
        // and will be discarded when an attempt is made to reorg to it.
        // TODO: Use a WeakReference to check that it is freed properly after the reorg
        blocks.add(new BlockAndValidity(b14, false, false, b6.getHash(), "b14"));
        // Make sure we dont die if an orphan gets added twice
        blocks.add(new BlockAndValidity(b14, false, false, b6.getHash(), "b14"));
        
        blocks.add(new BlockAndValidity(b12, false, true, b13.getHash(), "b12"));
        
        // Add a block with MAX_BLOCK_SIGOPS and one with one more sigop
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b16 (6)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b15 = createNextBlock(b13, chainHeadHeight + 6, out5, null);
        {
            int sigOps = 0;
            for (Transaction tx : b15.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKSIG);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b15.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b15.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b15.addTransaction(tx);
        }
        b15.solve();
        
        blocks.add(new BlockAndValidity(b15, true, false, b15.getHash(), "b15"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b15.getTransactions().get(0).getHash()),
                b15.getTransactions().get(0).getOutputs().get(0).getValue(),
                b15.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out6 = spendableOutputs.poll();
        
        Block b16 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            int sigOps = 0;
            for (Transaction tx : b16.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + 1];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKSIG);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b16.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b16.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b16.addTransaction(tx);
        }
        b16.solve();
        
        blocks.add(new BlockAndValidity(b16, false, true, b15.getHash(), "b16"));
                
        // Attempt to spend a transaction created on a different fork
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b17 (6)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b17 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), new byte[] {}));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b3.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b3.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b17.addTransaction(tx);
        }
        b17.solve();
        blocks.add(new BlockAndValidity(b17, false, true, b15.getHash(), "b17"));
        
        // Attempt to spend a transaction created on a different fork (on a fork this time)
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5)
        //                                                                \-> b18 (5) -> b19 (6)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b18 = createNextBlock(b13, chainHeadHeight + 6, out5, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), new byte[] {}));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b3.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b3.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b18.addTransaction(tx);
        }
        b18.solve();
        blocks.add(new BlockAndValidity(b18, true, false, b15.getHash(), "b17"));
        
        Block b19 = createNextBlock(b18, chainHeadHeight + 7, out6, null);
        blocks.add(new BlockAndValidity(b19, false, true, b15.getHash(), "b19"));
        
        // Attempt to spend a coinbase at depth too low
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b20 (7)
        //                      \-> b3 (1) -> b4 (2)
        //
        TransactionOutPointWithValue out7 = spendableOutputs.poll();

        Block b20 = createNextBlock(b15, chainHeadHeight + 7, out7, null);
        blocks.add(new BlockAndValidity(b20, false, true, b15.getHash(), "b20"));
        
        // Attempt to spend a coinbase at depth too low (on a fork this time)
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5)
        //                                                                \-> b21 (6) -> b22 (5)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b21 = createNextBlock(b13, chainHeadHeight + 6, out6, null);
        blocks.add(new BlockAndValidity(b21, true, false, b15.getHash(), "b21"));
        Block b22 = createNextBlock(b21, chainHeadHeight + 7, out5, null);
        blocks.add(new BlockAndValidity(b22, false, true, b15.getHash(), "b22"));
        
        // Create a block on either side of MAX_BLOCK_SIZE and make sure its accepted/rejected
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b23 (6)
        //                                                                           \-> b24 (6) -> b25 (7)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b23 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            Transaction tx = new Transaction(params);
            // Signature size is non-deterministic, so it may take several runs before finding any off-by-one errors
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIZE - b23.getMessageSize() - 138];
            Arrays.fill(outputScript, (byte)Script.OP_FALSE);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b23.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b23.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b23.addTransaction(tx);
        }
        b23.solve();
        blocks.add(new BlockAndValidity(b23, true, false, b23.getHash(), "b23"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b23.getTransactions().get(0).getHash()),
                b23.getTransactions().get(0).getOutputs().get(0).getValue(),
                b23.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        Block b24 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            Transaction tx = new Transaction(params);
            // Signature size is non-deterministic, so it may take several runs before finding any off-by-one errors
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIZE - b24.getMessageSize() - 135];
            Arrays.fill(outputScript, (byte)Script.OP_FALSE);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b24.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b24.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b24.addTransaction(tx);
        }
        b24.solve();
        blocks.add(new BlockAndValidity(b24, false, true, b23.getHash(), "b24"));
        
        // Extend the b24 chain to make sure bitcoind isn't accepting b24
        Block b25 = createNextBlock(b24, chainHeadHeight + 8, out7, null);
        blocks.add(new BlockAndValidity(b25, false, false, b23.getHash(), "b25"));
        
        // Create blocks with a coinbase input script size out of range
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b23 (6) -> b30 (7)
        //                                                                           \-> ... (6) -> ... (7)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b26 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        // 1 is too small, but we already generate every other block with 2, so that is tested
        b26.getTransactions().get(0).getInputs().get(0).setScriptBytes(new byte[] {0});
        b26.setMerkleRoot(null);
        b26.solve();
        blocks.add(new BlockAndValidity(b26, false, true, b23.getHash(), "b26"));
        
        // Extend the b26 chain to make sure bitcoind isn't accepting b26
        Block b27 = createNextBlock(b26, chainHeadHeight + 8, out7, null);
        blocks.add(new BlockAndValidity(b27, false, false, b23.getHash(), "b27"));
        
        Block b28 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            byte[] coinbase = new byte[101];
            Arrays.fill(coinbase, (byte)0);
            b28.getTransactions().get(0).getInputs().get(0).setScriptBytes(coinbase);
        }
        b28.setMerkleRoot(null);
        b28.solve();
        blocks.add(new BlockAndValidity(b28, false, true, b23.getHash(), "b28"));
        
        // Extend the b28 chain to make sure bitcoind isn't accepting b28
        Block b29 = createNextBlock(b28, chainHeadHeight + 8, out7, null);
        blocks.add(new BlockAndValidity(b29, false, false, b23.getHash(), "b29"));
        
        Block b30 = createNextBlock(b23, chainHeadHeight + 8, out7, null);
        {
            byte[] coinbase = new byte[100];
            Arrays.fill(coinbase, (byte)0);
            b30.getTransactions().get(0).getInputs().get(0).setScriptBytes(coinbase);
        }
        b30.setMerkleRoot(null);
        b30.solve();
        blocks.add(new BlockAndValidity(b30, true, false, b30.getHash(), "b30"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b30.getTransactions().get(0).getHash()),
                b30.getTransactions().get(0).getOutputs().get(0).getValue(),
                b30.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Check sigops of OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY/OP_CHECKSIGVERIFY
        // 6  (3)
        // 12 (3) -> b13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10)
        //                                                                                     \-> b36 (11)
        //                                                                         \-> b34 (10)
        //                                                              \-> b32 (9)
        //
        TransactionOutPointWithValue out8 = spendableOutputs.poll();

        Block b31 = createNextBlock(b30, chainHeadHeight + 9, out8, null);
        {
            int sigOps = 0;
            for (Transaction tx : b31.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[(Block.MAX_BLOCK_SIGOPS - sigOps)/20];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKMULTISIG);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b31.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b31.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b31.addTransaction(tx);
        }
        b31.solve();
        
        blocks.add(new BlockAndValidity(b31, true, false, b31.getHash(), "b31"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b31.getTransactions().get(0).getHash()),
                b31.getTransactions().get(0).getOutputs().get(0).getValue(),
                b31.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out9 = spendableOutputs.poll();
        
        Block b32 = createNextBlock(b31, chainHeadHeight + 10, out9, null);
        {
            int sigOps = 0;
            for (Transaction tx : b32.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[(Block.MAX_BLOCK_SIGOPS - sigOps)/20 + (Block.MAX_BLOCK_SIGOPS - sigOps)%20 + 1];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKMULTISIG);
            for (int i = 0; i < (Block.MAX_BLOCK_SIGOPS - sigOps)%20; i++)
                outputScript[i] = (byte)Script.OP_CHECKSIG;
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b32.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b32.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b32.addTransaction(tx);
        }
        b32.solve();
        
        blocks.add(new BlockAndValidity(b32, false, true, b31.getHash(), "b32"));
        
        
        Block b33 = createNextBlock(b31, chainHeadHeight + 10, out9, null);
        {
            int sigOps = 0;
            for (Transaction tx : b33.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[(Block.MAX_BLOCK_SIGOPS - sigOps)/20];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKMULTISIGVERIFY);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b33.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b33.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b33.addTransaction(tx);
        }
        b33.solve();
        
        blocks.add(new BlockAndValidity(b33, true, false, b33.getHash(), "b33"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b33.getTransactions().get(0).getHash()),
                b33.getTransactions().get(0).getOutputs().get(0).getValue(),
                b33.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out10 = spendableOutputs.poll();
        
        Block b34 = createNextBlock(b33, chainHeadHeight + 11, out10, null);
        {
            int sigOps = 0;
            for (Transaction tx : b34.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[(Block.MAX_BLOCK_SIGOPS - sigOps)/20 + (Block.MAX_BLOCK_SIGOPS - sigOps)%20 + 1];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKMULTISIGVERIFY);
            for (int i = 0; i < (Block.MAX_BLOCK_SIGOPS - sigOps)%20; i++)
                outputScript[i] = (byte)Script.OP_CHECKSIG;
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b34.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b34.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b34.addTransaction(tx);
        }
        b34.solve();
        
        blocks.add(new BlockAndValidity(b34, false, true, b33.getHash(), "b34"));
        
        
        Block b35 = createNextBlock(b33, chainHeadHeight + 11, out10, null);
        {
            int sigOps = 0;
            for (Transaction tx : b35.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKSIGVERIFY);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b35.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b35.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b35.addTransaction(tx);
        }
        b35.solve();
        
        blocks.add(new BlockAndValidity(b35, true, false, b35.getHash(), "b35"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b35.getTransactions().get(0).getHash()),
                b35.getTransactions().get(0).getOutputs().get(0).getValue(),
                b35.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out11 = spendableOutputs.poll();
        
        Block b36 = createNextBlock(b35, chainHeadHeight + 12, out11, null);
        {
            int sigOps = 0;
            for (Transaction tx : b36.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + 1];
            Arrays.fill(outputScript, (byte)Script.OP_CHECKSIGVERIFY);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b36.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b36.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b36.addTransaction(tx);
        }
        b36.solve();
        
        blocks.add(new BlockAndValidity(b36, false, true, b35.getHash(), "b36"));
        
        // Check spending of a transaction in a block which failed to connect
        // (test block store transaction abort handling, not that it should get this far if that's broken...)
        // 6  (3)
        // 12 (3) -> b13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10)
        //                                                                                     \-> b37 (11)
        //                                                                                     \-> b38 (11)
        //
        Block b37 = createNextBlock(b35, chainHeadHeight + 10, out11, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), new byte[] {}));
            addOnlyInputToTransaction(tx, out11); // double spend out11
            b37.addTransaction(tx);
        }
        b37.solve();
        blocks.add(new BlockAndValidity(b37, false, true, b35.getHash(), "b37"));
        
        Block b38 = createNextBlock(b35, chainHeadHeight + 10, out11, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), new byte[] {}));
            // Attempt to spend b37's first non-coinbase tx, at which point b37 was still considered valid
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b37.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b37.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b38.addTransaction(tx);
        }
        b38.solve();
        blocks.add(new BlockAndValidity(b38, false, true, b35.getHash(), "b38"));
        
        // Check P2SH SigOp counting
        // 13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b41 (12)
        //                                                                                      \-> b40 (12)
        //
        // Create some P2SH outputs that will require 6 sigops to spend
        byte[] b39p2shScriptPubKey;
        int b39numP2SHOutputs = 0, b39sigOpsPerOutput = 6;
        Block b39 = createNextBlock(b35, chainHeadHeight + 10, null, null);
        {
            ByteArrayOutputStream p2shScriptPubKey = new UnsafeByteArrayOutputStream();
            try {
                Script.writeBytes(p2shScriptPubKey, coinbaseOutKeyPubKey);
                p2shScriptPubKey.write(Script.OP_2DUP);
                p2shScriptPubKey.write(Script.OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(Script.OP_2DUP);
                p2shScriptPubKey.write(Script.OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(Script.OP_2DUP);
                p2shScriptPubKey.write(Script.OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(Script.OP_2DUP);
                p2shScriptPubKey.write(Script.OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(Script.OP_2DUP);
                p2shScriptPubKey.write(Script.OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(Script.OP_CHECKSIG);
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
            b39p2shScriptPubKey = p2shScriptPubKey.toByteArray();
            
            byte[] scriptHash = Utils.sha256hash160(b39p2shScriptPubKey);
            UnsafeByteArrayOutputStream scriptPubKey = new UnsafeByteArrayOutputStream(scriptHash.length + 3);
            scriptPubKey.write(Script.OP_HASH160);
            try {
                Script.writeBytes(scriptPubKey, scriptHash);
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
            scriptPubKey.write(Script.OP_EQUAL);
            
            BigInteger lastOutputValue = out11.value.subtract(BigInteger.valueOf(1));
            TransactionOutPoint lastOutPoint;
            {
                Transaction tx = new Transaction(params);
                tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), scriptPubKey.toByteArray()));
                tx.addOutput(new TransactionOutput(params, tx, lastOutputValue, new byte[]{Script.OP_1}));
                addOnlyInputToTransaction(tx, out11);
                lastOutPoint = new TransactionOutPoint(params, 1, tx.getHash());
                b39.addTransaction(tx);
            }
            b39numP2SHOutputs++;
            
            while (b39.getMessageSize() < Block.MAX_BLOCK_SIZE)
            {
                Transaction tx = new Transaction(params);

                lastOutputValue = lastOutputValue.subtract(BigInteger.valueOf(1));
                tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), scriptPubKey.toByteArray()));
                tx.addOutput(new TransactionOutput(params, tx, lastOutputValue, new byte[]{Script.OP_1}));
                tx.addInput(new TransactionInput(params, tx, new byte[]{Script.OP_1}, lastOutPoint));
                lastOutPoint = new TransactionOutPoint(params, 1, tx.getHash());
                
                if (b39.getMessageSize() + tx.getMessageSize() < Block.MAX_BLOCK_SIZE) {
                    b39.addTransaction(tx);
                    b39numP2SHOutputs++;
                } else
                    break;
            }
        }
        b39.solve();
        blocks.add(new BlockAndValidity(b39, true, false, b39.getHash(), "b39"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b39.getTransactions().get(0).getHash()),
                b39.getTransactions().get(0).getOutputs().get(0).getValue(),
                b39.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out12 = spendableOutputs.poll();
        
        Block b40 = createNextBlock(b39, chainHeadHeight + 11, out12, null);
        {
            int sigOps = 0;
            for (Transaction tx : b40.transactions) {
                sigOps += tx.getSigOpCount();
            }
            
            int numTxes = (Block.MAX_BLOCK_SIGOPS - sigOps) / b39sigOpsPerOutput;
            Preconditions.checkState(numTxes <= b39numP2SHOutputs);
            
            TransactionOutPoint lastOutPoint = new TransactionOutPoint(params, 2, b40.getTransactions().get(1).getHash());
            
            byte[] scriptSig = null;
            for (int i = 1; i <= numTxes; i++) {
                Transaction tx = new Transaction(params);
                tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), new byte[] {Script.OP_1}));
                tx.addInput(new TransactionInput(params, tx, new byte[]{Script.OP_1}, lastOutPoint));
                
                TransactionInput input = new TransactionInput(params, tx, new byte[]{},
                        new TransactionOutPoint(params, 0, b39.getTransactions().get(i).getHash()));
                tx.addInput(input);

                if (scriptSig == null) {
                    // Exploit the SigHash.SINGLE bug to avoid having to make more than one signature
                    Sha256Hash hash = tx.hashTransactionForSignature(1, b39p2shScriptPubKey, SigHash.SINGLE, false);

                    // Sign input
                    try {
                        ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(73);
                        bos.write(coinbaseOutKey.sign(hash).encodeToDER());
                        bos.write(SigHash.SINGLE.ordinal() + 1);
                        byte[] signature = bos.toByteArray();

                        ByteArrayOutputStream scriptSigBos = new UnsafeByteArrayOutputStream(signature.length + b39p2shScriptPubKey.length + 3);
                        Script.writeBytes(scriptSigBos, new byte[] {(byte) Script.OP_CHECKSIG});
                        scriptSigBos.write(Script.createInputScript(signature));
                        Script.writeBytes(scriptSigBos, b39p2shScriptPubKey);
                        
                        scriptSig = scriptSigBos.toByteArray();
                    } catch (IOException e) {
                        throw new RuntimeException(e);  // Cannot happen.
                    }
                }
                
                input.setScriptBytes(scriptSig);
                
                lastOutPoint = new TransactionOutPoint(params, 0, tx.getHash());
                
                b40.addTransaction(tx);
            }

            sigOps += numTxes * b39sigOpsPerOutput;
            Transaction tx = new Transaction(params);
            tx.addInput(new TransactionInput(params, tx, new byte[]{Script.OP_1}, lastOutPoint));
            byte[] scriptPubKey = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + 1];
            Arrays.fill(scriptPubKey, (byte)Script.OP_CHECKSIG);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.ZERO, scriptPubKey));
            b40.addTransaction(tx);
        }
        b40.solve();
        blocks.add(new BlockAndValidity(b40, false, true, b39.getHash(), "b40"));
        
        Block b41 = null;
        if (addExpensiveBlocks) {
            b41 = createNextBlock(b39, chainHeadHeight + 11, out12, null);
            {
                int sigOps = 0;
                for (Transaction tx : b41.transactions) {
                    sigOps += tx.getSigOpCount();
                }

                int numTxes = (Block.MAX_BLOCK_SIGOPS - sigOps)
                        / b39sigOpsPerOutput;
                Preconditions.checkState(numTxes <= b39numP2SHOutputs);

                TransactionOutPoint lastOutPoint = new TransactionOutPoint(
                        params, 2, b41.getTransactions().get(1).getHash());

                byte[] scriptSig = null;
                for (int i = 1; i <= numTxes; i++) {
                    Transaction tx = new Transaction(params);
                    tx.addOutput(new TransactionOutput(params, tx, BigInteger
                            .valueOf(1), new byte[] { Script.OP_1 }));
                    tx.addInput(new TransactionInput(params, tx,
                            new byte[] { Script.OP_1 }, lastOutPoint));

                    TransactionInput input = new TransactionInput(params, tx,
                            new byte[] {}, new TransactionOutPoint(params, 0,
                                    b39.getTransactions().get(i).getHash()));
                    tx.addInput(input);

                    if (scriptSig == null) {
                        // Exploit the SigHash.SINGLE bug to avoid having to make more than one signature
                        Sha256Hash hash = tx.hashTransactionForSignature(1,
                                b39p2shScriptPubKey, SigHash.SINGLE, false);

                        // Sign input
                        try {
                            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(
                                    73);
                            bos.write(coinbaseOutKey.sign(hash).encodeToDER());
                            bos.write(SigHash.SINGLE.ordinal() + 1);
                            byte[] signature = bos.toByteArray();

                            ByteArrayOutputStream scriptSigBos = new UnsafeByteArrayOutputStream(
                                    signature.length
                                            + b39p2shScriptPubKey.length + 3);
                            Script.writeBytes(scriptSigBos,
                                    new byte[] { (byte) Script.OP_CHECKSIG });
                            scriptSigBos.write(Script
                                    .createInputScript(signature));
                            Script.writeBytes(scriptSigBos, b39p2shScriptPubKey);

                            scriptSig = scriptSigBos.toByteArray();
                        } catch (IOException e) {
                            throw new RuntimeException(e); // Cannot happen.
                        }
                    }

                    input.setScriptBytes(scriptSig);

                    lastOutPoint = new TransactionOutPoint(params, 0,
                            tx.getHash());

                    b41.addTransaction(tx);
                }

                sigOps += numTxes * b39sigOpsPerOutput;
                Transaction tx = new Transaction(params);
                tx.addInput(new TransactionInput(params, tx,
                        new byte[] { Script.OP_1 }, lastOutPoint));
                byte[] scriptPubKey = new byte[Block.MAX_BLOCK_SIGOPS - sigOps];
                Arrays.fill(scriptPubKey, (byte) Script.OP_CHECKSIG);
                tx.addOutput(new TransactionOutput(params, tx, BigInteger.ZERO, scriptPubKey));
                b41.addTransaction(tx);
            }
            b41.solve();
            blocks.add(new BlockAndValidity(b41, true, false, b41.getHash(), "b41"));
        }
        
        // Fork off of b39 to create a constant base again
        // b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13)
        //                                                                 \-> b41 (12)
        //
        Block b42 = createNextBlock(b39, chainHeadHeight + 11, out12, null);
        blocks.add(new BlockAndValidity(b42, true, false, b41 == null ? b42.getHash() : b41.getHash(), "b42"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b42.getTransactions().get(0).getHash()),
                b42.getTransactions().get(0).getOutputs().get(0).getValue(),
                b42.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out13 = spendableOutputs.poll();
        
        Block b43 = createNextBlock(b42, chainHeadHeight + 12, out13, null);
        blocks.add(new BlockAndValidity(b43, true, false, b43.getHash(), "b43"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b43.getTransactions().get(0).getHash()),
                b43.getTransactions().get(0).getOutputs().get(0).getValue(),
                b43.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Test a number of really invalid scenarios
        //  -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b44 (14)
        //                                                                                   \-> ??? (15)
        //
        TransactionOutPointWithValue out14 = spendableOutputs.poll();
        
        // A valid block created exactly like b44 to make sure the creation itself works
        Block b44 = new Block(params);
        {
            b44.setDifficultyTarget(b43.getDifficultyTarget());
            b44.addCoinbaseTransaction(coinbaseOutKeyPubKey, BigInteger.ZERO);
            
            Transaction t = new Transaction(params);
            // Entirely invalid scriptPubKey to ensure we aren't pre-verifying too much
            t.addOutput(new TransactionOutput(params, t, BigInteger.valueOf(0), new byte[] { Script.OP_PUSHDATA1 - 1 }));
            t.addOutput(new TransactionOutput(params, t, BigInteger.valueOf(1), Script.createOutputScript(coinbaseOutKeyPubKey)));
            // Spendable output
            t.addOutput(new TransactionOutput(params, t, BigInteger.ZERO, new byte[] {Script.OP_1}));
            addOnlyInputToTransaction(t, out14);
            b44.addTransaction(t);

            b44.setPrevBlockHash(b43.getHash());
            b44.setTime(b43.getTimeSeconds() + 1);
        }
        b44.solve();
        blocks.add(new BlockAndValidity(b44, true, false, b44.getHash(), "b44"));
        
        TransactionOutPointWithValue out15 = spendableOutputs.poll();
        
        // A block with a non-coinbase as the first tx
        Block b45 = new Block(params);
        {
            b45.setDifficultyTarget(b44.getDifficultyTarget());
            //b45.addCoinbaseTransaction(pubKey, coinbaseValue);
            
            Transaction t = new Transaction(params);
            // Entirely invalid scriptPubKey to ensure we aren't pre-verifying too much
            t.addOutput(new TransactionOutput(params, t, BigInteger.valueOf(0), new byte[] { Script.OP_PUSHDATA1 - 1 }));
            t.addOutput(new TransactionOutput(params, t, BigInteger.valueOf(1), Script.createOutputScript(coinbaseOutKeyPubKey)));
            // Spendable output
            t.addOutput(new TransactionOutput(params, t, BigInteger.ZERO, new byte[] {Script.OP_1}));
            addOnlyInputToTransaction(t, out15);
            try {
                b45.addTransaction(t);
            } catch (RuntimeException e) { } // Should happen
            if (b45.getTransactions().size() > 0)
                throw new RuntimeException("addTransaction doesn't properly check for adding a non-coinbase as first tx");
            b45.addTransaction(t, false);

            b45.setPrevBlockHash(b44.getHash());
            b45.setTime(b44.getTimeSeconds() + 1);
        }
        b45.solve();
        blocks.add(new BlockAndValidity(b45, false, true, b44.getHash(), "b45"));
        
        // A block with no txn
        Block b46 = new Block(params);
        {
            b46.transactions = new ArrayList<Transaction>();
            b46.setDifficultyTarget(b44.getDifficultyTarget());
            b46.setMerkleRoot(Sha256Hash.ZERO_HASH);

            b46.setPrevBlockHash(b44.getHash());
            b46.setTime(b44.getTimeSeconds() + 1);
        }
        b46.solve();
        blocks.add(new BlockAndValidity(b46, false, true, b44.getHash(), "b46"));
        
        // A block with invalid work
        Block b47 = createNextBlock(b44, chainHeadHeight + 14, out15, null);
        {
            try {
                // Inverse solve
                BigInteger target = b47.getDifficultyTargetAsInteger();
                while (true) {
                    BigInteger h = b47.getHash().toBigInteger();
                    if (h.compareTo(target) > 0) // if invalid
                        break;
                    // increment the nonce and try again.
                    b47.setNonce(b47.getNonce() + 1);
                }
            } catch (VerificationException e) {
                throw new RuntimeException(e); // Cannot happen.
            }
        }
        blocks.add(new BlockAndValidity(b47, false, true, b44.getHash(), "b47"));
        
        // Block with timestamp > 2h in the future
        Block b48 = createNextBlock(b44, chainHeadHeight + 14, out15, null);
        b48.setTime(Utils.now().getTime() / 1000 + 60*60*3);
        b48.solve();
        blocks.add(new BlockAndValidity(b48, false, true, b44.getHash(), "b48"));
        
        // Block with invalid merkle hash
        Block b49 = createNextBlock(b44, chainHeadHeight + 14, out15, null);
        b49.setMerkleRoot(Sha256Hash.ZERO_HASH);
        b49.solve();
        blocks.add(new BlockAndValidity(b49, false, true, b44.getHash(), "b49"));
        
        // Block with incorrect POW limit
        Block b50 = createNextBlock(b44, chainHeadHeight + 14, out15, null);
        {
            long diffTarget = b44.getDifficultyTarget();
            diffTarget &= 0xFFBFFFFF; // Make difficulty one bit harder
            b50.setDifficultyTarget(diffTarget);
        }
        b50.solve();
        blocks.add(new BlockAndValidity(b50, false, true, b44.getHash(), "b50"));
        
        // A block with two coinbase txn
        Block b51 = createNextBlock(b44, chainHeadHeight + 14, out15, null);
        {
            Transaction coinbase = new Transaction(params);
            coinbase.addInput(new TransactionInput(params, coinbase, new byte[]{(byte) 0xff, 110, 1}));
            coinbase.addOutput(new TransactionOutput(params, coinbase, BigInteger.ONE, Script.createOutputScript(coinbaseOutKeyPubKey)));
            b51.addTransaction(coinbase, false);
        }
        b51.solve();
        blocks.add(new BlockAndValidity(b51, false, true, b44.getHash(), "b51"));
        
        // A block with duplicate txn
        Block b52 = createNextBlock(b44, chainHeadHeight + 14, out15, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), new byte[] {}));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b52.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b52.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b52.addTransaction(tx);
            b52.addTransaction(tx);
        }
        b52.solve();
        blocks.add(new BlockAndValidity(b52, false, true, b44.getHash(), "b52"));
        
        // Test block timestamp
        //  -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15)
        //                                                                                   \-> b54 (15)
        //                                                                       \-> b44 (14)
        //
        Block b53 = createNextBlock(b43, chainHeadHeight + 13, out14, null);
        blocks.add(new BlockAndValidity(b53, true, false, b44.getHash(), "b53"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b53.getTransactions().get(0).getHash()),
                b53.getTransactions().get(0).getOutputs().get(0).getValue(),
                b53.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Block with invalid timestamp
        Block b54 = createNextBlock(b53, chainHeadHeight + 14, out15, null);
        b54.setTime(b35.getTimeSeconds() - 1);
        b54.solve();
        blocks.add(new BlockAndValidity(b54, false, true, b44.getHash(), "b54"));
        
        // Block with valid timestamp
        Block b55 = createNextBlock(b53, chainHeadHeight + 14, out15, null);
        b55.setTime(b35.getTimeSeconds());
        b55.solve();
        blocks.add(new BlockAndValidity(b55, true, false, b55.getHash(), "b55"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b55.getTransactions().get(0).getHash()),
                b55.getTransactions().get(0).getOutputs().get(0).getValue(),
                b55.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Test CVE-2012-2459
        // -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16)
        //                                                                                   \-> b56 (16)
        //
        TransactionOutPointWithValue out16 = spendableOutputs.poll();
        
        Block b57 = createNextBlock(b55, chainHeadHeight + 15, out16, null);
        Transaction b56txToDuplicate;
        {
            b56txToDuplicate = new Transaction(params);
            b56txToDuplicate.addOutput(new TransactionOutput(params, b56txToDuplicate, BigInteger.valueOf(1), new byte[] {}));
            addOnlyInputToTransaction(b56txToDuplicate, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b57.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b57.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b57.addTransaction(b56txToDuplicate);
        }
        b57.solve();
        
        Block b56;
        try {
            b56 = new Block(params, b57.bitcoinSerialize());
        } catch (ProtocolException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
        b56.addTransaction(b56txToDuplicate);
        Preconditions.checkState(b56.getHash().equals(b57.getHash()));
        blocks.add(new BlockAndValidity(b56, false, true, b55.getHash(), "b56"));
        
        blocks.add(new BlockAndValidity(b57, true, false, b57.getHash(), "b57"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b57.getTransactions().get(0).getHash()),
                b57.getTransactions().get(0).getOutputs().get(0).getValue(),
                b57.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Test a few invalid tx types
        // -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        //                                                                                    \-> ??? (17)
        //
        TransactionOutPointWithValue out17 = spendableOutputs.poll();
        
        // tx with prevout.n out of range
        Block b58 = createNextBlock(b57, chainHeadHeight + 16, out17, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.ZERO, new byte[] {}));
            tx.addInput(new TransactionInput(params, tx, new byte[] { Script.OP_1 },
                    new TransactionOutPoint(params, 3, b58.getTransactions().get(1).getHash())));
            b58.addTransaction(tx);
        }
        b58.solve();
        blocks.add(new BlockAndValidity(b58, false, true, b57.getHash(), "b58"));
        
        // tx with output value > input value out of range
        Block b59 = createNextBlock(b57, chainHeadHeight + 16, out17, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx,
                    b59.getTransactions().get(1).getOutputs().get(2).getValue().add(BigInteger.ONE), new byte[] {}));
            tx.addInput(new TransactionInput(params, tx, new byte[] { Script.OP_1 },
                    new TransactionOutPoint(params, 2, b59.getTransactions().get(1).getHash())));
            b59.addTransaction(tx);
        }
        b59.solve();
        blocks.add(new BlockAndValidity(b59, false, true, b57.getHash(), "b59"));
        
        Block b60 = createNextBlock(b57, chainHeadHeight + 16, out17, null);
        blocks.add(new BlockAndValidity(b60, true, false, b60.getHash(), "b60"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b60.getTransactions().get(0).getHash()),
                b60.getTransactions().get(0).getOutputs().get(0).getValue(),
                b60.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Test BIP30
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        //                                                                                    \-> b61 (18)
        //
        TransactionOutPointWithValue out18 = spendableOutputs.poll();
        
        Block b61 = createNextBlock(b60, chainHeadHeight + 17, out18, null);
        {
            byte[] scriptBytes = b61.getTransactions().get(0).getInputs().get(0).getScriptBytes();
            scriptBytes[0]--; // createNextBlock will increment the first script byte on each new block
            b61.getTransactions().get(0).getInputs().get(0).setScriptBytes(scriptBytes);
            b61.unCache();
        }
        b61.solve();
        blocks.add(new BlockAndValidity(b61, false, true, b60.getHash(), "b61"));
        
        // Test tx.isFinal is properly rejected (not an exhaustive tx.isFinal test, that should be in data-driven transaction tests)
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        //                                                                                    \-> b62 (18)
        //
        Block b62 = createNextBlock(b60, chainHeadHeight + 17, null, null);
        {
            Transaction tx = new Transaction(params);
            tx.setLockTime(0xffffffffL);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.ZERO, new byte[] { Script.OP_TRUE }));
            addOnlyInputToTransaction(tx, out18, 0);
            b62.addTransaction(tx);
            Preconditions.checkState(!tx.isFinal(chainHeadHeight + 17, b62.getTimeSeconds()));
        }
        b62.solve();
        blocks.add(new BlockAndValidity(b62, false, true, b60.getHash(), "b62"));
        
        // Test a non-final coinbase is also rejected
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        //                                                                                    \-> b63 (-)
        //
        Block b63 = createNextBlock(b60, chainHeadHeight + 17, null, null);
        {
            b63.getTransactions().get(0).setLockTime(0xffffffffL);
            b63.getTransactions().get(0).getInputs().get(0).setSequenceNumber(0xDEADBEEF);
            Preconditions.checkState(!b63.getTransactions().get(0).isFinal(chainHeadHeight + 17, b63.getTimeSeconds()));
        }
        b63.solve();
        blocks.add(new BlockAndValidity(b63, false, true, b60.getHash(), "b63"));
        
        // Check that a block which is (when properly encoded) <= MAX_BLOCK_SIZE is accepted
        // Even when it is encoded with varints that make its encoded size actually > MAX_BLOCK_SIZE
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18)
        //
        Block b64;
        {
            Block b64Created = createNextBlock(b60, chainHeadHeight + 17, out18, null);
            Transaction tx = new Transaction(params);
            // Signature size is non-deterministic, so it may take several runs before finding any off-by-one errors
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIZE - b64Created.getMessageSize() - 138];
            Arrays.fill(outputScript, (byte)Script.OP_FALSE);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.valueOf(1), outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b64Created.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b64Created.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b64Created.addTransaction(tx);
            b64Created.solve();
            
            UnsafeByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(b64Created.getMessageSize() + 8);
            b64Created.writeHeader(stream);
            
            byte[] varIntBytes = new byte[9];
            varIntBytes[0] = (byte) 255;
            Utils.uint32ToByteArrayLE((long)b64Created.getTransactions().size(), varIntBytes, 1);
            Utils.uint32ToByteArrayLE(((long)b64Created.getTransactions().size()) >>> 32, varIntBytes, 5);
            stream.write(varIntBytes);
            Preconditions.checkState(new VarInt(varIntBytes, 0).value == b64Created.getTransactions().size());
            
            for (Transaction transaction : b64Created.getTransactions())
                transaction.bitcoinSerialize(stream);
            b64 = new Block(params, stream.toByteArray(), false, true, stream.size());
            
            // The following checks are checking to ensure block serialization functions in the way needed for this test
            // If they fail, it is likely not an indication of error, but an indication that this test needs rewritten
            Preconditions.checkState(stream.size() == b64Created.getMessageSize() + 8);
            Preconditions.checkState(stream.size() == b64.getMessageSize());
            Preconditions.checkState(Arrays.equals(stream.toByteArray(), b64.bitcoinSerialize()));
            Preconditions.checkState(b64.getOptimalEncodingMessageSize() == b64Created.getMessageSize());
        }
        blocks.add(new BlockAndValidity(b64, true, false, b64.getHash(), "b64"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b64.getTransactions().get(0).getHash()),
                b64.getTransactions().get(0).getOutputs().get(0).getValue(),
                b64.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Spend an output created in the block itself
        // -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        //
        TransactionOutPointWithValue out19 = spendableOutputs.poll();
        
        Block b65 = createNextBlock(b64, chainHeadHeight + 18, null, null);
        {
            Transaction tx1 = new Transaction(params);
            tx1.addOutput(new TransactionOutput(params, tx1, out19.value, new byte[]{ Script.OP_TRUE }));
            addOnlyInputToTransaction(tx1, out19, 0);
            b65.addTransaction(tx1);
            Transaction tx2 = new Transaction(params);
            tx2.addOutput(new TransactionOutput(params, tx2, BigInteger.ZERO, new byte[]{ Script.OP_TRUE }));
            tx2.addInput(new TransactionInput(params, tx2, new byte[]{ Script.OP_TRUE },
                    new TransactionOutPoint(params, 0, tx1.getHash())));
            b65.addTransaction(tx2);
        }
        b65.solve();
        blocks.add(new BlockAndValidity(b65, true, false, b65.getHash(), "b65"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b65.getTransactions().get(0).getHash()),
                b65.getTransactions().get(0).getOutputs().get(0).getValue(),
                b65.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Attempt to spend an output created later in the same block
        // -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        //                                                                                    \-> b66 (20)
        //
        TransactionOutPointWithValue out20 = spendableOutputs.poll();
        
        Block b66 = createNextBlock(b65, chainHeadHeight + 19, null, null);
        {
            Transaction tx1 = new Transaction(params);
            tx1.addOutput(new TransactionOutput(params, tx1, out20.value, new byte[]{ Script.OP_TRUE }));
            addOnlyInputToTransaction(tx1, out20, 0);
            Transaction tx2 = new Transaction(params);
            tx2.addOutput(new TransactionOutput(params, tx2, BigInteger.ZERO, new byte[]{ Script.OP_TRUE }));
            tx2.addInput(new TransactionInput(params, tx2, new byte[]{ Script.OP_TRUE },
                    new TransactionOutPoint(params, 0, tx1.getHash())));
            b66.addTransaction(tx2);
            b66.addTransaction(tx1);
        }
        b66.solve();
        blocks.add(new BlockAndValidity(b66, false, true, b65.getHash(), "b66"));
        
        // Attempt to double-spend a transaction created in a block
        // -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        //                                                                                    \-> b67 (20)
        //
        Block b67 = createNextBlock(b65, chainHeadHeight + 19, null, null);
        {
            Transaction tx1 = new Transaction(params);
            tx1.addOutput(new TransactionOutput(params, tx1, out20.value, new byte[]{ Script.OP_TRUE }));
            addOnlyInputToTransaction(tx1, out20, 0);
            b67.addTransaction(tx1);
            Transaction tx2 = new Transaction(params);
            tx2.addOutput(new TransactionOutput(params, tx2, BigInteger.ZERO, new byte[]{ Script.OP_TRUE }));
            tx2.addInput(new TransactionInput(params, tx2, new byte[]{ Script.OP_TRUE },
                    new TransactionOutPoint(params, 0, tx1.getHash())));
            b67.addTransaction(tx2);
            Transaction tx3 = new Transaction(params);
            tx3.addOutput(new TransactionOutput(params, tx3, out20.value, new byte[]{ Script.OP_TRUE }));
            tx3.addInput(new TransactionInput(params, tx3, new byte[]{ Script.OP_TRUE },
                    new TransactionOutPoint(params, 0, tx1.getHash())));
            b67.addTransaction(tx3);
        }
        b67.solve();
        blocks.add(new BlockAndValidity(b67, false, true, b65.getHash(), "b67"));
        
        // A few more tests of block subsidy
        // -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20)
        //                                                                                    \-> b68 (20)
        //
        Block b68 = createNextBlock(b65, chainHeadHeight + 19, null, BigInteger.TEN);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, out20.value.subtract(BigInteger.valueOf(9)), new byte[]{ Script.OP_TRUE }));
            addOnlyInputToTransaction(tx, out20, 0);
            b68.addTransaction(tx);
        }
        b68.solve();
        blocks.add(new BlockAndValidity(b68, false, true, b65.getHash(), "b68"));
        
        Block b69 = createNextBlock(b65, chainHeadHeight + 19, null, BigInteger.TEN);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, out20.value.subtract(BigInteger.TEN), new byte[]{ Script.OP_TRUE }));
            addOnlyInputToTransaction(tx, out20, 0);
            b69.addTransaction(tx);
        }
        b69.solve();
        blocks.add(new BlockAndValidity(b69, true, false, b69.getHash(), "b69"));
        
        // Test spending the outpoint of a non-existent transaction
        // -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20)
        //                                                                                    \-> b70 (21)
        //
        TransactionOutPointWithValue out21 = spendableOutputs.poll();
        Block b70 = createNextBlock(b69, chainHeadHeight + 20, out21, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.ZERO, new byte[]{ Script.OP_TRUE }));
            tx.addInput(new TransactionInput(params, tx, new byte[]{ Script.OP_TRUE },
                    new TransactionOutPoint(params, 0, new Sha256Hash("23c70ed7c0506e9178fc1a987f40a33946d4ad4c962b5ae3a52546da53af0c5c"))));
            b70.addTransaction(tx);
        }
        b70.solve();
        blocks.add(new BlockAndValidity(b70, false, true, b69.getHash(), "b70"));
        
        // Test accepting an invalid block which has the same hash as a valid one (via merkle tree tricks)
        // -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20) -> b71 (21)
        //                                                                                    \-> b71 (21)
        //
        Block b72 = createNextBlock(b69, chainHeadHeight + 20, out21, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, BigInteger.ZERO, new byte[]{ Script.OP_TRUE }));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b72.getTransactions().get(1).getHash()),
                    BigInteger.valueOf(1), b72.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b72.addTransaction(tx);
        }
        b72.solve();
        
        Block b71 = new Block(params, b72.bitcoinSerialize());
        b71.addTransaction(b72.getTransactions().get(2));
        Preconditions.checkState(b71.getHash().equals(b72.getHash()));
        blocks.add(new BlockAndValidity(b71, false, true, b69.getHash(), "b71"));
        blocks.add(new BlockAndValidity(b72, true, false, b72.getHash(), "b72"));
        
        //TODO: Explicitly address MoneyRange() checks
        
        // (finally) return the created chain
        return blocks;
    }
    
    private Block createNextBlock(Block baseBlock, int nextBlockHeight, TransactionOutPointWithValue prevOut,
            BigInteger additionalCoinbaseValue) throws ScriptException {
        BigInteger coinbaseValue = Utils.toNanoCoins(50, 0).shiftRight(nextBlockHeight / params.getSubsidyDecreaseBlockCount())
                .add((prevOut != null ? prevOut.value.subtract(BigInteger.ONE) : BigInteger.valueOf(0)))
                .add(additionalCoinbaseValue == null ? BigInteger.valueOf(0) : additionalCoinbaseValue);
        Block block = baseBlock.createNextBlockWithCoinbase(coinbaseOutKeyPubKey, coinbaseValue);
        if (prevOut != null) {
            Transaction t = new Transaction(params);
            // Entirely invalid scriptPubKey to ensure we aren't pre-verifying too much
            t.addOutput(new TransactionOutput(params, t, BigInteger.valueOf(0), new byte[] { Script.OP_PUSHDATA1 - 1 }));
            t.addOutput(new TransactionOutput(params, t, BigInteger.valueOf(1), Script.createOutputScript(coinbaseOutKeyPubKey)));
            // Spendable output
            t.addOutput(new TransactionOutput(params, t, BigInteger.ZERO, new byte[] {Script.OP_1}));
            addOnlyInputToTransaction(t, prevOut);
            block.addTransaction(t);
            block.solve();
        }
        return block;
    }
    
    private void addOnlyInputToTransaction(Transaction t, TransactionOutPointWithValue prevOut) throws ScriptException {
        addOnlyInputToTransaction(t, prevOut, TransactionInput.NO_SEQUENCE);
    }
    
    private void addOnlyInputToTransaction(Transaction t, TransactionOutPointWithValue prevOut, long sequence) throws ScriptException {
        TransactionInput input = new TransactionInput(params, t, new byte[]{}, prevOut.outpoint);
        input.setSequenceNumber(sequence);
        t.addInput(input);

        byte[] connectedPubKeyScript = prevOut.scriptPubKey.program;
        Sha256Hash hash = t.hashTransactionForSignature(0, connectedPubKeyScript, SigHash.ALL, false);

        // Sign input
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(73);
            bos.write(coinbaseOutKey.sign(hash).encodeToDER());
            bos.write(SigHash.ALL.ordinal() + 1);
            byte[] signature = bos.toByteArray();
            
            Preconditions.checkState(prevOut.scriptPubKey.isSentToRawPubKey());
            input.setScriptBytes(Script.createInputScript(signature));
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }
}
