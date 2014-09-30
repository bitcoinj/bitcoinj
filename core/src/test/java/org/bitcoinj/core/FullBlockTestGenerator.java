package org.bitcoinj.core;

import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import static org.bitcoinj.core.Coin.*;
import static org.bitcoinj.script.ScriptOpCodes.*;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static java.util.Collections.singletonList;

class TransactionOutPointWithValue {
    public TransactionOutPoint outpoint;
    public Coin value;
    public Script scriptPubKey;

    public TransactionOutPointWithValue(TransactionOutPoint outpoint, Coin value, Script scriptPubKey) {
        this.outpoint = outpoint;
        this.value = value;
        this.scriptPubKey = scriptPubKey;
    }

    public TransactionOutPointWithValue(Transaction tx, int output) {
        this(new TransactionOutPoint(tx.getParams(), output, tx.getHash()),
                tx.getOutput(output).getValue(), tx.getOutput(output).getScriptPubKey());
    }
}

/** An arbitrary rule which the testing client must match */
class Rule {
    String ruleName;
    Rule(String ruleName) {
        this.ruleName = ruleName;
    }
}

/**
 * Represents a block which is sent to the tested application and which the application must either reject or accept,
 * depending on the flags in the rule
 */
class BlockAndValidity extends Rule {
    Block block;
    boolean connects;
    boolean throwsException;
    Sha256Hash hashChainTipAfterBlock;
    int heightAfterBlock;

    public BlockAndValidity(Map<Sha256Hash, Integer> blockToHeightMap, Block block, boolean connects, boolean throwsException, Sha256Hash hashChainTipAfterBlock, int heightAfterBlock, String blockName) {
        super(blockName);
        if (connects && throwsException)
            throw new RuntimeException("A block cannot connect if an exception was thrown while adding it.");
        this.block = block;
        this.connects = connects;
        this.throwsException = throwsException;
        this.hashChainTipAfterBlock = hashChainTipAfterBlock;
        this.heightAfterBlock = heightAfterBlock;

        // Double-check that we are always marking any given block at the same height
        Integer height = blockToHeightMap.get(hashChainTipAfterBlock);
        if (height != null)
            checkState(height == heightAfterBlock);
        else
            blockToHeightMap.put(hashChainTipAfterBlock, heightAfterBlock);
    }
}

/**
 * A test which checks the mempool state (ie defined which transactions should be in memory pool
 */
class MemoryPoolState extends Rule {
    Set<InventoryItem> mempool;
    public MemoryPoolState(Set<InventoryItem> mempool, String ruleName) {
        super(ruleName);
        this.mempool = mempool;
    }
}

class UTXORule extends Rule {
    List<TransactionOutPoint> query;
    UTXOsMessage result;

    public UTXORule(String ruleName, TransactionOutPoint query, UTXOsMessage result) {
        super(ruleName);
        this.query = singletonList(query);
        this.result = result;
    }

    public UTXORule(String ruleName, List<TransactionOutPoint> query, UTXOsMessage result) {
        super(ruleName);
        this.query = query;
        this.result = result;
    }
}

class RuleList {
    public List<Rule> list;
    public int maximumReorgBlockCount;
    public RuleList(List<Rule> list, int maximumReorgBlockCount) {
        this.list = list;
        this.maximumReorgBlockCount = maximumReorgBlockCount;
    }
}

public class FullBlockTestGenerator {
    // Used by BitcoindComparisonTool and AbstractFullPrunedBlockChainTest to create test cases
    private NetworkParameters params;
    private ECKey coinbaseOutKey;
    private byte[] coinbaseOutKeyPubKey;
    
    // Used to double-check that we are always using the right next-height
    private Map<Sha256Hash, Integer> blockToHeightMap = new HashMap<Sha256Hash, Integer>();
    
    public FullBlockTestGenerator(NetworkParameters params) {
        this.params = params;
        coinbaseOutKey = new ECKey();
        coinbaseOutKeyPubKey = coinbaseOutKey.getPubKey();
        Utils.setMockClock();
    }

    public RuleList getBlocksToTest(boolean addSigExpensiveBlocks, boolean runLargeReorgs, File blockStorageFile) throws ScriptException, ProtocolException, IOException {
        final FileOutputStream outStream = blockStorageFile != null ? new FileOutputStream(blockStorageFile) : null;

        final Script OP_TRUE_SCRIPT = new ScriptBuilder().op(OP_TRUE).build();
        final Script OP_NOP_SCRIPT = new ScriptBuilder().op(OP_NOP).build();

        // TODO: Rename this variable.
        List<Rule> blocks = new LinkedList<Rule>() {
            @Override
            public boolean add(Rule element) {
                if (outStream != null && element instanceof BlockAndValidity) {
                    try {
                        outStream.write((int) (params.getPacketMagic() >>> 24));
                        outStream.write((int) (params.getPacketMagic() >>> 16));
                        outStream.write((int) (params.getPacketMagic() >>> 8));
                        outStream.write((int) (params.getPacketMagic() >>> 0));
                        byte[] block = ((BlockAndValidity)element).block.bitcoinSerialize();
                        byte[] length = new byte[4];
                        Utils.uint32ToByteArrayBE(block.length, length, 0);
                        outStream.write(Utils.reverseBytes(length));
                        outStream.write(block);
                        ((BlockAndValidity)element).block = null;
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                return super.add(element);
            }
        };
        RuleList ret = new RuleList(blocks, 10);
        
        Queue<TransactionOutPointWithValue> spendableOutputs = new LinkedList<TransactionOutPointWithValue>();
        
        int chainHeadHeight = 1;
        Block chainHead = params.getGenesisBlock().createNextBlockWithCoinbase(coinbaseOutKeyPubKey);
        blocks.add(new BlockAndValidity(blockToHeightMap, chainHead, true, false, chainHead.getHash(), 1, "Initial Block"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, chainHead.getTransactions().get(0).getHash()),
                FIFTY_COINS, chainHead.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        for (int i = 1; i < params.getSpendableCoinbaseDepth(); i++) {
            chainHead = chainHead.createNextBlockWithCoinbase(coinbaseOutKeyPubKey);
            chainHeadHeight++;
            blocks.add(new BlockAndValidity(blockToHeightMap, chainHead, true, false, chainHead.getHash(), i+1, "Initial Block chain output generation"));
            spendableOutputs.offer(new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 0, chainHead.getTransactions().get(0).getHash()),
                    FIFTY_COINS, chainHead.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        }
        
        // Start by building a couple of blocks on top of the genesis block.
        Block b1 = createNextBlock(chainHead, chainHeadHeight + 1, spendableOutputs.poll(), null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b1, true, false, b1.getHash(), chainHeadHeight + 1, "b1"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b1.getTransactions().get(0).getHash()),
                b1.getTransactions().get(0).getOutputs().get(0).getValue(),
                b1.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out1 = spendableOutputs.poll(); checkState(out1 != null);
        Block b2 = createNextBlock(b1, chainHeadHeight + 2, out1, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b2, true, false, b2.getHash(), chainHeadHeight + 2, "b2"));
        // Make sure nothing funky happens if we try to re-add b2
        blocks.add(new BlockAndValidity(blockToHeightMap, b2, true, false, b2.getHash(), chainHeadHeight + 2, "b2"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b2.getTransactions().get(0).getHash()),
                b2.getTransactions().get(0).getOutput(0).getValue(),
                b2.getTransactions().get(0).getOutput(0).getScriptPubKey()));
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
        blocks.add(new BlockAndValidity(blockToHeightMap, b3, true, false, b2.getHash(), chainHeadHeight + 2, "b3"));
        // Make sure nothing breaks if we add b3 twice
        blocks.add(new BlockAndValidity(blockToHeightMap, b3, true, false, b2.getHash(), chainHeadHeight + 2, "b3"));

        // Do a simple UTXO query.
        UTXORule utxo1;
        {
            Transaction coinbase = b2.getTransactions().get(0);
            TransactionOutPoint outpoint = new TransactionOutPoint(params, 0, coinbase.getHash());
            long[] heights = new long[] {chainHeadHeight + 2};
            UTXOsMessage result = new UTXOsMessage(params, ImmutableList.of(coinbase.getOutput(0)), heights, b2.getHash(), chainHeadHeight + 2);
            utxo1 = new UTXORule("utxo1", outpoint, result);
            blocks.add(utxo1);
        }

        // Now we add another block to make the alternative chain longer.
        //
        //     genesis -> b1 (0) -> b2 (1)
        //                      \-> b3 (1) -> b4 (2)
        //
        TransactionOutPointWithValue out2 = checkNotNull(spendableOutputs.poll());
        Block b4 = createNextBlock(b3, chainHeadHeight + 3, out2, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b4, true, false, b4.getHash(), chainHeadHeight + 3, "b4"));

        // Check that the old coinbase is no longer in the UTXO set and the new one is.
        {
            Transaction coinbase = b4.getTransactions().get(0);
            TransactionOutPoint outpoint = new TransactionOutPoint(params, 0, coinbase.getHash());
            List<TransactionOutPoint> queries = ImmutableList.of(utxo1.query.get(0), outpoint);
            List<TransactionOutput> results = Lists.asList(null, coinbase.getOutput(0), new TransactionOutput[] {});
            long[] heights = new long[] {chainHeadHeight + 3};
            UTXOsMessage result = new UTXOsMessage(params, results, heights, b4.getHash(), chainHeadHeight + 3);
            UTXORule utxo2 = new UTXORule("utxo2", queries, result);
            blocks.add(utxo2);
        }

        // ... and back to the first chain.
        Block b5 = createNextBlock(b2, chainHeadHeight + 3, out2, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b5, true, false, b4.getHash(), chainHeadHeight + 3, "b5"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b5.getTransactions().get(0).getHash()),
                b5.getTransactions().get(0).getOutputs().get(0).getValue(),
                b5.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out3 = spendableOutputs.poll();
        
        Block b6 = createNextBlock(b5, chainHeadHeight + 4, out3, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b6, true, false, b6.getHash(), chainHeadHeight + 4, "b6"));
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
        blocks.add(new BlockAndValidity(blockToHeightMap, b7, true, false, b6.getHash(), chainHeadHeight + 4, "b7"));
        
        TransactionOutPointWithValue out4 = spendableOutputs.poll();

        Block b8 = createNextBlock(b7, chainHeadHeight + 6, out4, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b8, false, true, b6.getHash(), chainHeadHeight + 4, "b8"));
        
        // Try to create a block that has too much fee
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6 (3)
        //                                                    \-> b9 (4)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b9 = createNextBlock(b6, chainHeadHeight + 5, out4, SATOSHI);
        blocks.add(new BlockAndValidity(blockToHeightMap, b9, false, true, b6.getHash(), chainHeadHeight + 4, "b9"));
        
        // Create a fork that ends in a block with too much fee (the one that causes the reorg)
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b10 (3) -> b11 (4)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b10 = createNextBlock(b5, chainHeadHeight + 4, out3, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b10, true, false, b6.getHash(), chainHeadHeight + 4, "b10"));
        
        Block b11 = createNextBlock(b10, chainHeadHeight + 5, out4, SATOSHI);
        blocks.add(new BlockAndValidity(blockToHeightMap, b11, false, true, b6.getHash(), chainHeadHeight + 4, "b11"));
        
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
        blocks.add(new BlockAndValidity(blockToHeightMap, b13, false, false, b6.getHash(), chainHeadHeight + 4, "b13"));
        // Make sure we dont die if an orphan gets added twice
        blocks.add(new BlockAndValidity(blockToHeightMap, b13, false, false, b6.getHash(), chainHeadHeight + 4, "b13"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b13.getTransactions().get(0).getHash()),
                b13.getTransactions().get(0).getOutputs().get(0).getValue(),
                b13.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));

        TransactionOutPointWithValue out5 = spendableOutputs.poll();

        Block b14 = createNextBlock(b13, chainHeadHeight + 6, out5, SATOSHI);
        // This will be "validly" added, though its actually invalid, it will just be marked orphan
        // and will be discarded when an attempt is made to reorg to it.
        // TODO: Use a WeakReference to check that it is freed properly after the reorg
        blocks.add(new BlockAndValidity(blockToHeightMap, b14, false, false, b6.getHash(), chainHeadHeight + 4, "b14"));
        // Make sure we dont die if an orphan gets added twice
        blocks.add(new BlockAndValidity(blockToHeightMap, b14, false, false, b6.getHash(), chainHeadHeight + 4, "b14"));
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b12, false, true, b13.getHash(), chainHeadHeight + 5, "b12"));
        
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
            Arrays.fill(outputScript, (byte) OP_CHECKSIG);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b15.getTransactions().get(1).getHash()),
                    SATOSHI, b15.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b15.addTransaction(tx);
        }
        b15.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b15, true, false, b15.getHash(), chainHeadHeight + 6, "b15"));
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
            Arrays.fill(outputScript, (byte) OP_CHECKSIG);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b16.getTransactions().get(1).getHash()),
                    SATOSHI, b16.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b16.addTransaction(tx);
        }
        b16.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b16, false, true, b15.getHash(), chainHeadHeight + 6, "b16"));
                
        // Attempt to spend a transaction created on a different fork
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b17 (6)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b17 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, new byte[] {}));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b3.getTransactions().get(1).getHash()),
                    SATOSHI, b3.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b17.addTransaction(tx);
        }
        b17.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b17, false, true, b15.getHash(), chainHeadHeight + 6, "b17"));
        
        // Attempt to spend a transaction created on a different fork (on a fork this time)
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5)
        //                                                                \-> b18 (5) -> b19 (6)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b18 = createNextBlock(b13, chainHeadHeight + 6, out5, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, new byte[] {}));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b3.getTransactions().get(1).getHash()),
                    SATOSHI, b3.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b18.addTransaction(tx);
        }
        b18.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b18, true, false, b15.getHash(), chainHeadHeight + 6, "b17"));
        
        Block b19 = createNextBlock(b18, chainHeadHeight + 7, out6, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b19, false, true, b15.getHash(), chainHeadHeight + 6, "b19"));
        
        // Attempt to spend a coinbase at depth too low
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5) -> b20 (7)
        //                      \-> b3 (1) -> b4 (2)
        //
        TransactionOutPointWithValue out7 = spendableOutputs.poll();

        Block b20 = createNextBlock(b15, chainHeadHeight + 7, out7, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b20, false, true, b15.getHash(), chainHeadHeight + 6, "b20"));
        
        // Attempt to spend a coinbase at depth too low (on a fork this time)
        //     genesis -> b1 (0) -> b2 (1) -> b5 (2) -> b6  (3)
        //                                          \-> b12 (3) -> b13 (4) -> b15 (5)
        //                                                                \-> b21 (6) -> b22 (5)
        //                      \-> b3 (1) -> b4 (2)
        //
        Block b21 = createNextBlock(b13, chainHeadHeight + 6, out6, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b21, true, false, b15.getHash(), chainHeadHeight + 6, "b21"));
        Block b22 = createNextBlock(b21, chainHeadHeight + 7, out5, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b22, false, true, b15.getHash(), chainHeadHeight + 6, "b22"));
        
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
            Arrays.fill(outputScript, (byte) OP_FALSE);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b23.getTransactions().get(1).getHash()),
                    SATOSHI, b23.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b23.addTransaction(tx);
        }
        b23.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b23, true, false, b23.getHash(), chainHeadHeight + 7, "b23"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b23.getTransactions().get(0).getHash()),
                b23.getTransactions().get(0).getOutputs().get(0).getValue(),
                b23.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        Block b24 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            Transaction tx = new Transaction(params);
            // Signature size is non-deterministic, so it may take several runs before finding any off-by-one errors
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIZE - b24.getMessageSize() - 135];
            Arrays.fill(outputScript, (byte) OP_FALSE);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b24.getTransactions().get(1).getHash()),
                    SATOSHI, b24.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b24.addTransaction(tx);
        }
        b24.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b24, false, true, b23.getHash(), chainHeadHeight + 7, "b24"));
        
        // Extend the b24 chain to make sure bitcoind isn't accepting b24
        Block b25 = createNextBlock(b24, chainHeadHeight + 8, out7, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b25, false, false, b23.getHash(), chainHeadHeight + 7, "b25"));
        
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
        blocks.add(new BlockAndValidity(blockToHeightMap, b26, false, true, b23.getHash(), chainHeadHeight + 7, "b26"));
        
        // Extend the b26 chain to make sure bitcoind isn't accepting b26
        Block b27 = createNextBlock(b26, chainHeadHeight + 8, out7, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b27, false, false, b23.getHash(), chainHeadHeight + 7, "b27"));
        
        Block b28 = createNextBlock(b15, chainHeadHeight + 7, out6, null);
        {
            byte[] coinbase = new byte[101];
            Arrays.fill(coinbase, (byte)0);
            b28.getTransactions().get(0).getInputs().get(0).setScriptBytes(coinbase);
        }
        b28.setMerkleRoot(null);
        b28.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b28, false, true, b23.getHash(), chainHeadHeight + 7, "b28"));
        
        // Extend the b28 chain to make sure bitcoind isn't accepting b28
        Block b29 = createNextBlock(b28, chainHeadHeight + 8, out7, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b29, false, false, b23.getHash(), chainHeadHeight + 7, "b29"));
        
        Block b30 = createNextBlock(b23, chainHeadHeight + 8, out7, null);
        {
            byte[] coinbase = new byte[100];
            Arrays.fill(coinbase, (byte)0);
            b30.getTransactions().get(0).getInputs().get(0).setScriptBytes(coinbase);
        }
        b30.setMerkleRoot(null);
        b30.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b30, true, false, b30.getHash(), chainHeadHeight + 8, "b30"));
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
            Arrays.fill(outputScript, (byte) OP_CHECKMULTISIG);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b31.getTransactions().get(1).getHash()),
                    SATOSHI, b31.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b31.addTransaction(tx);
        }
        b31.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b31, true, false, b31.getHash(), chainHeadHeight + 9, "b31"));
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
            Arrays.fill(outputScript, (byte) OP_CHECKMULTISIG);
            for (int i = 0; i < (Block.MAX_BLOCK_SIGOPS - sigOps)%20; i++)
                outputScript[i] = (byte) OP_CHECKSIG;
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b32.getTransactions().get(1).getHash()),
                    SATOSHI, b32.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b32.addTransaction(tx);
        }
        b32.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b32, false, true, b31.getHash(), chainHeadHeight + 9, "b32"));
        
        
        Block b33 = createNextBlock(b31, chainHeadHeight + 10, out9, null);
        {
            int sigOps = 0;
            for (Transaction tx : b33.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[(Block.MAX_BLOCK_SIGOPS - sigOps)/20];
            Arrays.fill(outputScript, (byte) OP_CHECKMULTISIGVERIFY);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b33.getTransactions().get(1).getHash()),
                    SATOSHI, b33.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b33.addTransaction(tx);
        }
        b33.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b33, true, false, b33.getHash(), chainHeadHeight + 10, "b33"));
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
            Arrays.fill(outputScript, (byte) OP_CHECKMULTISIGVERIFY);
            for (int i = 0; i < (Block.MAX_BLOCK_SIGOPS - sigOps)%20; i++)
                outputScript[i] = (byte) OP_CHECKSIG;
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b34.getTransactions().get(1).getHash()),
                    SATOSHI, b34.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b34.addTransaction(tx);
        }
        b34.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b34, false, true, b33.getHash(), chainHeadHeight + 10, "b34"));
        
        
        Block b35 = createNextBlock(b33, chainHeadHeight + 11, out10, null);
        {
            int sigOps = 0;
            for (Transaction tx : b35.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps];
            Arrays.fill(outputScript, (byte) OP_CHECKSIGVERIFY);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b35.getTransactions().get(1).getHash()),
                    SATOSHI, b35.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b35.addTransaction(tx);
        }
        b35.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b35, true, false, b35.getHash(), chainHeadHeight + 11, "b35"));
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
            Arrays.fill(outputScript, (byte) OP_CHECKSIGVERIFY);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b36.getTransactions().get(1).getHash()),
                    SATOSHI, b36.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b36.addTransaction(tx);
        }
        b36.solve();
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b36, false, true, b35.getHash(), chainHeadHeight + 11, "b36"));
        
        // Check spending of a transaction in a block which failed to connect
        // (test block store transaction abort handling, not that it should get this far if that's broken...)
        // 6  (3)
        // 12 (3) -> b13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10)
        //                                                                                     \-> b37 (11)
        //                                                                                     \-> b38 (11)
        //
        Block b37 = createNextBlock(b35, chainHeadHeight + 12, out11, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, new byte[] {}));
            addOnlyInputToTransaction(tx, out11); // double spend out11
            b37.addTransaction(tx);
        }
        b37.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b37, false, true, b35.getHash(), chainHeadHeight + 11, "b37"));
        
        Block b38 = createNextBlock(b35, chainHeadHeight + 12, out11, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, new byte[] {}));
            // Attempt to spend b37's first non-coinbase tx, at which point b37 was still considered valid
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b37.getTransactions().get(1).getHash()),
                    SATOSHI, b37.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b38.addTransaction(tx);
        }
        b38.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b38, false, true, b35.getHash(), chainHeadHeight + 11, "b38"));
        
        // Check P2SH SigOp counting
        // 13 (4) -> b15 (5) -> b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b41 (12)
        //                                                                                      \-> b40 (12)
        //
        // Create some P2SH outputs that will require 6 sigops to spend
        byte[] b39p2shScriptPubKey;
        int b39numP2SHOutputs = 0, b39sigOpsPerOutput = 6;
        Block b39 = createNextBlock(b35, chainHeadHeight + 12, null, null);
        {
            ByteArrayOutputStream p2shScriptPubKey = new UnsafeByteArrayOutputStream();
            try {
                Script.writeBytes(p2shScriptPubKey, coinbaseOutKeyPubKey);
                p2shScriptPubKey.write(OP_2DUP);
                p2shScriptPubKey.write(OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(OP_2DUP);
                p2shScriptPubKey.write(OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(OP_2DUP);
                p2shScriptPubKey.write(OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(OP_2DUP);
                p2shScriptPubKey.write(OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(OP_2DUP);
                p2shScriptPubKey.write(OP_CHECKSIGVERIFY);
                p2shScriptPubKey.write(OP_CHECKSIG);
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
            b39p2shScriptPubKey = p2shScriptPubKey.toByteArray();
            
            byte[] scriptHash = Utils.sha256hash160(b39p2shScriptPubKey);
            UnsafeByteArrayOutputStream scriptPubKey = new UnsafeByteArrayOutputStream(scriptHash.length + 3);
            scriptPubKey.write(OP_HASH160);
            try {
                Script.writeBytes(scriptPubKey, scriptHash);
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
            scriptPubKey.write(OP_EQUAL);
            
            Coin lastOutputValue = out11.value.subtract(SATOSHI);
            TransactionOutPoint lastOutPoint;
            {
                Transaction tx = new Transaction(params);
                tx.addOutput(new TransactionOutput(params, tx, SATOSHI, scriptPubKey.toByteArray()));
                tx.addOutput(new TransactionOutput(params, tx, lastOutputValue, new byte[]{OP_1}));
                addOnlyInputToTransaction(tx, out11);
                lastOutPoint = new TransactionOutPoint(params, 1, tx.getHash());
                b39.addTransaction(tx);
            }
            b39numP2SHOutputs++;
            
            while (b39.getMessageSize() < Block.MAX_BLOCK_SIZE)
            {
                Transaction tx = new Transaction(params);

                lastOutputValue = lastOutputValue.subtract(SATOSHI);
                tx.addOutput(new TransactionOutput(params, tx, SATOSHI, scriptPubKey.toByteArray()));
                tx.addOutput(new TransactionOutput(params, tx, lastOutputValue, new byte[]{OP_1}));
                tx.addInput(new TransactionInput(params, tx, new byte[]{OP_1}, lastOutPoint));
                lastOutPoint = new TransactionOutPoint(params, 1, tx.getHash());
                
                if (b39.getMessageSize() + tx.getMessageSize() < Block.MAX_BLOCK_SIZE) {
                    b39.addTransaction(tx);
                    b39numP2SHOutputs++;
                } else
                    break;
            }
        }
        b39.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b39, true, false, b39.getHash(), chainHeadHeight + 12, "b39"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b39.getTransactions().get(0).getHash()),
                b39.getTransactions().get(0).getOutputs().get(0).getValue(),
                b39.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out12 = spendableOutputs.poll();
        
        Block b40 = createNextBlock(b39, chainHeadHeight + 13, out12, null);
        {
            int sigOps = 0;
            for (Transaction tx : b40.transactions) {
                sigOps += tx.getSigOpCount();
            }
            
            int numTxes = (Block.MAX_BLOCK_SIGOPS - sigOps) / b39sigOpsPerOutput;
            checkState(numTxes <= b39numP2SHOutputs);
            
            TransactionOutPoint lastOutPoint = new TransactionOutPoint(params, 2, b40.getTransactions().get(1).getHash());
            
            byte[] scriptSig = null;
            for (int i = 1; i <= numTxes; i++) {
                Transaction tx = new Transaction(params);
                tx.addOutput(new TransactionOutput(params, tx, SATOSHI, new byte[] {OP_1}));
                tx.addInput(new TransactionInput(params, tx, new byte[]{OP_1}, lastOutPoint));
                
                TransactionInput input = new TransactionInput(params, tx, new byte[]{},
                        new TransactionOutPoint(params, 0, b39.getTransactions().get(i).getHash()));
                tx.addInput(input);

                if (scriptSig == null) {
                    // Exploit the SigHash.SINGLE bug to avoid having to make more than one signature
                    Sha256Hash hash = tx.hashForSignature(1, b39p2shScriptPubKey, SigHash.SINGLE, false);

                    // Sign input
                    try {
                        ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(73);
                        bos.write(coinbaseOutKey.sign(hash).encodeToDER());
                        bos.write(SigHash.SINGLE.ordinal() + 1);
                        byte[] signature = bos.toByteArray();

                        ByteArrayOutputStream scriptSigBos = new UnsafeByteArrayOutputStream(signature.length + b39p2shScriptPubKey.length + 3);
                        Script.writeBytes(scriptSigBos, new byte[] {(byte) OP_CHECKSIG});
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
            tx.addInput(new TransactionInput(params, tx, new byte[]{OP_1}, lastOutPoint));
            byte[] scriptPubKey = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + 1];
            Arrays.fill(scriptPubKey, (byte) OP_CHECKSIG);
            tx.addOutput(new TransactionOutput(params, tx, ZERO, scriptPubKey));
            b40.addTransaction(tx);
        }
        b40.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b40, false, true, b39.getHash(), chainHeadHeight + 12, "b40"));
        
        Block b41 = null;
        if (addSigExpensiveBlocks) {
            b41 = createNextBlock(b39, chainHeadHeight + 13, out12, null);
            {
                int sigOps = 0;
                for (Transaction tx : b41.transactions) {
                    sigOps += tx.getSigOpCount();
                }

                int numTxes = (Block.MAX_BLOCK_SIGOPS - sigOps)
                        / b39sigOpsPerOutput;
                checkState(numTxes <= b39numP2SHOutputs);

                TransactionOutPoint lastOutPoint = new TransactionOutPoint(
                        params, 2, b41.getTransactions().get(1).getHash());

                byte[] scriptSig = null;
                for (int i = 1; i <= numTxes; i++) {
                    Transaction tx = new Transaction(params);
                    tx.addOutput(new TransactionOutput(params, tx, Coin
                            .SATOSHI, new byte[] {OP_1}));
                    tx.addInput(new TransactionInput(params, tx,
                            new byte[] {OP_1}, lastOutPoint));

                    TransactionInput input = new TransactionInput(params, tx,
                            new byte[] {}, new TransactionOutPoint(params, 0,
                                    b39.getTransactions().get(i).getHash()));
                    tx.addInput(input);

                    if (scriptSig == null) {
                        // Exploit the SigHash.SINGLE bug to avoid having to make more than one signature
                        Sha256Hash hash = tx.hashForSignature(1,
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
                                    new byte[] { (byte) OP_CHECKSIG});
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
                        new byte[] {OP_1}, lastOutPoint));
                byte[] scriptPubKey = new byte[Block.MAX_BLOCK_SIGOPS - sigOps];
                Arrays.fill(scriptPubKey, (byte) OP_CHECKSIG);
                tx.addOutput(new TransactionOutput(params, tx, ZERO, scriptPubKey));
                b41.addTransaction(tx);
            }
            b41.solve();
            blocks.add(new BlockAndValidity(blockToHeightMap, b41, true, false, b41.getHash(), chainHeadHeight + 13, "b41"));
        }
        
        // Fork off of b39 to create a constant base again
        // b23 (6) -> b30 (7) -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13)
        //                                                                 \-> b41 (12)
        //
        Block b42 = createNextBlock(b39, chainHeadHeight + 13, out12, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b42, true, false, b41 == null ? b42.getHash() : b41.getHash(), chainHeadHeight + 13, "b42"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b42.getTransactions().get(0).getHash()),
                b42.getTransactions().get(0).getOutputs().get(0).getValue(),
                b42.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        TransactionOutPointWithValue out13 = spendableOutputs.poll();
        
        Block b43 = createNextBlock(b42, chainHeadHeight + 14, out13, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b43, true, false, b43.getHash(), chainHeadHeight + 14, "b43"));
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
        byte[] outScriptBytes = ScriptBuilder.createOutputScript(ECKey.fromPublicOnly(coinbaseOutKeyPubKey)).getProgram();
        {
            b44.setDifficultyTarget(b43.getDifficultyTarget());
            b44.addCoinbaseTransaction(coinbaseOutKeyPubKey, ZERO);
            
            Transaction t = new Transaction(params);
            // Entirely invalid scriptPubKey to ensure we aren't pre-verifying too much
            t.addOutput(new TransactionOutput(params, t, ZERO, new byte[] {OP_PUSHDATA1 - 1 }));
            t.addOutput(new TransactionOutput(params, t, SATOSHI, outScriptBytes));
            // Spendable output
            t.addOutput(new TransactionOutput(params, t, ZERO, new byte[] {OP_1}));
            addOnlyInputToTransaction(t, out14);
            b44.addTransaction(t);

            b44.setPrevBlockHash(b43.getHash());
            b44.setTime(b43.getTimeSeconds() + 1);
        }
        b44.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b44, true, false, b44.getHash(), chainHeadHeight + 15, "b44"));
        
        TransactionOutPointWithValue out15 = spendableOutputs.poll();
        
        // A block with a non-coinbase as the first tx
        Block b45 = new Block(params);
        {
            b45.setDifficultyTarget(b44.getDifficultyTarget());
            //b45.addCoinbaseTransaction(pubKey, coinbaseValue);
            
            Transaction t = new Transaction(params);
            // Entirely invalid scriptPubKey to ensure we aren't pre-verifying too much
            t.addOutput(new TransactionOutput(params, t, ZERO, new byte[] {OP_PUSHDATA1 - 1 }));
            t.addOutput(new TransactionOutput(params, t, SATOSHI, outScriptBytes));
            // Spendable output
            t.addOutput(new TransactionOutput(params, t, ZERO, new byte[] {OP_1}));
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
        blocks.add(new BlockAndValidity(blockToHeightMap, b45, false, true, b44.getHash(), chainHeadHeight + 15, "b45"));
        
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
        blocks.add(new BlockAndValidity(blockToHeightMap, b46, false, true, b44.getHash(), chainHeadHeight + 15, "b46"));
        
        // A block with invalid work
        Block b47 = createNextBlock(b44, chainHeadHeight + 16, out15, null);
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
        blocks.add(new BlockAndValidity(blockToHeightMap, b47, false, true, b44.getHash(), chainHeadHeight + 15, "b47"));
        
        // Block with timestamp > 2h in the future
        Block b48 = createNextBlock(b44, chainHeadHeight + 16, out15, null);
        b48.setTime(Utils.currentTimeSeconds() + 60*60*3);
        b48.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b48, false, true, b44.getHash(), chainHeadHeight + 15, "b48"));
        
        // Block with invalid merkle hash
        Block b49 = createNextBlock(b44, chainHeadHeight + 16, out15, null);
        b49.setMerkleRoot(Sha256Hash.ZERO_HASH);
        b49.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b49, false, true, b44.getHash(), chainHeadHeight + 15, "b49"));
        
        // Block with incorrect POW limit
        Block b50 = createNextBlock(b44, chainHeadHeight + 16, out15, null);
        {
            long diffTarget = b44.getDifficultyTarget();
            diffTarget &= 0xFFBFFFFF; // Make difficulty one bit harder
            b50.setDifficultyTarget(diffTarget);
        }
        b50.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b50, false, true, b44.getHash(), chainHeadHeight + 15, "b50"));
        
        // A block with two coinbase txn
        Block b51 = createNextBlock(b44, chainHeadHeight + 16, out15, null);
        {
            Transaction coinbase = new Transaction(params);
            coinbase.addInput(new TransactionInput(params, coinbase, new byte[]{(byte) 0xff, 110, 1}));
            coinbase.addOutput(new TransactionOutput(params, coinbase, SATOSHI, outScriptBytes));
            b51.addTransaction(coinbase, false);
        }
        b51.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b51, false, true, b44.getHash(), chainHeadHeight + 15, "b51"));
        
        // A block with duplicate txn
        Block b52 = createNextBlock(b44, chainHeadHeight + 16, out15, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, new byte[] {}));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b52.getTransactions().get(1).getHash()),
                    SATOSHI, b52.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b52.addTransaction(tx);
            b52.addTransaction(tx);
        }
        b52.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b52, false, true, b44.getHash(), chainHeadHeight + 15, "b52"));
        
        // Test block timestamp
        //  -> b31 (8) -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15)
        //                                                                                   \-> b54 (15)
        //                                                                       \-> b44 (14)
        //
        Block b53 = createNextBlock(b43, chainHeadHeight + 15, out14, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b53, true, false, b44.getHash(), chainHeadHeight + 15, "b53"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b53.getTransactions().get(0).getHash()),
                b53.getTransactions().get(0).getOutputs().get(0).getValue(),
                b53.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Block with invalid timestamp
        Block b54 = createNextBlock(b53, chainHeadHeight + 16, out15, null);
        b54.setTime(b35.getTimeSeconds() - 1);
        b54.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b54, false, true, b44.getHash(), chainHeadHeight + 15, "b54"));
        
        // Block with valid timestamp
        Block b55 = createNextBlock(b53, chainHeadHeight + 16, out15, null);
        b55.setTime(b35.getTimeSeconds());
        b55.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b55, true, false, b55.getHash(), chainHeadHeight + 16, "b55"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b55.getTransactions().get(0).getHash()),
                b55.getTransactions().get(0).getOutputs().get(0).getValue(),
                b55.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Test CVE-2012-2459
        // -> b33 (9) -> b35 (10) -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16)
        //                                                                                   \-> b56 (16)
        //
        TransactionOutPointWithValue out16 = spendableOutputs.poll();
        
        Block b57 = createNextBlock(b55, chainHeadHeight + 17, out16, null);
        Transaction b56txToDuplicate;
        {
            b56txToDuplicate = new Transaction(params);
            b56txToDuplicate.addOutput(new TransactionOutput(params, b56txToDuplicate, SATOSHI, new byte[] {}));
            addOnlyInputToTransaction(b56txToDuplicate, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b57.getTransactions().get(1).getHash()),
                    SATOSHI, b57.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
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
        checkState(b56.getHash().equals(b57.getHash()));
        blocks.add(new BlockAndValidity(blockToHeightMap, b56, false, true, b55.getHash(), chainHeadHeight + 16, "b56"));
        
        blocks.add(new BlockAndValidity(blockToHeightMap, b57, true, false, b57.getHash(), chainHeadHeight + 17, "b57"));
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
        Block b58 = createNextBlock(b57, chainHeadHeight + 18, out17, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx, ZERO, new byte[] {}));
            tx.addInput(new TransactionInput(params, tx, new byte[] {OP_1},
                    new TransactionOutPoint(params, 3, b58.getTransactions().get(1).getHash())));
            b58.addTransaction(tx);
        }
        b58.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b58, false, true, b57.getHash(), chainHeadHeight + 17, "b58"));
        
        // tx with output value > input value out of range
        Block b59 = createNextBlock(b57, chainHeadHeight + 18, out17, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(new TransactionOutput(params, tx,
                    b59.getTransactions().get(1).getOutputs().get(2).getValue().add(SATOSHI), new byte[] {}));
            tx.addInput(new TransactionInput(params, tx, new byte[] {OP_1},
                    new TransactionOutPoint(params, 2, b59.getTransactions().get(1).getHash())));
            b59.addTransaction(tx);
        }
        b59.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b59, false, true, b57.getHash(), chainHeadHeight + 17, "b59"));
        
        Block b60 = createNextBlock(b57, chainHeadHeight + 18, out17, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b60, true, false, b60.getHash(), chainHeadHeight + 18, "b60"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b60.getTransactions().get(0).getHash()),
                b60.getTransactions().get(0).getOutputs().get(0).getValue(),
                b60.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Test BIP30
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        //                                                                                    \-> b61 (18)
        //
        TransactionOutPointWithValue out18 = spendableOutputs.poll();
        
        Block b61 = createNextBlock(b60, chainHeadHeight + 19, out18, null);
        {
            b61.getTransactions().get(0).getInput(0).setScriptBytes(b60.getTransactions().get(0).getInput(0).getScriptBytes());
            b61.unCache();
            checkState(b61.getTransactions().get(0).equals(b60.getTransactions().get(0)));
        }
        b61.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b61, false, true, b60.getHash(), chainHeadHeight + 18, "b61"));
        
        // Test tx.isFinal is properly rejected (not an exhaustive tx.isFinal test, that should be in data-driven transaction tests)
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        //                                                                                    \-> b62 (18)
        //
        Block b62 = createNextBlock(b60, chainHeadHeight + 19, null, null);
        {
            Transaction tx = new Transaction(params);
            tx.setLockTime(0xffffffffL);
            tx.addOutput(ZERO, OP_TRUE_SCRIPT);
            addOnlyInputToTransaction(tx, out18, 0);
            b62.addTransaction(tx);
            checkState(!tx.isFinal(chainHeadHeight + 17, b62.getTimeSeconds()));
        }
        b62.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b62, false, true, b60.getHash(), chainHeadHeight + 18, "b62"));
        
        // Test a non-final coinbase is also rejected
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17)
        //                                                                                    \-> b63 (-)
        //
        Block b63 = createNextBlock(b60, chainHeadHeight + 19, null, null);
        {
            b63.getTransactions().get(0).setLockTime(0xffffffffL);
            b63.getTransactions().get(0).getInputs().get(0).setSequenceNumber(0xDEADBEEF);
            checkState(!b63.getTransactions().get(0).isFinal(chainHeadHeight + 17, b63.getTimeSeconds()));
        }
        b63.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b63, false, true, b60.getHash(), chainHeadHeight + 18, "b63"));
        
        // Check that a block which is (when properly encoded) <= MAX_BLOCK_SIZE is accepted
        // Even when it is encoded with varints that make its encoded size actually > MAX_BLOCK_SIZE
        // -> b39 (11) -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18)
        //
        Block b64;
        {
            Block b64Created = createNextBlock(b60, chainHeadHeight + 19, out18, null);
            Transaction tx = new Transaction(params);
            // Signature size is non-deterministic, so it may take several runs before finding any off-by-one errors
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIZE - b64Created.getMessageSize() - 138];
            Arrays.fill(outputScript, (byte) OP_FALSE);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b64Created.getTransactions().get(1).getHash()),
                    SATOSHI, b64Created.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b64Created.addTransaction(tx);
            b64Created.solve();
            
            UnsafeByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(b64Created.getMessageSize() + 8);
            b64Created.writeHeader(stream);
            
            byte[] varIntBytes = new byte[9];
            varIntBytes[0] = (byte) 255;
            Utils.uint32ToByteArrayLE((long)b64Created.getTransactions().size(), varIntBytes, 1);
            Utils.uint32ToByteArrayLE(((long)b64Created.getTransactions().size()) >>> 32, varIntBytes, 5);
            stream.write(varIntBytes);
            checkState(new VarInt(varIntBytes, 0).value == b64Created.getTransactions().size());
            
            for (Transaction transaction : b64Created.getTransactions())
                transaction.bitcoinSerialize(stream);
            b64 = new Block(params, stream.toByteArray(), false, true, stream.size());
            
            // The following checks are checking to ensure block serialization functions in the way needed for this test
            // If they fail, it is likely not an indication of error, but an indication that this test needs rewritten
            checkState(stream.size() == b64Created.getMessageSize() + 8);
            checkState(stream.size() == b64.getMessageSize());
            checkState(Arrays.equals(stream.toByteArray(), b64.bitcoinSerialize()));
            checkState(b64.getOptimalEncodingMessageSize() == b64Created.getMessageSize());
        }
        blocks.add(new BlockAndValidity(blockToHeightMap, b64, true, false, b64.getHash(), chainHeadHeight + 19, "b64"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b64.getTransactions().get(0).getHash()),
                b64.getTransactions().get(0).getOutputs().get(0).getValue(),
                b64.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Spend an output created in the block itself
        // -> b42 (12) -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        //
        TransactionOutPointWithValue out19 = spendableOutputs.poll();  checkState(out19 != null);//TODO preconditions all the way up
        
        Block b65 = createNextBlock(b64, chainHeadHeight + 20, null, null);
        {
            Transaction tx1 = new Transaction(params);
            tx1.addOutput(out19.value, OP_TRUE_SCRIPT);
            addOnlyInputToTransaction(tx1, out19, 0);
            b65.addTransaction(tx1);
            Transaction tx2 = new Transaction(params);
            tx2.addOutput(ZERO, OP_TRUE_SCRIPT);
            tx2.addInput(tx1.getHash(), 0, OP_TRUE_SCRIPT);
            b65.addTransaction(tx2);
        }
        b65.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b65, true, false, b65.getHash(), chainHeadHeight + 20, "b65"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b65.getTransactions().get(0).getHash()),
                b65.getTransactions().get(0).getOutputs().get(0).getValue(),
                b65.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Attempt to spend an output created later in the same block
        // -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        //                                                                                    \-> b66 (20)
        //
        TransactionOutPointWithValue out20 = spendableOutputs.poll();  checkState(out20 != null);
        
        Block b66 = createNextBlock(b65, chainHeadHeight + 21, null, null);
        {
            Transaction tx1 = new Transaction(params);
            tx1.addOutput(out20.value, OP_TRUE_SCRIPT);
            addOnlyInputToTransaction(tx1, out20, 0);
            Transaction tx2 = new Transaction(params);
            tx2.addOutput(ZERO, OP_TRUE_SCRIPT);
            tx2.addInput(tx1.getHash(), 0, OP_NOP_SCRIPT);
            b66.addTransaction(tx2);
            b66.addTransaction(tx1);
        }
        b66.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b66, false, true, b65.getHash(), chainHeadHeight + 20, "b66"));
        
        // Attempt to double-spend a transaction created in a block
        // -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19)
        //                                                                                    \-> b67 (20)
        //
        Block b67 = createNextBlock(b65, chainHeadHeight + 21, null, null);
        {
            Transaction tx1 = new Transaction(params);
            tx1.addOutput(out20.value, OP_TRUE_SCRIPT);
            addOnlyInputToTransaction(tx1, out20, 0);
            b67.addTransaction(tx1);
            Transaction tx2 = new Transaction(params);
            tx2.addOutput(ZERO, OP_TRUE_SCRIPT);
            tx2.addInput(tx1.getHash(), 0, OP_NOP_SCRIPT);
            b67.addTransaction(tx2);
            Transaction tx3 = new Transaction(params);
            tx3.addOutput(out20.value, OP_TRUE_SCRIPT);
            tx3.addInput(tx1.getHash(), 0, OP_NOP_SCRIPT);
            b67.addTransaction(tx3);
        }
        b67.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b67, false, true, b65.getHash(), chainHeadHeight + 20, "b67"));
        
        // A few more tests of block subsidy
        // -> b43 (13) -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20)
        //                                                                                    \-> b68 (20)
        //
        Block b68 = createNextBlock(b65, chainHeadHeight + 21, null, SATOSHI.multiply(10));
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(out20.value.subtract(Coin.valueOf(9)), OP_TRUE_SCRIPT);
            addOnlyInputToTransaction(tx, out20, 0);
            b68.addTransaction(tx);
        }
        b68.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b68, false, true, b65.getHash(), chainHeadHeight + 20, "b68"));
        
        Block b69 = createNextBlock(b65, chainHeadHeight + 21, null, SATOSHI.multiply(10));
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(out20.value.subtract(Coin.valueOf(10)), OP_TRUE_SCRIPT);
            addOnlyInputToTransaction(tx, out20, 0);
            b69.addTransaction(tx);
        }
        b69.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b69, true, false, b69.getHash(), chainHeadHeight + 21, "b69"));

        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b69.getTransactions().get(0).getHash()),
                b69.getTransactions().get(0).getOutputs().get(0).getValue(),
                b69.getTransactions().get(0).getOutputs().get(0).getScriptPubKey()));
        
        // Test spending the outpoint of a non-existent transaction
        // -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20)
        //                                                                                    \-> b70 (21)
        //
        TransactionOutPointWithValue out21 = spendableOutputs.poll();  checkState(out21 != null);
        Block b70 = createNextBlock(b69, chainHeadHeight + 22, out21, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(ZERO, OP_TRUE_SCRIPT);
            tx.addInput(new Sha256Hash("23c70ed7c0506e9178fc1a987f40a33946d4ad4c962b5ae3a52546da53af0c5c"), 0,
                    OP_NOP_SCRIPT);
            b70.addTransaction(tx);
        }
        b70.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b70, false, true, b69.getHash(), chainHeadHeight + 21, "b70"));
        
        // Test accepting an invalid block which has the same hash as a valid one (via merkle tree tricks)
        // -> b53 (14) -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20) -> b71 (21)
        //                                                                                    \-> b72 (21)
        //
        Block b72 = createNextBlock(b69, chainHeadHeight + 22, out21, null);
        {
            Transaction tx = new Transaction(params);
            tx.addOutput(ZERO, OP_TRUE_SCRIPT);
            final Transaction tx2 = b72.getTransactions().get(1);
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, tx2.getHash()),
                    SATOSHI, tx2.getOutput(1).getScriptPubKey()));
            b72.addTransaction(tx);
        }
        b72.solve();
        
        Block b71 = new Block(params, b72.bitcoinSerialize());
        b71.addTransaction(b72.getTransactions().get(2));
        checkState(b71.getHash().equals(b72.getHash()));
        blocks.add(new BlockAndValidity(blockToHeightMap, b71, false, true, b69.getHash(), chainHeadHeight + 21, "b71"));
        blocks.add(new BlockAndValidity(blockToHeightMap, b72, true, false, b72.getHash(), chainHeadHeight + 22, "b72"));

        final Transaction b72tx = b72.getTransactions().get(0);
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b72tx.getHash()),
                b72tx.getOutput(0).getValue(),
                b72tx.getOutput(0).getScriptPubKey()));

        // Have some fun with invalid scripts and MAX_BLOCK_SIGOPS
        // -> b55 (15) -> b57 (16) -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20) -> b72 (21)
        //                                                                                    \-> b** (22)
        //
        TransactionOutPointWithValue out22 = spendableOutputs.poll();  checkState(out22 != null);

        Block b73 = createNextBlock(b72, chainHeadHeight + 23, out22, null);
        {
            int sigOps = 0;
            for (Transaction tx : b73.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + (int)Script.MAX_SCRIPT_ELEMENT_SIZE + 1 + 5 + 1];
            Arrays.fill(outputScript, (byte) OP_CHECKSIG);
            // If we push an element that is too large, the CHECKSIGs after that push are still counted
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps] = OP_PUSHDATA4;
            Utils.uint32ToByteArrayLE(Script.MAX_SCRIPT_ELEMENT_SIZE + 1, outputScript, Block.MAX_BLOCK_SIGOPS - sigOps + 1);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b73.getTransactions().get(1).getHash()),
                    SATOSHI, b73.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b73.addTransaction(tx);
        }
        b73.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b73, false, true, b72.getHash(), chainHeadHeight + 22, "b73"));

        Block b74 = createNextBlock(b72, chainHeadHeight + 23, out22, null);
        {
            int sigOps = 0;
            for (Transaction tx : b74.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + (int)Script.MAX_SCRIPT_ELEMENT_SIZE + 42];
            Arrays.fill(outputScript, (byte) OP_CHECKSIG);
            // If we push an invalid element, all previous CHECKSIGs are counted
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 1] = OP_PUSHDATA4;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 2] = (byte)0xfe;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 3] = (byte)0xff;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 4] = (byte)0xff;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 5] = (byte)0xff;
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b74.getTransactions().get(1).getHash()),
                    SATOSHI, b74.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b74.addTransaction(tx);
        }
        b74.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b74, false, true, b72.getHash(), chainHeadHeight + 22, "b74"));

        Block b75 = createNextBlock(b72, chainHeadHeight + 23, out22, null);
        {
            int sigOps = 0;
            for (Transaction tx : b75.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + (int)Script.MAX_SCRIPT_ELEMENT_SIZE + 42];
            Arrays.fill(outputScript, (byte) OP_CHECKSIG);
            // If we push an invalid element, all subsequent CHECKSIGs are not counted
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps] = OP_PUSHDATA4;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 1] = (byte)0xff;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 2] = (byte)0xff;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 3] = (byte)0xff;
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps + 4] = (byte)0xff;
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b75.getTransactions().get(1).getHash()),
                    SATOSHI, b75.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b75.addTransaction(tx);
        }
        b75.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b75, true, false, b75.getHash(), chainHeadHeight + 23, "b75"));
        final Transaction b75tx = b75.getTransactions().get(0);
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b75tx.getHash()),
                b75tx.getOutput(0).getValue(),
                b75tx.getOutput(0).getScriptPubKey()));

        TransactionOutPointWithValue out23 = spendableOutputs.poll();  checkState(out23 != null);

        Block b76 = createNextBlock(b75, chainHeadHeight + 24, out23, null);
        {
            int sigOps = 0;
            for (Transaction tx : b76.transactions) {
                sigOps += tx.getSigOpCount();
            }
            Transaction tx = new Transaction(params);
            byte[] outputScript = new byte[Block.MAX_BLOCK_SIGOPS - sigOps + (int)Script.MAX_SCRIPT_ELEMENT_SIZE + 1 + 5];
            Arrays.fill(outputScript, (byte) OP_CHECKSIG);
            // If we push an element that is filled with CHECKSIGs, they (obviously) arent counted
            outputScript[Block.MAX_BLOCK_SIGOPS - sigOps] = OP_PUSHDATA4;
            Utils.uint32ToByteArrayLE(Block.MAX_BLOCK_SIGOPS, outputScript, Block.MAX_BLOCK_SIGOPS - sigOps + 1);
            tx.addOutput(new TransactionOutput(params, tx, SATOSHI, outputScript));
            addOnlyInputToTransaction(tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b76.getTransactions().get(1).getHash()),
                    SATOSHI, b76.getTransactions().get(1).getOutput(1).getScriptPubKey()));
            b76.addTransaction(tx);
        }
        b76.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b76, true, false, b76.getHash(), chainHeadHeight + 24, "b76"));
        final Transaction b76tx = b76.getTransactions().get(0);
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b76tx.getHash()),
                b76tx.getOutput(0).getValue(),
                b76tx.getOutput(0).getScriptPubKey()));

        // Test transaction resurrection
        // -> b77 (24) -> b78 (22) -> b79 (23)
        //            \-> b80 (22) -> b81 (23) -> b82 (24)
        // b78 creates a tx, which is spent in b79. after b82, both should be in mempool
        //
        TransactionOutPointWithValue out24 = checkNotNull(spendableOutputs.poll());
        TransactionOutPointWithValue out25 = checkNotNull(spendableOutputs.poll());
        TransactionOutPointWithValue out26 = checkNotNull(spendableOutputs.poll());
        TransactionOutPointWithValue out27 = checkNotNull(spendableOutputs.poll());

        Block b77 = createNextBlock(b76, chainHeadHeight + 25, out24, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b77, true, false, b77.getHash(), chainHeadHeight + 25, "b77"));

        Block b78 = createNextBlock(b77, chainHeadHeight + 26, out25, null);
        Transaction b78tx = new Transaction(params);
        {
            b78tx.addOutput(ZERO, OP_TRUE_SCRIPT);
            addOnlyInputToTransaction(b78tx, new TransactionOutPointWithValue(
                    new TransactionOutPoint(params, 1, b77.getTransactions().get(1).getHash()),
                    SATOSHI, b77.getTransactions().get(1).getOutputs().get(1).getScriptPubKey()));
            b78.addTransaction(b78tx);
        }
        b78.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b78, true, false, b78.getHash(), chainHeadHeight + 26, "b78"));

        Block b79 = createNextBlock(b78, chainHeadHeight + 27, out26, null);
        Transaction b79tx = new Transaction(params);

        {
            b79tx.addOutput(ZERO, OP_TRUE_SCRIPT);
            b79tx.addInput(b78tx.getHash(), 0, OP_NOP_SCRIPT);
            b79.addTransaction(b79tx);
        }
        b79.solve();
        blocks.add(new BlockAndValidity(blockToHeightMap, b79, true, false, b79.getHash(), chainHeadHeight + 27, "b79"));

        blocks.add(new MemoryPoolState(new HashSet<InventoryItem>(), "post-b79 empty mempool"));

        Block b80 = createNextBlock(b77, chainHeadHeight + 26, out25, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b80, true, false, b79.getHash(), chainHeadHeight + 27, "b80"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b80.getTransactions().get(0).getHash()),
                b80.getTransactions().get(0).getOutput(0).getValue(),
                b80.getTransactions().get(0).getOutput(0).getScriptPubKey()));

        Block b81 = createNextBlock(b80, chainHeadHeight + 27, out26, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b81, true, false, b79.getHash(), chainHeadHeight + 27, "b81"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b81.getTransactions().get(0).getHash()),
                b81.getTransactions().get(0).getOutput(0).getValue(),
                b81.getTransactions().get(0).getOutput(0).getScriptPubKey()));

        Block b82 = createNextBlock(b81, chainHeadHeight + 28, out27, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b82, true, false, b82.getHash(), chainHeadHeight + 28, "b82"));
        spendableOutputs.offer(new TransactionOutPointWithValue(
                new TransactionOutPoint(params, 0, b82.getTransactions().get(0).getHash()),
                b82.getTransactions().get(0).getOutput(0).getValue(),
                b82.getTransactions().get(0).getOutput(0).getScriptPubKey()));

        HashSet<InventoryItem> post82Mempool = new HashSet<InventoryItem>();
        post82Mempool.add(new InventoryItem(InventoryItem.Type.Transaction, b78tx.getHash()));
        post82Mempool.add(new InventoryItem(InventoryItem.Type.Transaction, b79tx.getHash()));
        blocks.add(new MemoryPoolState(post82Mempool, "post-b82 tx resurrection"));

        System.err.println("b78tx: " + b78tx);
        System.err.println("b79tx: " + b79tx);
        System.err.flush();

        // Check the UTXO query takes mempool into account.
        {
            TransactionOutPoint outpoint = new TransactionOutPoint(params, 0, b79tx.getHash());
            long[] heights = new long[] { UTXOsMessage.MEMPOOL_HEIGHT };
            UTXOsMessage result = new UTXOsMessage(params, ImmutableList.of(b79tx.getOutput(0)), heights, b82.getHash(), chainHeadHeight + 28);
            UTXORule utxo3 = new UTXORule("utxo3", outpoint, result);
            blocks.add(utxo3);
        }

        // The remaining tests arent designed to fit in the standard flow, and thus must always come last
        // Add new tests here.
        //TODO: Explicitly address MoneyRange() checks

        // Test massive reorgs (in terms of tx count)
        // -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20) -> b72 (21) -> b1001 (22) -> lots of outputs -> lots of spends
        // Reorg back to:
        // -> b60 (17) -> b64 (18) -> b65 (19) -> b69 (20) -> b72 (21) -> b1001 (22) -> empty blocks
        //
        TransactionOutPointWithValue out28 = spendableOutputs.poll();  checkState(out28 != null);

        Block b1001 = createNextBlock(b82, chainHeadHeight + 29, out28, null);
        blocks.add(new BlockAndValidity(blockToHeightMap, b1001, true, false, b1001.getHash(), chainHeadHeight + 29, "b1001"));
        int nextHeight = chainHeadHeight + 30;
        
        if (runLargeReorgs) {
            // No way you can fit this test in memory
            Preconditions.checkArgument(blockStorageFile != null);
            
            Block lastBlock = b1001;
            TransactionOutPoint lastOutput = new TransactionOutPoint(params, 2, b1001.getTransactions().get(1).getHash());
            int blockCountAfter1001;
            
            List<Sha256Hash> hashesToSpend = new LinkedList<Sha256Hash>(); // all index 0
            final int TRANSACTION_CREATION_BLOCKS = 100;
            for (blockCountAfter1001 = 0; blockCountAfter1001 < TRANSACTION_CREATION_BLOCKS; blockCountAfter1001++) {
                Block block = createNextBlock(lastBlock, nextHeight++, null, null);
                while (block.getMessageSize() < Block.MAX_BLOCK_SIZE - 500) {
                    Transaction tx = new Transaction(params);
                    tx.addInput(lastOutput.getHash(), lastOutput.getIndex(), OP_NOP_SCRIPT);
                    tx.addOutput(ZERO, OP_TRUE_SCRIPT);
                    tx.addOutput(ZERO, OP_TRUE_SCRIPT);
                    lastOutput = new TransactionOutPoint(params, 1, tx.getHash());
                    hashesToSpend.add(tx.getHash());
                    block.addTransaction(tx);
                }
                block.solve();
                blocks.add(new BlockAndValidity(blockToHeightMap, block, true, false, block.getHash(), nextHeight-1,
                                                "post-b1001 repeated transaction generator " + blockCountAfter1001 + "/" + TRANSACTION_CREATION_BLOCKS));
                lastBlock = block;
            }

            Iterator<Sha256Hash> hashes = hashesToSpend.iterator();
            for (int i = 0; hashes.hasNext(); i++) {
                Block block = createNextBlock(lastBlock, nextHeight++, null, null);
                while (block.getMessageSize() < Block.MAX_BLOCK_SIZE - 500 && hashes.hasNext()) {
                    Transaction tx = new Transaction(params);
                    tx.addInput(hashes.next(), 0, OP_NOP_SCRIPT);
                    tx.addOutput(ZERO, OP_TRUE_SCRIPT);
                    block.addTransaction(tx);
                }
                block.solve();
                blocks.add(new BlockAndValidity(blockToHeightMap, block, true, false, block.getHash(), nextHeight-1, "post-b1001 repeated transaction spender " + i));
                lastBlock = block;
                blockCountAfter1001++;
            }
            
            // Reorg back to b1001 + empty blocks
            Sha256Hash firstHash = lastBlock.getHash();
            int height = nextHeight-1;
            nextHeight = chainHeadHeight + 26;
            lastBlock = b1001;
            for (int i = 0; i < blockCountAfter1001; i++) {
                Block block = createNextBlock(lastBlock, nextHeight++, null, null);
                blocks.add(new BlockAndValidity(blockToHeightMap, block, true, false, firstHash, height, "post-b1001 empty reorg block " + i + "/" + blockCountAfter1001));
                lastBlock = block;
            }
            
            // Try to spend from the other chain
            Block b1002 = createNextBlock(lastBlock, nextHeight, null, null);
            {
                Transaction tx = new Transaction(params);
                tx.addInput(hashesToSpend.get(0), 0, OP_NOP_SCRIPT);
                tx.addOutput(ZERO, OP_TRUE_SCRIPT);
                b1002.addTransaction(tx);
            }
            b1002.solve();
            blocks.add(new BlockAndValidity(blockToHeightMap, b1002, false, true, firstHash, height, "b1002"));
            
            // Now actually reorg
            Block b1003 = createNextBlock(lastBlock, nextHeight, null, null);
            blocks.add(new BlockAndValidity(blockToHeightMap, b1003, true, false, b1003.getHash(), nextHeight, "b1003"));
            
            // Now try to spend again
            Block b1004 = createNextBlock(b1003, nextHeight+1, null, null);
            {
                Transaction tx = new Transaction(params);
                tx.addInput(hashesToSpend.get(0), 0, OP_NOP_SCRIPT);
                tx.addOutput(ZERO, OP_TRUE_SCRIPT);
                b1004.addTransaction(tx);
            }
            b1004.solve();
            blocks.add(new BlockAndValidity(blockToHeightMap, b1004, false, true, b1003.getHash(), nextHeight, "b1004"));
            
            ret.maximumReorgBlockCount = Math.max(ret.maximumReorgBlockCount, blockCountAfter1001);
        }
        
        if (outStream != null)
            outStream.close();
        
        // (finally) return the created chain
        return ret;
    }

    private byte uniquenessCounter = 0;
    private Block createNextBlock(Block baseBlock, int nextBlockHeight, @Nullable TransactionOutPointWithValue prevOut,
            Coin additionalCoinbaseValue) throws ScriptException {
        Integer height = blockToHeightMap.get(baseBlock.getHash());
        if (height != null)
            checkState(height == nextBlockHeight - 1);
        Coin coinbaseValue = FIFTY_COINS.shiftRight(nextBlockHeight / params.getSubsidyDecreaseBlockCount())
                .add((prevOut != null ? prevOut.value.subtract(SATOSHI) : ZERO))
                .add(additionalCoinbaseValue == null ? ZERO : additionalCoinbaseValue);
        Block block = baseBlock.createNextBlockWithCoinbase(coinbaseOutKeyPubKey, coinbaseValue);
        if (prevOut != null) {
            Transaction t = new Transaction(params);
            // Entirely invalid scriptPubKey to ensure we aren't pre-verifying too much
            t.addOutput(new TransactionOutput(params, t, ZERO, new byte[] {OP_PUSHDATA1 - 1 }));
            t.addOutput(new TransactionOutput(params, t, SATOSHI,
                    ScriptBuilder.createOutputScript(ECKey.fromPublicOnly(coinbaseOutKeyPubKey)).getProgram()));
            // Spendable output
            t.addOutput(new TransactionOutput(params, t, ZERO, new byte[] {OP_1, uniquenessCounter++}));
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

        if (prevOut.scriptPubKey.getChunks().get(0).equalsOpCode(OP_TRUE)) {
            input.setScriptSig(new ScriptBuilder().op(OP_1).build());
        } else {
            // Sign input
            checkState(prevOut.scriptPubKey.isSentToRawPubKey());
            Sha256Hash hash = t.hashForSignature(0, prevOut.scriptPubKey, SigHash.ALL, false);
            input.setScriptSig(ScriptBuilder.createInputScript(
                new TransactionSignature(coinbaseOutKey.sign(hash), SigHash.ALL, false))
            );
        }
    }
}
