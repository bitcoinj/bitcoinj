/*
 * Copyright 2012 Matt Corallo.
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

import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.VerifyFlag;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.FullPrunedBlockStore;
import org.bitcoinj.utils.*;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.concurrent.*;

import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A FullPrunedBlockChain works in conjunction with a {@link FullPrunedBlockStore} to verify all the rules of the
 * Bitcoin system, with the downside being a large cost in system resources. Fully verifying means all unspent
 * transaction outputs are stored. Once a transaction output is spent and that spend is buried deep enough, the data
 * related to it is deleted to ensure disk space usage doesn't grow forever. For this reason a pruning node cannot
 * serve the full block chain to other clients, but it nevertheless provides the same security guarantees as Bitcoin
 * Core does.</p>
 */
public class FullPrunedBlockChain extends AbstractBlockChain {
    private static final Logger log = LoggerFactory.getLogger(FullPrunedBlockChain.class);

    /**
     * Keeps a map of block hashes to StoredBlocks.
     */
    protected final FullPrunedBlockStore blockStore;

    // Whether or not to execute scriptPubKeys before accepting a transaction (i.e. check signatures).
    private boolean runScripts = true;

    /**
     * Constructs a block chain connected to the given wallet and store. To obtain a {@link Wallet} you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using
     * {@link Wallet#loadFromFile(File, WalletExtension...)}
     */
    public FullPrunedBlockChain(Context context, Wallet wallet, FullPrunedBlockStore blockStore) throws BlockStoreException {
        this(context, new ArrayList<Wallet>(), blockStore);
        addWallet(wallet);
    }

    /**
     * Constructs a block chain connected to the given wallet and store. To obtain a {@link Wallet} you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using
     * {@link Wallet#loadFromFile(File, WalletExtension...)}
     */
    public FullPrunedBlockChain(NetworkParameters params, Wallet wallet, FullPrunedBlockStore blockStore) throws BlockStoreException {
        this(Context.getOrCreate(params), wallet, blockStore);
    }

    /**
     * Constructs a block chain connected to the given store.
     */
    public FullPrunedBlockChain(Context context, FullPrunedBlockStore blockStore) throws BlockStoreException {
        this(context, new ArrayList<Wallet>(), blockStore);
    }

    /**
     * See {@link #FullPrunedBlockChain(Context, Wallet, FullPrunedBlockStore)}
     */
    public FullPrunedBlockChain(NetworkParameters params, FullPrunedBlockStore blockStore) throws BlockStoreException {
        this(Context.getOrCreate(params), blockStore);
    }

    /**
     * Constructs a block chain connected to the given list of wallets and a store.
     */
    public FullPrunedBlockChain(Context context, List<Wallet> listeners, FullPrunedBlockStore blockStore) throws BlockStoreException {
        super(context, listeners, blockStore);
        this.blockStore = blockStore;
        // Ignore upgrading for now
        this.chainHead = blockStore.getVerifiedChainHead();
    }

    /**
     * See {@link #FullPrunedBlockChain(Context, List, FullPrunedBlockStore)}
     */
    public FullPrunedBlockChain(NetworkParameters params, List<Wallet> listeners,
                                FullPrunedBlockStore blockStore) throws BlockStoreException {
        this(Context.getOrCreate(params), listeners, blockStore);
    }

    @Override
    protected StoredBlock addToBlockStore(StoredBlock storedPrev, Block header, TransactionOutputChanges txOutChanges)
            throws BlockStoreException, VerificationException {
        StoredBlock newBlock = storedPrev.build(header);
        blockStore.put(newBlock, new StoredUndoableBlock(newBlock.getHeader().getHash(), txOutChanges));
        return newBlock;
    }

    @Override
    protected StoredBlock addToBlockStore(StoredBlock storedPrev, Block block)
            throws BlockStoreException, VerificationException {
        StoredBlock newBlock = storedPrev.build(block);
        blockStore.put(newBlock, new StoredUndoableBlock(newBlock.getHeader().getHash(), block.transactions));
        return newBlock;
    }

    @Override
    protected void rollbackBlockStore(int height) throws BlockStoreException {
        throw new BlockStoreException("Unsupported");
    }

    @Override
    protected boolean shouldVerifyTransactions() {
        return true;
    }

    /**
     * Whether or not to run scripts whilst accepting blocks (i.e. checking signatures, for most transactions).
     * If you're accepting data from an untrusted node, such as one found via the P2P network, this should be set
     * to true (which is the default). If you're downloading a chain from a node you control, script execution
     * is redundant because you know the connected node won't relay bad data to you. In that case it's safe to set
     * this to false and obtain a significant speedup.
     */
    public void setRunScripts(boolean value) {
        this.runScripts = value;
    }

    // TODO: Remove lots of duplicated code in the two connectTransactions

    // TODO: execute in order of largest transaction (by input count) first
    ExecutorService scriptVerificationExecutor = Executors.newFixedThreadPool(
            Runtime.getRuntime().availableProcessors(), new ContextPropagatingThreadFactory("Script verification"));

    /**
     * A job submitted to the executor which verifies signatures.
     */
    private static class Verifier implements Callable<VerificationException> {
        final Transaction tx;
        final List<Script> prevOutScripts;
        final Set<VerifyFlag> verifyFlags;

        public Verifier(final Transaction tx, final List<Script> prevOutScripts, final Set<VerifyFlag> verifyFlags) {
            this.tx = tx;
            this.prevOutScripts = prevOutScripts;
            this.verifyFlags = verifyFlags;
        }

        @Nullable
        @Override
        public VerificationException call() throws Exception {
            try {
                ListIterator<Script> prevOutIt = prevOutScripts.listIterator();
                for (int index = 0; index < tx.getInputs().size(); index++) {
                    tx.getInputs().get(index).getScriptSig().correctlySpends(tx, index, prevOutIt.next(), verifyFlags);
                }
            } catch (VerificationException e) {
                return e;
            }
            return null;
        }
    }

    /**
     * Get the {@link Script} from the script bytes or return Script of empty byte array.
     */
    private Script getScript(byte[] scriptBytes) {
        try {
            return new Script(scriptBytes);
        } catch (Exception e) {
            return new Script(new byte[0]);
        }
    }

    /**
     * Get the address from the {@link Script} if it exists otherwise return empty string "".
     *
     * @param script The script.
     * @return The address.
     */
    private String getScriptAddress(@Nullable Script script) {
        String address = "";
        try {
            if (script != null) {
                address = script.getToAddress(params, true).toString();
            }
        } catch (Exception e) {
        }
        return address;
    }

    @Override
    protected TransactionOutputChanges connectTransactions(int height, Block block)
            throws VerificationException, BlockStoreException {
        checkState(lock.isHeldByCurrentThread());
        if (block.transactions == null)
            throw new RuntimeException("connectTransactions called with Block that didn't have transactions!");
        if (!params.passesCheckpoint(height, block.getHash()))
            throw new VerificationException("Block failed checkpoint lockin at " + height);

        blockStore.beginDatabaseBatchWrite();

        LinkedList<UTXO> txOutsSpent = new LinkedList<>();
        LinkedList<UTXO> txOutsCreated = new LinkedList<>();
        long sigOps = 0;

        if (scriptVerificationExecutor.isShutdown())
            scriptVerificationExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        List<Future<VerificationException>> listScriptVerificationResults = new ArrayList<>(block.transactions.size());
        try {
            if (!params.isCheckpoint(height)) {
                // BIP30 violator blocks are ones that contain a duplicated transaction. They are all in the
                // checkpoints list and we therefore only check non-checkpoints for duplicated transactions here. See the
                // BIP30 document for more details on this: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
                for (Transaction tx : block.transactions) {
                    final Set<VerifyFlag> verifyFlags = params.getTransactionVerificationFlags(block, tx, getVersionTally(), height);
                    Sha256Hash hash = tx.getHash();
                    // If we already have unspent outputs for this hash, we saw the tx already. Either the block is
                    // being added twice (bug) or the block is a BIP30 violator.
                    if (blockStore.hasUnspentOutputs(hash, tx.getOutputs().size()))
                        throw new VerificationException("Block failed BIP30 test!");
                    if (verifyFlags.contains(VerifyFlag.P2SH)) // We already check non-BIP16 sigops in Block.verifyTransactions(true)
                        sigOps += tx.getSigOpCount();
                }
            }
            Coin totalFees = Coin.ZERO;
            Coin coinbaseValue = null;
            for (final Transaction tx : block.transactions) {
                boolean isCoinBase = tx.isCoinBase();
                Coin valueIn = Coin.ZERO;
                Coin valueOut = Coin.ZERO;
                final List<Script> prevOutScripts = new LinkedList<>();
                final Set<VerifyFlag> verifyFlags = params.getTransactionVerificationFlags(block, tx, getVersionTally(), height);
                if (!isCoinBase) {
                    // For each input of the transaction remove the corresponding output from the set of unspent
                    // outputs.
                    for (int index = 0; index < tx.getInputs().size(); index++) {
                        TransactionInput in = tx.getInputs().get(index);
                        UTXO prevOut = blockStore.getTransactionOutput(in.getOutpoint().getHash(),
                                in.getOutpoint().getIndex());
                        if (prevOut == null)
                            throw new VerificationException("Attempted to spend a non-existent or already spent output!");
                        // Coinbases can't be spent until they mature, to avoid re-orgs destroying entire transaction
                        // chains. The assumption is there will ~never be re-orgs deeper than the spendable coinbase
                        // chain depth.
                        if (prevOut.isCoinbase()) {
                            if (height - prevOut.getHeight() < params.getSpendableCoinbaseDepth()) {
                                throw new VerificationException("Tried to spend coinbase at depth " + (height - prevOut.getHeight()));
                            }
                        }
                        // TODO: Check we're not spending the genesis transaction here. Bitcoin Core won't allow it.
                        valueIn = valueIn.add(prevOut.getValue());
                        if (verifyFlags.contains(VerifyFlag.P2SH)) {
                            if (ScriptPattern.isPayToScriptHash(prevOut.getScript()))
                                sigOps += Script.getP2SHSigOpCount(in.getScriptBytes());
                            if (sigOps > Block.MAX_BLOCK_SIGOPS)
                                throw new VerificationException("Too many P2SH SigOps in block");
                        }

                        prevOutScripts.add(prevOut.getScript());
                        blockStore.removeUnspentTransactionOutput(prevOut);
                        txOutsSpent.add(prevOut);
                    }
                }
                Sha256Hash hash = tx.getHash();
                for (TransactionOutput out : tx.getOutputs()) {
                    valueOut = valueOut.add(out.getValue());
                    // For each output, add it to the set of unspent outputs so it can be consumed in future.
                    Script script = getScript(out.getScriptBytes());
                    UTXO newOut = new UTXO(hash,
                            out.getIndex(),
                            out.getValue(),
                            height, isCoinBase,
                            script,
                            getScriptAddress(script));
                    blockStore.addUnspentTransactionOutput(newOut);
                    txOutsCreated.add(newOut);
                }
                // All values were already checked for being non-negative (as it is verified in Transaction.verify())
                // but we check again here just for defence in depth. Transactions with zero output value are OK.
                if (valueOut.signum() < 0 || valueOut.compareTo(params.getMaxMoney()) > 0)
                    throw new VerificationException("Transaction output value out of range");
                if (isCoinBase) {
                    coinbaseValue = valueOut;
                } else {
                    if (valueIn.compareTo(valueOut) < 0 || valueIn.compareTo(params.getMaxMoney()) > 0)
                        throw new VerificationException("Transaction input value out of range");
                    totalFees = totalFees.add(valueIn.subtract(valueOut));
                }

                if (!isCoinBase && runScripts) {
                    // Because correctlySpends modifies transactions, this must come after we are done with tx
                    FutureTask<VerificationException> future = new FutureTask<>(new Verifier(tx, prevOutScripts, verifyFlags));
                    scriptVerificationExecutor.execute(future);
                    listScriptVerificationResults.add(future);
                }
            }
            if (totalFees.compareTo(params.getMaxMoney()) > 0 || block.getBlockInflation(height).add(totalFees).compareTo(coinbaseValue) < 0)
                throw new VerificationException("Transaction fees out of range");
            for (Future<VerificationException> future : listScriptVerificationResults) {
                VerificationException e;
                try {
                    e = future.get();
                } catch (InterruptedException thrownE) {
                    throw new RuntimeException(thrownE); // Shouldn't happen
                } catch (ExecutionException thrownE) {
                    log.error("Script.correctlySpends threw a non-normal exception: " + thrownE.getCause());
                    throw new VerificationException("Bug in Script.correctlySpends, likely script malformed in some new and interesting way.", thrownE);
                }
                if (e != null)
                    throw e;
            }
        } catch (VerificationException e) {
            scriptVerificationExecutor.shutdownNow();
            blockStore.abortDatabaseBatchWrite();
            throw e;
        } catch (BlockStoreException e) {
            scriptVerificationExecutor.shutdownNow();
            blockStore.abortDatabaseBatchWrite();
            throw e;
        }
        return new TransactionOutputChanges(txOutsCreated, txOutsSpent);
    }

    /**
     * Used during reorgs to connect a block previously on a fork
     */
    @Override
    protected synchronized TransactionOutputChanges connectTransactions(StoredBlock newBlock)
            throws VerificationException, BlockStoreException, PrunedException {
        checkState(lock.isHeldByCurrentThread());
        if (!params.passesCheckpoint(newBlock.getHeight(), newBlock.getHeader().getHash()))
            throw new VerificationException("Block failed checkpoint lockin at " + newBlock.getHeight());

        blockStore.beginDatabaseBatchWrite();
        StoredUndoableBlock block = blockStore.getUndoBlock(newBlock.getHeader().getHash());
        if (block == null) {
            // We're trying to re-org too deep and the data needed has been deleted.
            blockStore.abortDatabaseBatchWrite();
            throw new PrunedException(newBlock.getHeader().getHash());
        }
        TransactionOutputChanges txOutChanges;
        try {
            List<Transaction> transactions = block.getTransactions();
            if (transactions != null) {
                LinkedList<UTXO> txOutsSpent = new LinkedList<>();
                LinkedList<UTXO> txOutsCreated = new LinkedList<>();
                long sigOps = 0;

                if (!params.isCheckpoint(newBlock.getHeight())) {
                    for (Transaction tx : transactions) {
                        Sha256Hash hash = tx.getHash();
                        if (blockStore.hasUnspentOutputs(hash, tx.getOutputs().size()))
                            throw new VerificationException("Block failed BIP30 test!");
                    }
                }
                Coin totalFees = Coin.ZERO;
                Coin coinbaseValue = null;

                if (scriptVerificationExecutor.isShutdown())
                    scriptVerificationExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
                List<Future<VerificationException>> listScriptVerificationResults = new ArrayList<>(transactions.size());
                for (final Transaction tx : transactions) {
                    final Set<VerifyFlag> verifyFlags =
                        params.getTransactionVerificationFlags(newBlock.getHeader(), tx, getVersionTally(), Integer.SIZE);
                    boolean isCoinBase = tx.isCoinBase();
                    Coin valueIn = Coin.ZERO;
                    Coin valueOut = Coin.ZERO;
                    final List<Script> prevOutScripts = new LinkedList<>();

                    if (!isCoinBase) {
                        for (int index = 0; index < tx.getInputs().size(); index++) {
                            final TransactionInput in = tx.getInputs().get(index);
                            final UTXO prevOut = blockStore.getTransactionOutput(in.getOutpoint().getHash(),
                                    in.getOutpoint().getIndex());
                            if (prevOut == null)
                                throw new VerificationException("Attempted spend of a non-existent or already spent output!");
                            if (prevOut.isCoinbase() && newBlock.getHeight() - prevOut.getHeight() < params.getSpendableCoinbaseDepth())
                                throw new VerificationException("Tried to spend coinbase at depth " + (newBlock.getHeight() - prevOut.getHeight()));
                            valueIn = valueIn.add(prevOut.getValue());
                            if (verifyFlags.contains(VerifyFlag.P2SH)) {
                                if (ScriptPattern.isPayToScriptHash(prevOut.getScript()))
                                    sigOps += Script.getP2SHSigOpCount(in.getScriptBytes());
                                if (sigOps > Block.MAX_BLOCK_SIGOPS)
                                    throw new VerificationException("Too many P2SH SigOps in block");
                            }

                            // TODO: Enforce DER signature format

                            prevOutScripts.add(prevOut.getScript());

                            blockStore.removeUnspentTransactionOutput(prevOut);
                            txOutsSpent.add(prevOut);
                        }
                    }
                    Sha256Hash hash = tx.getHash();
                    for (TransactionOutput out : tx.getOutputs()) {
                        valueOut = valueOut.add(out.getValue());
                        Script script = getScript(out.getScriptBytes());
                        UTXO newOut = new UTXO(hash,
                                out.getIndex(),
                                out.getValue(),
                                newBlock.getHeight(),
                                isCoinBase,
                                script,
                                getScriptAddress(script));
                        blockStore.addUnspentTransactionOutput(newOut);
                        txOutsCreated.add(newOut);
                    }
                    // All values were already checked for being non-negative (as it is verified in Transaction.verify())
                    // but we check again here just for defence in depth. Transactions with zero output value are OK.
                    if (valueOut.signum() < 0 || valueOut.compareTo(params.getMaxMoney()) > 0)
                        throw new VerificationException("Transaction output value out of range");
                    if (isCoinBase) {
                        coinbaseValue = valueOut;
                    } else {
                        if (valueIn.compareTo(valueOut) < 0 || valueIn.compareTo(params.getMaxMoney()) > 0)
                            throw new VerificationException("Transaction input value out of range");
                        totalFees = totalFees.add(valueIn.subtract(valueOut));
                    }

                    if (!isCoinBase) {
                        // Because correctlySpends modifies transactions, this must come after we are done with tx
                        FutureTask<VerificationException> future = new FutureTask<>(new Verifier(tx, prevOutScripts, verifyFlags));
                        scriptVerificationExecutor.execute(future);
                        listScriptVerificationResults.add(future);
                    }
                }
                if (totalFees.compareTo(params.getMaxMoney()) > 0 ||
                        newBlock.getHeader().getBlockInflation(newBlock.getHeight()).add(totalFees).compareTo(coinbaseValue) < 0)
                    throw new VerificationException("Transaction fees out of range");
                txOutChanges = new TransactionOutputChanges(txOutsCreated, txOutsSpent);
                for (Future<VerificationException> future : listScriptVerificationResults) {
                    VerificationException e;
                    try {
                        e = future.get();
                    } catch (InterruptedException thrownE) {
                        throw new RuntimeException(thrownE); // Shouldn't happen
                    } catch (ExecutionException thrownE) {
                        log.error("Script.correctlySpends threw a non-normal exception: " + thrownE.getCause());
                        throw new VerificationException("Bug in Script.correctlySpends, likely script malformed in some new and interesting way.", thrownE);
                    }
                    if (e != null)
                        throw e;
                }
            } else {
                txOutChanges = block.getTxOutChanges();
                if (!params.isCheckpoint(newBlock.getHeight()))
                    for (UTXO out : txOutChanges.txOutsCreated) {
                        Sha256Hash hash = out.getHash();
                        if (blockStore.getTransactionOutput(hash, out.getIndex()) != null)
                            throw new VerificationException("Block failed BIP30 test!");
                    }
                for (UTXO out : txOutChanges.txOutsCreated)
                    blockStore.addUnspentTransactionOutput(out);
                for (UTXO out : txOutChanges.txOutsSpent)
                    blockStore.removeUnspentTransactionOutput(out);
            }
        } catch (VerificationException e) {
            scriptVerificationExecutor.shutdownNow();
            blockStore.abortDatabaseBatchWrite();
            throw e;
        } catch (BlockStoreException e) {
            scriptVerificationExecutor.shutdownNow();
            blockStore.abortDatabaseBatchWrite();
            throw e;
        }
        return txOutChanges;
    }

    /**
     * This is broken for blocks that do not pass BIP30, so all BIP30-failing blocks which are allowed to fail BIP30
     * must be checkpointed.
     */
    @Override
    protected void disconnectTransactions(StoredBlock oldBlock) throws PrunedException, BlockStoreException {
        checkState(lock.isHeldByCurrentThread());
        blockStore.beginDatabaseBatchWrite();
        try {
            StoredUndoableBlock undoBlock = blockStore.getUndoBlock(oldBlock.getHeader().getHash());
            if (undoBlock == null) throw new PrunedException(oldBlock.getHeader().getHash());
            TransactionOutputChanges txOutChanges = undoBlock.getTxOutChanges();
            for (UTXO out : txOutChanges.txOutsSpent)
                blockStore.addUnspentTransactionOutput(out);
            for (UTXO out : txOutChanges.txOutsCreated)
                blockStore.removeUnspentTransactionOutput(out);
        } catch (PrunedException e) {
            blockStore.abortDatabaseBatchWrite();
            throw e;
        } catch (BlockStoreException e) {
            blockStore.abortDatabaseBatchWrite();
            throw e;
        }
    }

    @Override
    protected void doSetChainHead(StoredBlock chainHead) throws BlockStoreException {
        checkState(lock.isHeldByCurrentThread());
        blockStore.setVerifiedChainHead(chainHead);
        blockStore.commitDatabaseBatchWrite();
    }

    @Override
    protected void notSettingChainHead() throws BlockStoreException {
        blockStore.abortDatabaseBatchWrite();
    }

    @Override
    protected StoredBlock getStoredBlockInCurrentScope(Sha256Hash hash) throws BlockStoreException {
        checkState(lock.isHeldByCurrentThread());
        return blockStore.getOnceUndoableStoredBlock(hash);
    }
}
