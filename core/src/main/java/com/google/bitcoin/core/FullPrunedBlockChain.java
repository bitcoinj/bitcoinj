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

import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.FullPrunedBlockStore;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * <p>A FullPrunedBlockChain works in conjunction with a {@link FullPrunedBlockStore} to provide a fully verifying
 * block chain. Fully verifying means all unspent transaction outputs are stored. Once a transaction output is spent
 * and that spend is buried deep enough, the data related to is deleted to ensure disk space usage doesn't grow
 * forever. For this reason a pruning node cannot serve the full block chain to other clients, but it nevertheless
 * provides the same security guarantees as a regular Satoshi client does.</p>
 */
public class FullPrunedBlockChain extends AbstractBlockChain {    
    /** Keeps a map of block hashes to StoredBlocks. */
    protected final FullPrunedBlockStore blockStore;

    /**
     * Constructs a BlockChain connected to the given wallet and store. To obtain a {@link Wallet} you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using {@link Wallet#loadFromFile(java.io.File)}
     */
    public FullPrunedBlockChain(NetworkParameters params, Wallet wallet, FullPrunedBlockStore blockStore) throws BlockStoreException {
        this(params, new ArrayList<Wallet>(), blockStore);
        if (wallet != null)
            addWallet(wallet);
    }

    /**
     * Constructs a BlockChain that has no wallet at all. This is helpful when you don't actually care about sending
     * and receiving coins but rather, just want to explore the network data structures.
     */
    public FullPrunedBlockChain(NetworkParameters params, FullPrunedBlockStore blockStore) throws BlockStoreException {
        this(params, new ArrayList<Wallet>(), blockStore);
    }

    /**
     * Constructs a BlockChain connected to the given list of wallets and a store.
     */
    public FullPrunedBlockChain(NetworkParameters params, List<Wallet> wallets,
                                FullPrunedBlockStore blockStore) throws BlockStoreException {
        super(params, wallets, blockStore);
        this.blockStore = blockStore;
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
        LinkedList<StoredTransaction> transactions = new LinkedList<StoredTransaction>();
        for (Transaction tx : block.transactions)
            transactions.add(new StoredTransaction(tx, newBlock.getHeight()));
        blockStore.put(newBlock, new StoredUndoableBlock(newBlock.getHeader().getHash(), transactions));
        return newBlock;
    }

    @Override
    protected boolean shouldVerifyTransactions() {
        return true;
    }
    
    //TODO: Remove lots of duplicated code in the two connectTransactions
    //TODO: More checking can be done here (eg spent-coinbase depth check)
    
    @Override
    protected TransactionOutputChanges connectTransactions(int height, Block block)
            throws VerificationException, BlockStoreException {
        if (block.transactions == null)
            throw new RuntimeException("connectTransactions called with Block that didn't have transactions!");
        if (!params.passesCheckpoint(height, block.getHash()))
            throw new VerificationException("Block failed checkpoint lockin at " + height);

        blockStore.beginDatabaseBatchWrite();

        LinkedList<StoredTransactionOutput> txOutsSpent = new LinkedList<StoredTransactionOutput>();
        LinkedList<StoredTransactionOutput> txOutsCreated = new LinkedList<StoredTransactionOutput>();        
        try {
            if (!params.isCheckpoint(height)) {
                // BIP30 violator blocks are ones that contain a duplicated transaction. They are all in the
                // checkpoints list and we therefore only check non-checkpoints for duplicated transactions here. See the
                // BIP30 document for more details on this: https://en.bitcoin.it/wiki/BIP_0030
                for (Transaction tx : block.transactions) {
                    Sha256Hash hash = tx.getHash();
                    // If we already have unspent outputs for this hash, we saw the tx already. Either the block is
                    // being added twice (bug) or the block is a BIP30 violator.
                    if (blockStore.hasUnspentOutputs(hash, tx.getOutputs().size()))
                        throw new VerificationException("Block failed BIP30 test!");
                }
            }
            for (Transaction tx : block.transactions) {
                boolean isCoinBase = tx.isCoinBase();
                if (!isCoinBase) {
                    // For each input of the transaction remove the corresponding output from the set of unspent
                    // outputs.
                    for (TransactionInput in : tx.getInputs()) {
                        StoredTransactionOutput prevOut = blockStore.getTransactionOutput(in.getOutpoint().getHash(),
                                                                                          in.getOutpoint().getIndex());
                        if (prevOut == null)
                            throw new VerificationException("Attempted to spend a non-existent or already spent output!");
                        // TODO: Check we're not spending the genesis transaction here. Satoshis code won't allow it.
                        //TODO: check script here
                        blockStore.removeUnspentTransactionOutput(prevOut);
                        txOutsSpent.add(prevOut);
                    }
                }
                Sha256Hash hash = tx.getHash();
                for (TransactionOutput out : tx.getOutputs()) {
                    // For each output, add it to the set of unspent outputs so it can be consumed in future.
                    StoredTransactionOutput newOut = new StoredTransactionOutput(hash, out.getIndex(), out.getValue(),
                            height, isCoinBase, out.getScriptBytes());
                    blockStore.addUnspentTransactionOutput(newOut);
                    txOutsCreated.add(newOut);
                }
            }
        } catch (VerificationException e) {
            blockStore.abortDatabaseBatchWrite();
            throw e;
        } catch (BlockStoreException e) {
            blockStore.abortDatabaseBatchWrite();
            throw e;
        }
        return new TransactionOutputChanges(txOutsCreated, txOutsSpent);
    }
    
    @Override
    /**
     * Used during reorgs to connect a block previously on a fork
     */
    protected TransactionOutputChanges connectTransactions(StoredBlock newBlock)
            throws VerificationException, BlockStoreException, PrunedException {
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
            List<StoredTransaction> transactions = block.getTransactions();
            if (transactions != null) {
                LinkedList<StoredTransactionOutput> txOutsSpent = new LinkedList<StoredTransactionOutput>();
                LinkedList<StoredTransactionOutput> txOutsCreated = new LinkedList<StoredTransactionOutput>();
                if (!params.isCheckpoint(newBlock.getHeight())) {
                    // See explanation above.
                    for(StoredTransaction tx : transactions) {
                        Sha256Hash hash = tx.getHash();
                        if (blockStore.hasUnspentOutputs(hash, tx.getOutputs().size()))
                            throw new VerificationException("Block failed BIP30 test!");
                    }
                }
                for (StoredTransaction tx : transactions) {
                    boolean isCoinBase = tx.isCoinBase();
                    if (!isCoinBase)
                        for(TransactionInput in : tx.getInputs()) {
                            StoredTransactionOutput prevOut = blockStore.getTransactionOutput(in.getOutpoint().getHash(),
                                                                                              in.getOutpoint().getIndex());
                            if (prevOut == null)
                                throw new VerificationException("Attempted spend of a non-existent or already spent output!");
                            //TODO: check script here
                            blockStore.removeUnspentTransactionOutput(prevOut);
                            txOutsSpent.add(prevOut);
                        }
                    Sha256Hash hash = tx.getHash();
                    for (StoredTransactionOutput out : tx.getOutputs()) {
                        StoredTransactionOutput newOut = new StoredTransactionOutput(hash, out.getIndex(), out.getValue(),
                                                                                     newBlock.getHeight(), isCoinBase,
                                                                                     out.getScriptBytes());
                        blockStore.addUnspentTransactionOutput(newOut);
                        txOutsCreated.add(newOut);
                    }
                }
                txOutChanges = new TransactionOutputChanges(txOutsCreated, txOutsSpent);
            } else {
                // Use the undo data.
                txOutChanges = block.getTxOutChanges();
                if (!params.isCheckpoint(newBlock.getHeight()))
                    for(StoredTransactionOutput out : txOutChanges.txOutsCreated) {
                        Sha256Hash hash = out.getHash();
                        if (blockStore.getTransactionOutput(hash, out.getIndex()) != null)
                            throw new VerificationException("Block failed BIP30 test!");
                    }
                for (StoredTransactionOutput out : txOutChanges.txOutsCreated)
                    blockStore.addUnspentTransactionOutput(out);
                for (StoredTransactionOutput out : txOutChanges.txOutsSpent)
                    blockStore.removeUnspentTransactionOutput(out);
            }
        } catch (VerificationException e) {
            blockStore.abortDatabaseBatchWrite();
            throw e;
        } catch (BlockStoreException e) {
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
        blockStore.beginDatabaseBatchWrite();
        try {
            StoredUndoableBlock undoBlock = blockStore.getUndoBlock(oldBlock.getHeader().getHash());
            if (undoBlock == null) throw new PrunedException(oldBlock.getHeader().getHash());
            TransactionOutputChanges txOutChanges = undoBlock.getTxOutChanges();
            for(StoredTransactionOutput out : txOutChanges.txOutsSpent)
                blockStore.addUnspentTransactionOutput(out);
            for(StoredTransactionOutput out : txOutChanges.txOutsCreated)
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
    protected void preSetChainHead() throws BlockStoreException {
        blockStore.commitDatabaseBatchWrite();
    }

    @Override
    protected void notSettingChainHead() throws BlockStoreException {
        blockStore.abortDatabaseBatchWrite();
    }
}
