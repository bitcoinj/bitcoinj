/**
 * Copyright 2011 Google Inc.
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

import static com.google.common.base.Preconditions.checkArgument;

import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import java.util.ArrayList;
import java.util.List;

// TODO: Rename this class to SPVBlockChain at some point.

/**
 * A BlockChain implements the <i>simplified payment verification</i> mode of the Bitcoin protocol. It is the right
 * choice to use for programs that have limited resources as it won't verify transactions signatures or attempt to store
 * all of the block chain. Really, this class should be called SPVBlockChain but for backwards compatibility it is not.
 */
public class BlockChain extends AbstractBlockChain {
    /** Keeps a map of block hashes to StoredBlocks. */
    protected final BlockStore blockStore;

    /**
     * <p>Constructs a BlockChain connected to the given wallet and store. To obtain a {@link Wallet} you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using
     * {@link Wallet#loadFromFile(java.io.File, WalletExtension...)}</p>
     *
     * <p>For the store, you should use {@link org.bitcoinj.store.SPVBlockStore} or you could also try a
     * {@link org.bitcoinj.store.MemoryBlockStore} if you want to hold all headers in RAM and don't care about
     * disk serialization (this is rare).</p>
     */
    public BlockChain(Context context, Wallet wallet, BlockStore blockStore) throws BlockStoreException {
        this(context, new ArrayList<BlockChainListener>(), blockStore);
        addWallet(wallet);
    }

    /** See {@link #BlockChain(Context, Wallet, BlockStore)}} */
    public BlockChain(NetworkParameters params, Wallet wallet, BlockStore blockStore) throws BlockStoreException {
        this(Context.getOrCreate(params), wallet, blockStore);
    }

    /**
     * Constructs a BlockChain that has no wallet at all. This is helpful when you don't actually care about sending
     * and receiving coins but rather, just want to explore the network data structures.
     */
    public BlockChain(Context context, BlockStore blockStore) throws BlockStoreException {
        this(context, new ArrayList<BlockChainListener>(), blockStore);
    }

    /** See {@link #BlockChain(Context, BlockStore)} */
    public BlockChain(NetworkParameters params, BlockStore blockStore) throws BlockStoreException {
        this(params, new ArrayList<BlockChainListener>(), blockStore);
    }

    /**
     * Constructs a BlockChain connected to the given list of listeners and a store.
     */
    public BlockChain(Context params, List<BlockChainListener> wallets, BlockStore blockStore) throws BlockStoreException {
        super(params, wallets, blockStore);
        this.blockStore = blockStore;
    }

    /** See {@link #BlockChain(Context, List, BlockStore)} */
    public BlockChain(NetworkParameters params, List<BlockChainListener> wallets, BlockStore blockStore) throws BlockStoreException {
        this(Context.getOrCreate(params), wallets, blockStore);
    }

    @Override
    protected StoredBlock addToBlockStore(StoredBlock storedPrev, Block blockHeader, TransactionOutputChanges txOutChanges)
            throws BlockStoreException, VerificationException {
        StoredBlock newBlock = storedPrev.build(blockHeader);
        blockStore.put(newBlock);
        return newBlock;
    }
    
    @Override
    protected StoredBlock addToBlockStore(StoredBlock storedPrev, Block blockHeader)
            throws BlockStoreException, VerificationException {
        StoredBlock newBlock = storedPrev.build(blockHeader);
        blockStore.put(newBlock);
        return newBlock;
    }

    @Override
    protected void rollbackBlockStore(int height) throws BlockStoreException {
        lock.lock();
        try {
            int currentHeight = getBestChainHeight();
            checkArgument(height >= 0 && height <= currentHeight, "Bad height: %s", height);
            if (height == currentHeight)
                return; // nothing to do

            // Look for the block we want to be the new chain head
            StoredBlock newChainHead = blockStore.getChainHead();
            while (newChainHead.getHeight() > height) {
                newChainHead = newChainHead.getPrev(blockStore);
                if (newChainHead == null)
                    throw new BlockStoreException("Unreachable height");
            }

            // Modify store directly
            blockStore.put(newChainHead);
            this.setChainHead(newChainHead);
        } finally {
            lock.unlock();
        }
    }

    @Override
    protected boolean shouldVerifyTransactions() {
        return false;
    }

    @Override
    protected TransactionOutputChanges connectTransactions(int height, Block block) {
        // Don't have to do anything as this is only called if(shouldVerifyTransactions())
        throw new UnsupportedOperationException();
    }

    @Override
    protected TransactionOutputChanges connectTransactions(StoredBlock newBlock) {
        // Don't have to do anything as this is only called if(shouldVerifyTransactions())
        throw new UnsupportedOperationException();
    }

    @Override
    protected void disconnectTransactions(StoredBlock block) {
        // Don't have to do anything as this is only called if(shouldVerifyTransactions())
        throw new UnsupportedOperationException();
    }

    @Override
    protected void doSetChainHead(StoredBlock chainHead) throws BlockStoreException {
        blockStore.setChainHead(chainHead);
    }

    @Override
    protected void notSettingChainHead() throws BlockStoreException {
        // We don't use DB transactions here, so we don't need to do anything
    }

    @Override
    protected StoredBlock getStoredBlockInCurrentScope(Sha256Hash hash) throws BlockStoreException {
        return blockStore.get(hash);
    }

    @Override
    public boolean add(FilteredBlock block) throws VerificationException, PrunedException {
        boolean success = super.add(block);
        if (success) {
            trackFilteredTransactions(block.getTransactionCount());
        }
        return success;
    }
}
