/*
 * Copyright 2012 Google Inc.
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

import com.google.common.base.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.*;
import org.bitcoinj.utils.*;
import org.slf4j.*;

import javax.annotation.*;
import java.util.*;
import java.util.concurrent.locks.*;

import static com.google.common.base.Preconditions.*;

/**
 * <p>An AbstractBlockChain holds a series of {@link Block} objects, links them together, and knows how to verify that
 * the chain follows the rules of the {@link NetworkParameters} for this chain.</p>
 *
 * <p>It can be connected to a #$Wallet, and also #$TransactionReceivedInBlockListeners that can receive transactions and
 * notifications of re-organizations.</p>
 *
 * <p>An AbstractBlockChain implementation must be connected to a {@link BlockStore} implementation. The chain object
 * by itself doesn't store any data, that's delegated to the store. Which store you use is a decision best made by
 * reading the getting started guide, but briefly, fully validating block chains need fully validating stores. In
 * the lightweight SPV mode, a #$SPVBlockStore is the right choice.</p>
 *
 * <p>This class implements an abstract class which makes it simple to create a BlockChain that does/doesn't do full
 * verification.  It verifies headers and is implements most of what is required to implement SPV mode, but
 * also provides callback hooks which can be used to do full verification.</p>
 *
 * <p>There are two subclasses of AbstractBlockChain that are useful: #$BlockChain, which is the simplest
 * class and implements <i>simplified payment verification</i>. This is a lightweight and efficient mode that does
 * not verify the contents of blocks, just their headers. A #$FullPrunedBlockChain paired with a
 * #$H2FullPrunedBlockStore implements full verification, which is equivalent to
 * Bitcoin Core. To learn more about the alternative security models, please consult the articles on the
 * website.</p>
 *
 * <b>Theory</b>
 *
 * <p>The 'chain' is actually a tree although in normal operation it operates mostly as a list of {@link Block}s.
 * When multiple new head blocks are found simultaneously, there are multiple stories of the economy competing to become
 * the one true consensus. This can happen naturally when two miners solve a block within a few seconds of each other,
 * or it can happen when the chain is under attack.</p>
 *
 * <p>A reference to the head block of the best known chain is stored. If you can reach the genesis block by repeatedly
 * walking through the prevBlock pointers, then we say this is a full chain. If you cannot reach the genesis block
 * we say it is an orphan chain. Orphan chains can occur when blocks are solved and received during the initial block
 * chain download, or if we connect to a peer that doesn't send us blocks in order.</p>
 *
 * <p>A reorganize occurs when the blocks that make up the best known chain change. Note that simply adding a
 * new block to the top of the best chain isn't a reorganize, but that a reorganize is always triggered by adding
 * a new block that connects to some other (non best head) block. By "best" we mean the chain representing the largest
 * amount of work done.</p>
 *
 * <p>Every so often the block chain passes a difficulty transition point. At that time, all the blocks in the last
 * 2016 blocks are examined and a new difficulty target is calculated from them.</p>
 */
public abstract class AbstractBlockChain {
    private static final Logger log = LoggerFactory.getLogger(AbstractBlockChain.class);
    /** synchronization lock */
    protected final ReentrantLock lock = Threading.lock(AbstractBlockChain.class);

    /** Keeps a map of block hashes to StoredBlocks. */
    private final BlockStore blockStore;

    /**
     * Tracks the top of the best known chain.<p>
     *
     * Following this one down to the genesis block produces the story of the economy from the creation of Bitcoin
     * until the present day. The chain head can change if a new set of blocks is received that results in a chain of
     * greater work than the one obtained by following this one down. In that case a reorganize is triggered,
     * potentially invalidating transactions in our wallet.
     */
    protected StoredBlock chainHead;

    // TODO: Scrap this and use a proper read/write for all of the block chain objects.
    // The chainHead field is read/written synchronized with this object rather than BlockChain. However writing is
    // also guaranteed to happen whilst BlockChain is synchronized (see setChainHead). The goal of this is to let
    // clients quickly access the chain head even whilst the block chain is downloading and thus the BlockChain is
    // locked most of the time.
    private final Object chainHeadLock = new Object();

    /** network parameters for this chain */
    protected final NetworkParameters params;

    // Holds a block header and, optionally, a list of tx hashes or block's transactions
    class OrphanBlock {
        final Block block;
        final List<Sha256Hash> filteredTxHashes;
        final Map<Sha256Hash, Transaction> filteredTxn;
        OrphanBlock(Block block, @Nullable List<Sha256Hash> filteredTxHashes, @Nullable Map<Sha256Hash, Transaction> filteredTxn) {
            final boolean filtered = filteredTxHashes != null && filteredTxn != null;
            Preconditions.checkArgument((block.getTransactions() == null && filtered)
                                        || (block.getTransactions() != null && !filtered));
            this.block = block;
            this.filteredTxHashes = filteredTxHashes;
            this.filteredTxn = filteredTxn;
        }
    }
    // Holds blocks that we have received but can't plug into the chain yet, eg because they were created whilst we
    // were downloading the block chain.
    private final LinkedHashMap<Sha256Hash, OrphanBlock> orphanBlocks = new LinkedHashMap<>();

    /**
     * Constructs a BlockChain connected to the given list of listeners (wallets) and a store.
     * @param blockStore where to store blocks
     * @throws BlockStoreException if a failure occurs while storing a block
     */
    public AbstractBlockChain( BlockStore blockStore) throws BlockStoreException {
        this.blockStore = blockStore;
        chainHead = blockStore.getChainHead();
        log.info("chain head is at height {}:\n{}", chainHead.getHeight(), chainHead.getHeader());

        // TODO(andozw): decide if we need to init params.
        this.params = MainNetParams.get();
    }
    
    /**
     * Adds/updates the given {@link Block} with the block store.
     * This version is used when the transactions have not been verified.
     * @param storedPrev The {@link StoredBlock} which immediately precedes block.
     * @param block The {@link Block} to add/update.
     * @return the newly created {@link StoredBlock}
     * @throws BlockStoreException if a failure occurs while storing a block
     * @throws VerificationException if the block is invalid
     */
    protected abstract StoredBlock addToBlockStore(StoredBlock storedPrev, Block block)
            throws BlockStoreException, VerificationException;
    
    /**
     * Adds/updates the given {@link StoredBlock} with the block store.
     * This version is used when the transactions have already been verified to properly spend txOutputChanges.
     * @param storedPrev The {@link StoredBlock} which immediately precedes block.
     * @param header The {@link StoredBlock} to add/update.
     * @param txOutputChanges The total sum of all changes made by this block to the set of open transaction outputs
     *                        (from a call to connectTransactions), if in fully verifying mode (null otherwise).
     * @return the newly created {@link StoredBlock}
     * @throws BlockStoreException if a failure occurs while storing a block
     * @throws VerificationException if the block is invalid
     */
    protected abstract StoredBlock addToBlockStore(StoredBlock storedPrev, Block header,
                                                   @Nullable TransactionOutputChanges txOutputChanges)
            throws BlockStoreException, VerificationException;

    /**
     * Called before setting chain head in memory.
     * Should write the new head to block store and then commit any database transactions
     * that were started by disconnectTransactions/connectTransactions.
     * @param chainHead chain head to set
     * @throws BlockStoreException if a failure occurs while storing a block
     */
    protected abstract void doSetChainHead(StoredBlock chainHead) throws BlockStoreException;
    
    /**
     * For a standard BlockChain, this should return blockStore.get(hash),
     * for a FullPrunedBlockChain blockStore.getOnceUndoableStoredBlock(hash)
     * @param hash hash of block to fetch
     * @return block with matching hash
     * @throws BlockStoreException if a failure occurs while storing a block
     */
    protected abstract StoredBlock getStoredBlockInCurrentScope(Sha256Hash hash) throws BlockStoreException;

    
    /**
     * Whether or not we are maintaining a set of unspent outputs and are verifying all transactions.
     * Also indicates that all calls to add() should provide a block containing transactions
     * @return true if we are verifying all transactions
     */
    protected abstract boolean shouldVerifyTransactions();
    
    /**
     * Connect each transaction in block.transactions, verifying them as we go and removing spent outputs
     * If an error is encountered in a transaction, no changes should be made to the underlying BlockStore.
     * and a VerificationException should be thrown.
     * Only called if(shouldVerifyTransactions())
     * @param height block height to attach at
     * @param block block to connect
     * @return The full set of all changes made to the set of open transaction outputs.
     * @throws VerificationException if an attempt was made to spend an already-spent output, or if a transaction incorrectly solved an output script.
     * @throws BlockStoreException if the block store had an underlying error.
     */
    protected abstract TransactionOutputChanges connectTransactions(int height, Block block) throws VerificationException, BlockStoreException;

    /**
     * Load newBlock from BlockStore and connect its transactions, returning changes to the set of unspent transactions.
     * If an error is encountered in a transaction, no changes should be made to the underlying BlockStore.
     * Only called if(shouldVerifyTransactions())
     * @param newBlock block to load
     * @throws PrunedException if newBlock does not exist as a #$StoredUndoableBlock in the block store.
     * @throws VerificationException if an attempt was made to spend an already-spent output, or if a transaction incorrectly solved an output script.
     * @throws BlockStoreException if the block store had an underlying error or newBlock does not exist in the block store at all.
     * @return The full set of all changes made to the set of open transaction outputs.
     */
    protected abstract TransactionOutputChanges connectTransactions(StoredBlock newBlock) throws VerificationException, BlockStoreException, PrunedException;    
    
    // filteredTxHashList contains all transactions, filteredTxn just a subset
    private boolean add(Block block, boolean tryConnecting,
                        @Nullable List<Sha256Hash> filteredTxHashList, @Nullable Map<Sha256Hash, Transaction> filteredTxn)
            throws BlockStoreException, VerificationException, PrunedException {
        // TODO: Use read/write locks to ensure that during chain download properties are still low latency.
        lock.lock();
        try {
            // Quick check for duplicates to avoid an expensive check further down (in findSplit). This can happen a lot
            // when connecting orphan transactions due to the dumb brute force algorithm we use.
            if (block.equals(getChainHead().getHeader())) {
                return true;
            }
            if (tryConnecting && orphanBlocks.containsKey(block.getHash())) {
                return false;
            }

            // If we want to verify transactions (ie we are running with full blocks), verify that block has transactions
            if (shouldVerifyTransactions() && block.getTransactions() == null)
                throw new VerificationException("Got a block header while running in full-block mode");

            // Check for already-seen block, but only for full pruned mode, where the DB is
            // more likely able to handle these queries quickly.
            if (shouldVerifyTransactions() && blockStore.get(block.getHash()) != null) {
                return true;
            }

            final StoredBlock storedPrev;

            // TODO(andozw): revisit.
            final int height;
            final EnumSet<Block.VerifyFlag> flags;

            // Prove the block is internally valid: hash is lower than target, etc. This only checks the block contents
            // if there is a tx sending or receiving coins using an address in one of our wallets. And those transactions
            // are only lightly verified: presence in a valid connecting block is taken as proof of validity. See the
            // article here for more details: https://bitcoinj.github.io/security-model
            try {
                block.verifyHeader();
                storedPrev = getStoredBlockInCurrentScope(block.getPrevBlockHash());
                if (storedPrev != null) {
                    height = storedPrev.getHeight() + 1;
                } else {
                    height = Block.BLOCK_HEIGHT_UNKNOWN;
                }
            } catch (VerificationException e) {
                log.error("Failed to verify block: ", e);
                log.error(block.getHashAsString());
                throw e;
            }

            // Try linking it to a place in the currently known blocks.

            if (storedPrev == null) {
                // We can't find the previous block. Probably we are still in the process of downloading the chain and a
                // block was solved whilst we were doing it. We put it to one side and try to connect it later when we
                // have more blocks.
                checkState(tryConnecting, "bug in tryConnectingOrphans");
                log.warn("Block does not connect: {} prev {}", block.getHashAsString(), block.getPrevBlockHash());
                orphanBlocks.put(block.getHash(), new OrphanBlock(block, filteredTxHashList, filteredTxn));
                if (tryConnecting)
                    tryConnectingOrphans();
                return false;
            } else {
                checkState(lock.isHeldByCurrentThread());
                // It connects to somewhere on the chain. Not necessarily the top of the best known chain.
                connectBlock(block, storedPrev, shouldVerifyTransactions(), filteredTxHashList, filteredTxn);
                if (tryConnecting)
                    tryConnectingOrphans();
                return true;
            }
        } finally {
            lock.unlock();
        }
    }

    // expensiveChecks enables checks that require looking at blocks further back in the chain
    // than the previous one when connecting (eg median timestamp check)
    // It could be exposed, but for now we just set it to shouldVerifyTransactions()
    private void connectBlock(final Block block, StoredBlock storedPrev, boolean expensiveChecks,
                              @Nullable final List<Sha256Hash> filteredTxHashList,
                              @Nullable final Map<Sha256Hash, Transaction> filteredTxn) throws BlockStoreException, VerificationException, PrunedException {
        checkState(lock.isHeldByCurrentThread());
        boolean filtered = filteredTxHashList != null && filteredTxn != null;

        if (shouldVerifyTransactions()) {
            for (Transaction tx : block.getTransactions())
                if (!tx.isFinal(storedPrev.getHeight() + 1, block.getTimeSeconds()))
                   throw new VerificationException("Block contains non-final transaction");
        }
        
        StoredBlock head = getChainHead();
        if (storedPrev.equals(head)) {
            if (filtered && filteredTxn.size() > 0)  {
                log.debug("Block {} connects to top of best chain with {} transaction(s) of which we were sent {}",
                        block.getHashAsString(), filteredTxHashList.size(), filteredTxn.size());
                for (Sha256Hash hash : filteredTxHashList) log.debug("  matched tx {}", hash);
            }
            if (expensiveChecks && block.getTimeSeconds() <= getMedianTimestampOfRecentBlocks(head, blockStore))
                throw new VerificationException("Block's timestamp is too early");

            // TODO(andozw): revisit.
            //// BIP 66 & 65: Enforce block version 3/4 once they are a supermajority of blocks
            //// NOTE: This requires 1,000 blocks since the last checkpoint (on main
            //// net, less on test) in order to be applied. It is also limited to
            //// stopping addition of new v2/3 blocks to the tip of the chain.
            //if (block.getVersion() == Block.BLOCK_VERSION_BIP34
            //    || block.getVersion() == Block.BLOCK_VERSION_BIP66) {
            //    final Integer count = versionTally.getCountAtOrAbove(block.getVersion() + 1);
            //    if (count != null
            //        && count >= params.getMajorityRejectBlockOutdated()) {
            //        throw new VerificationException.BlockVersionOutOfDate(block.getVersion());
            //    }
            //}

            // This block connects to the best known block, it is a normal continuation of the system.
            TransactionOutputChanges txOutChanges = null;
            if (shouldVerifyTransactions())
                txOutChanges = connectTransactions(storedPrev.getHeight() + 1, block);
            StoredBlock newStoredBlock = addToBlockStore(storedPrev,
                    block.getTransactions() == null ? block : block.cloneAsHeader(), txOutChanges);
            //versionTally.add(block.getVersion());
            setChainHead(newStoredBlock);
            if (log.isDebugEnabled())
                log.debug("Chain is now {} blocks high, running listeners", newStoredBlock.getHeight());
        } else {
            // This block connects to somewhere other than the top of the best known chain. We treat these differently.
            //
            // Note that we send the transactions to the wallet FIRST, even if we're about to re-organize this block
            // to become the new best chain head. This simplifies handling of the re-org in the Wallet class.
            StoredBlock newBlock = storedPrev.build(block);
            boolean haveNewBestChain = newBlock.moreWorkThan(head);
            if (haveNewBestChain) {
                log.info("Block is causing a re-organize");
            } else {
                StoredBlock splitPoint = findSplit(newBlock, head, blockStore);
                if (splitPoint != null && splitPoint.equals(newBlock)) {
                    // newStoredBlock is a part of the same chain, there's no fork. This happens when we receive a block
                    // that we already saw and linked into the chain previously, which isn't the chain head.
                    // Re-processing it is confusing for the wallet so just skip.
                    log.warn("Saw duplicated block in best chain at height {}: {}",
                            newBlock.getHeight(), newBlock.getHeader().getHash());
                    return;
                }
                if (splitPoint == null) {
                    // This should absolutely never happen
                    // (lets not write the full block to disk to keep any bugs which allow this to happen
                    //  from writing unreasonable amounts of data to disk)
                    throw new VerificationException("Block forks the chain but splitPoint is null");
                } else {
                    // We aren't actually spending any transactions (yet) because we are on a fork
                    addToBlockStore(storedPrev, block);
                    int splitPointHeight = splitPoint.getHeight();
                    String splitPointHash = splitPoint.getHeader().getHashAsString();
                    log.info("Block forks the chain at height {}/block {}, but it did not cause a reorganize:\n{}",
                            splitPointHeight, splitPointHash, newBlock.getHeader().getHashAsString());
                }
            }
            
            //// We may not have any transactions if we received only a header, which can happen during fast catchup.
            //// If we do, send them to the wallet but state that they are on a side chain so it knows not to try and
            //// spend them until they become activated.
            //if (block.getTransactions() != null || filtered) {
            //    informListenersForNewBlock(block, NewBlockType.SIDE_CHAIN, filteredTxHashList, filteredTxn, newBlock);
            //}
            
            if (haveNewBestChain)
                handleNewBestChain(storedPrev, newBlock, block, expensiveChecks);
        }
    }

    /**
     * Gets the median timestamp of the last 11 blocks
     */
    private static long getMedianTimestampOfRecentBlocks(StoredBlock storedBlock,
                                                         BlockStore store) throws BlockStoreException {
        long[] timestamps = new long[11];
        int unused = 9;
        timestamps[10] = storedBlock.getHeader().getTimeSeconds();
        while (unused >= 0 && (storedBlock = storedBlock.getPrev(store)) != null)
            timestamps[unused--] = storedBlock.getHeader().getTimeSeconds();
        
        Arrays.sort(timestamps, unused+1, 11);
        return timestamps[unused + (11-unused)/2];
    }
    
    /**
     * Disconnect each transaction in the block (after reading it from the block store)
     * Only called if(shouldVerifyTransactions())
     * @param block block to disconnect
     * @throws PrunedException if block does not exist as a #$StoredUndoableBlock in the block store.
     * @throws BlockStoreException if the block store had an underlying error or block does not exist in the block store at all.
     */
    protected abstract void disconnectTransactions(StoredBlock block) throws PrunedException, BlockStoreException;

    /**
     * Called as part of connecting a block when the new block results in a different chain having higher total work.
     * 
     * if (shouldVerifyTransactions)
     *     Either newChainHead needs to be in the block store as a FullStoredBlock, or (block != null && block.transactions != null)
     */
    private void handleNewBestChain(StoredBlock storedPrev, StoredBlock newChainHead, Block block, boolean expensiveChecks)
            throws BlockStoreException, VerificationException, PrunedException {
        checkState(lock.isHeldByCurrentThread());
        // This chain has overtaken the one we currently believe is best. Reorganize is required.
        //
        // Firstly, calculate the block at which the chain diverged. We only need to examine the
        // chain from beyond this block to find differences.
        StoredBlock head = getChainHead();
        final StoredBlock splitPoint = findSplit(newChainHead, head, blockStore);
        log.info("Re-organize after split at height {}", splitPoint.getHeight());
        log.info("Old chain head: {}", head.getHeader().getHashAsString());
        log.info("New chain head: {}", newChainHead.getHeader().getHashAsString());
        log.info("Split at block: {}", splitPoint.getHeader().getHashAsString());
        // Then build a list of all blocks in the old part of the chain and the new part.
        final LinkedList<StoredBlock> oldBlocks = getPartialChain(head, splitPoint, blockStore);
        final LinkedList<StoredBlock> newBlocks = getPartialChain(newChainHead, splitPoint, blockStore);
        // Disconnect each transaction in the previous best chain that is no longer in the new best chain
        StoredBlock storedNewHead = splitPoint;
        if (shouldVerifyTransactions()) {
            for (StoredBlock oldBlock : oldBlocks) {
                try {
                    disconnectTransactions(oldBlock);
                } catch (PrunedException e) {
                    // We threw away the data we need to re-org this deep! We need to go back to a peer with full
                    // block contents and ask them for the relevant data then rebuild the indexs. Or we could just
                    // give up and ask the human operator to help get us unstuck (eg, rescan from the genesis block).
                    // TODO: Retry adding this block when we get a block with hash e.getHash()
                    throw e;
                }
            }
            StoredBlock cursor;
            // Walk in ascending chronological order.
            for (Iterator<StoredBlock> it = newBlocks.descendingIterator(); it.hasNext();) {
                cursor = it.next();
                Block cursorBlock = cursor.getHeader();
                if (expensiveChecks && cursorBlock.getTimeSeconds() <= getMedianTimestampOfRecentBlocks(cursor.getPrev(blockStore), blockStore))
                    throw new VerificationException("Block's timestamp is too early during reorg");
                TransactionOutputChanges txOutChanges;
                if (cursor != newChainHead || block == null)
                    txOutChanges = connectTransactions(cursor);
                else
                    txOutChanges = connectTransactions(newChainHead.getHeight(), block);
                storedNewHead = addToBlockStore(storedNewHead, cursorBlock.cloneAsHeader(), txOutChanges);
            }
        } else {
            // (Finally) write block to block store
            storedNewHead = addToBlockStore(storedPrev, newChainHead.getHeader());
        }
        //// Now inform the listeners. This is necessary so the set of currently active transactions (that we can spend)
        //// can be updated to take into account the re-organize. We might also have received new coins we didn't have
        //// before and our previous spends might have been undone.
        //for (final ListenerRegistration<ReorganizeListener> registration : reorganizeListeners) {
        //    if (registration.executor == Threading.SAME_THREAD) {
        //        // Short circuit the executor so we can propagate any exceptions.
        //        // TODO: Do we really need to do this or should it be irrelevant?
        //        registration.listener.reorganize(splitPoint, oldBlocks, newBlocks);
        //    } else {
        //        registration.executor.execute(new Runnable() {
        //            @Override
        //            public void run() {
        //                try {
        //                    registration.listener.reorganize(splitPoint, oldBlocks, newBlocks);
        //                } catch (VerificationException e) {
        //                    log.error("Block chain listener threw exception during reorg", e);
        //                }
        //            }
        //        });
        //    }
        //}
        // Update the pointer to the best known block.
        setChainHead(storedNewHead);
    }

    /**
     * Returns the set of contiguous blocks between 'higher' and 'lower'. Higher is included, lower is not.
     */
    private static LinkedList<StoredBlock> getPartialChain(StoredBlock higher, StoredBlock lower, BlockStore store) throws BlockStoreException {
        checkArgument(higher.getHeight() > lower.getHeight(), "higher and lower are reversed");
        LinkedList<StoredBlock> results = new LinkedList<>();
        StoredBlock cursor = higher;
        do {
            results.add(cursor);
            cursor = checkNotNull(cursor.getPrev(store), "Ran off the end of the chain");
        } while (!cursor.equals(lower));
        return results;
    }

    /**
     * Locates the point in the chain at which newStoredBlock and chainHead diverge. Returns null if no split point was
     * found (ie they are not part of the same chain). Returns newChainHead or chainHead if they don't actually diverge
     * but are part of the same chain.
     */
    private static StoredBlock findSplit(StoredBlock newChainHead, StoredBlock oldChainHead,
                                         BlockStore store) throws BlockStoreException {
        StoredBlock currentChainCursor = oldChainHead;
        StoredBlock newChainCursor = newChainHead;
        // Loop until we find the block both chains have in common. Example:
        //
        //    A -> B -> C -> D
        //         \--> E -> F -> G
        //
        // findSplit will return block B. oldChainHead = D and newChainHead = G.
        while (!currentChainCursor.equals(newChainCursor)) {
            if (currentChainCursor.getHeight() > newChainCursor.getHeight()) {
                currentChainCursor = currentChainCursor.getPrev(store);
                checkNotNull(currentChainCursor, "Attempt to follow an orphan chain");
            } else {
                newChainCursor = newChainCursor.getPrev(store);
                checkNotNull(newChainCursor, "Attempt to follow an orphan chain");
            }
        }
        return currentChainCursor;
    }

    /**
     * Indicates whether new Block was on the best chain or not
     */
    public enum NewBlockType {
        /** New block is on the best chain */
        BEST_CHAIN,
        /** New block is on a side chain */
        SIDE_CHAIN
    }

    /**
     * @param chainHead chain head to set
     * @throws BlockStoreException if a failure occurs while storing a block
     */
    protected void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        doSetChainHead(chainHead);
        synchronized (chainHeadLock) {
            this.chainHead = chainHead;
        }
    }

    /**
     * For each block in orphanBlocks, see if we can now fit it on top of the chain and if so, do so.
     */
    private void tryConnectingOrphans() throws VerificationException, BlockStoreException, PrunedException {
        checkState(lock.isHeldByCurrentThread());
        // For each block in our orphan list, try and fit it onto the head of the chain. If we succeed remove it
        // from the list and keep going. If we changed the head of the list at the end of the round try again until
        // we can't fit anything else on the top.
        //
        // This algorithm is kind of crappy, we should do a topo-sort then just connect them in order, but for small
        // numbers of orphan blocks it does OK.
        int blocksConnectedThisRound;
        do {
            blocksConnectedThisRound = 0;
            Iterator<OrphanBlock> iter = orphanBlocks.values().iterator();
            while (iter.hasNext()) {
                OrphanBlock orphanBlock = iter.next();
                // Look up the blocks previous.
                StoredBlock prev = getStoredBlockInCurrentScope(orphanBlock.block.getPrevBlockHash());
                if (prev == null) {
                    // This is still an unconnected/orphan block.
                    if (log.isDebugEnabled())
                        log.debug("Orphan block {} is not connectable right now", orphanBlock.block.getHash());
                    continue;
                }
                // Otherwise we can connect it now.
                // False here ensures we don't recurse infinitely downwards when connecting huge chains.
                log.info("Connected orphan {}", orphanBlock.block.getHash());
                add(orphanBlock.block, false, orphanBlock.filteredTxHashes, orphanBlock.filteredTxn);
                iter.remove();
                blocksConnectedThisRound++;
            }
            if (blocksConnectedThisRound > 0) {
                log.info("Connected {} orphan blocks.", blocksConnectedThisRound);
            }
        } while (blocksConnectedThisRound > 0);
    }

    /**
     * Returns the block at the head of the current best chain. This is the block which represents the greatest
     * amount of cumulative work done.
     * @return block at the head of the current best chain
     */
    public StoredBlock getChainHead() {
        synchronized (chainHeadLock) {
            return chainHead;
        }
    }

    /**
     * Returns an estimate of when the given block will be reached, assuming a perfect 10 minute average for each
     * block. This is useful for turning transaction lock times into human readable times. Note that a height in
     * the past will still be estimated, even though the time of solving is actually known (we won't scan backwards
     * through the chain to obtain the right answer).
     * @param height block time to estimate
     * @return estimated date block will be mined
     */
    public Date estimateBlockTime(int height) {
        synchronized (chainHeadLock) {
            long offset = height - chainHead.getHeight();
            long headTime = chainHead.getHeader().getTimeSeconds();
            long estimated = (headTime * 1000) + (1000L * 60L * 10L * offset);
            return new Date(estimated);
        }
    }
}
