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

import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.utils.EventListenerInvoker;
import com.google.common.base.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

/**
 * A Peer handles the high level communication with a BitCoin node.
 *
 * <p>After making the connection with connect(), call run() to start the message handling loop.
 */
public class Peer {
    private static final Logger log = LoggerFactory.getLogger(Peer.class);
    public static final int CONNECT_TIMEOUT_MSEC = 60000;

    private NetworkConnection conn;
    private final NetworkParameters params;
    // Whether the peer loop is supposed to be running or not. Set to false during shutdown so the peer loop
    // knows to quit when the socket goes away.
    private boolean running;
    private final BlockChain blockChain;
    // When an API user explicitly requests a block or transaction from a peer, the InventoryItem is put here
    // whilst waiting for the response. Synchronized on itself. Is not used for downloads Peer generates itself.
    // TODO: Make this work for transactions as well.
    private final List<GetDataFuture<Block>> pendingGetBlockFutures;
    // Height of the chain advertised in the peers version message.
    private int bestHeight;
    private PeerAddress address;
    private List<PeerEventListener> eventListeners;
    // Whether to try and download blocks and transactions from this peer. Set to false by PeerGroup if not the
    // primary peer. This is to avoid redundant work and concurrency problems with downloading the same chain
    // in parallel.
    private boolean downloadData = true;
    // The version data to announce to the other side of the connections we make: useful for setting our "user agent"
    // equivalent and other things.
    private VersionMessage versionMessage;

    /**
     * Size of the pending transactions pool. Override this to reduce memory usage on constrained platforms. The pool
     * is used to keep track of how many peers announced a transaction. With an untampered-with internet connection,
     * the more peers announce a transaction, the more confidence you can have that it's valid.
     */
    public static int TRANSACTION_MEMORY_POOL_SIZE = 1000;

    // Maps announced transaction hashes to the Transaction objects. If this is not a download peer, the Transaction
    // objects must be provided from elsewhere (ie, a PeerGroup object). If the Transaction hasn't been downloaded or
    // provided yet, the map value is null. This is somewhat equivalent to the reference implementations memory pool.
    private LinkedHashMap<Sha256Hash, Transaction> announcedTransactionHashes = new LinkedHashMap<Sha256Hash, Transaction>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Sha256Hash, Transaction> sha256HashTransactionEntry) {
            // An arbitrary choice to stop the memory used by tracked transactions getting too huge. Mobile platforms
            // may want to reduce this.
            return size() > TRANSACTION_MEMORY_POOL_SIZE;
        }
    };

    // A time before which we only download block headers, after that point we download block bodies.
    private long fastCatchupTimeSecs;
    // Whether we are currently downloading headers only or block bodies. Defaults to true, if the fast catchup time
    // is set AND our best block is before that date, switch to false until block headers beyond that point have been
    // received at which point it gets set to true again. This isn't relevant unless downloadData is true.
    private boolean downloadBlockBodies = true;

    /**
     * Construct a peer that reads/writes from the given block chain. Note that communication won't occur until
     * you call connect(), which will set up a new NetworkConnection.
     *
     * @param bestHeight our current best chain height, to facilitate downloading
     */
    public Peer(NetworkParameters params, PeerAddress address, int bestHeight, BlockChain blockChain) {
        this(params, address, blockChain, new VersionMessage(params, bestHeight));
    }

    /**
     * Construct a peer that reads/writes from the given block chain. Note that communication won't occur until
     * you call connect(), which will set up a new NetworkConnection.
     *
     * @param ver The version data to announce to the other side.
     */
    public Peer(NetworkParameters params, PeerAddress address, BlockChain blockChain, VersionMessage ver) {
        this.params = params;
        this.address = address;
        this.blockChain = blockChain;
        this.pendingGetBlockFutures = new ArrayList<GetDataFuture<Block>>();
        this.eventListeners = new ArrayList<PeerEventListener>();
        this.fastCatchupTimeSecs = params.genesisBlock.getTimeSeconds();
        this.versionMessage = ver;
    }

    /**
     * Construct a peer that reads/writes from the given block chain. Note that communication won't occur until
     * you call connect(), which will set up a new NetworkConnection.
     */
    public Peer(NetworkParameters params, PeerAddress address, BlockChain blockChain) {
        this(params, address, 0, blockChain);
    }

    /**
     * Construct a peer that uses the given, already connected network connection object.
     */
    public Peer(NetworkParameters params, BlockChain blockChain, NetworkConnection connection) {
        this(params, null, 0, blockChain);
        this.conn = connection;
        this.address = connection.getPeerAddress();
    }
    
    public synchronized void addEventListener(PeerEventListener listener) {
        eventListeners.add(listener);
    }

    public synchronized boolean removeEventListener(PeerEventListener listener) {
        return eventListeners.remove(listener);
    }

    @Override
    public String toString() {
        if (address == null) {
            // User-provided NetworkConnection object.
            return "Peer(NetworkConnection:" + conn + ")";
        } else {
            return "Peer(" + address.getAddr() + ":" + address.getPort() + ")";
        }
    }

    /**
     * Connects to the peer.
     *
     * @throws PeerException when there is a temporary problem with the peer and we should retry later
     */
    public synchronized void connect() throws PeerException {
        try {
            conn = new TCPNetworkConnection(address, params, CONNECT_TIMEOUT_MSEC, false, versionMessage);
        } catch (IOException ex) {
            throw new PeerException(ex);
        } catch (ProtocolException ex) {
            throw new PeerException(ex);
        }
    }

    // For testing
    void setConnection(NetworkConnection conn) {
        this.conn = conn;
    }

    /**
     * Runs in the peers network loop and manages communication with the peer.
     *
     * <p>connect() must be called first
     *
     * @throws PeerException when there is a temporary problem with the peer and we should retry later
     */
    public void run() throws PeerException {
        // This should be called in the network loop thread for this peer
        if (conn == null)
            throw new RuntimeException("please call connect() first");

        running = true;

        try {
            while (true) {
                Message m = conn.readMessage();

                // Allow event listeners to filter the message stream. Listeners are allowed to drop messages by
                // returning null.
                for (PeerEventListener listener : eventListeners) {
                    synchronized (listener) {
                        m = listener.onPreMessageReceived(this, m);
                        if (m == null) break;
                    }
                }
                if (m == null) continue;

                if (m instanceof InventoryMessage) {
                    processInv((InventoryMessage) m);
                } else if (m instanceof Block) {
                    processBlock((Block) m);
                } else if (m instanceof Transaction) {
                    processTransaction((Transaction) m);
                } else if (m instanceof GetDataMessage) {
                    processGetData((GetDataMessage) m);
                } else if (m instanceof AddressMessage) {
                    // We don't care about addresses of the network right now. But in future,
                    // we should save them in the wallet so we don't put too much load on the seed nodes and can
                    // properly explore the network.
                } else if (m instanceof HeadersMessage) {
                    processHeaders((HeadersMessage) m);
                } else if (m instanceof AlertMessage) {
                    processAlert((AlertMessage)m);
                } else {
                    // TODO: Handle the other messages we can receive.
                    log.warn("Received unhandled message: {}", m);
                }
            }
        } catch (IOException e) {
            if (!running) {
                // This exception was expected because we are tearing down the socket as part of quitting.
                log.info("Shutting down peer loop");
            } else {
                disconnect();
                throw new PeerException(e);
            }
        } catch (ProtocolException e) {
            disconnect();
            throw new PeerException(e);
        } catch (RuntimeException e) {
            disconnect();
            log.error("unexpected exception in peer loop: ", e.getMessage());
            throw e;
        }

        disconnect();
    }

    private void processAlert(AlertMessage m) {
        try {
            if (m.isSignatureValid()) {
                log.info("Received alert from peer {}: {}", toString(), m.getStatusBar());
            } else {
                log.warn("Received alert with invalid signature from peer {}: {}", toString(), m.getStatusBar());
            }
        } catch (Throwable t) {
            // Signature checking can FAIL on Android platforms before Gingerbread apparently due to bugs in their
            // BigInteger implementations! See issue 160 for discussion. As alerts are just optional and not that
            // useful, we just swallow the error here.
            log.error("Failed to check signature: bug in platform libraries?", t);
        }
    }

    private void processHeaders(HeadersMessage m) throws IOException, ProtocolException {
        // Runs in network loop thread for this peer.
        //
        // This method can run if a peer just randomly sends us a "headers" message (should never happen), or more
        // likely when we've requested them as part of chain download using fast catchup. We need to add each block to
        // the chain if it pre-dates the fast catchup time. If we go past it, we can stop processing the headers and
        // request the full blocks from that point on instead.
        Preconditions.checkState(!downloadBlockBodies);

        try {
            for (int i = 0; i < m.getBlockHeaders().size(); i++) {
                Block header = m.getBlockHeaders().get(i);
                if (header.getTimeSeconds() < fastCatchupTimeSecs) {
                    if (blockChain.add(header)) {
                        // The block was successfully linked into the chain. Notify the user of our progress.
                        invokeOnBlocksDownloaded(header);
                    } else {
                        // This block is unconnected - we don't know how to get from it back to the genesis block yet.
                        // That must mean that the peer is buggy or malicious because we specifically requested for
                        // headers that are part of the best chain.
                        throw new ProtocolException("Got unconnected header from peer: " + header.getHashAsString());
                    }
                } else {
                    log.info("Passed the fast catchup time, discarding {} headers and requesting full blocks",
                            m.getBlockHeaders().size() - i);
                    downloadBlockBodies = true;
                    blockChainDownload(header.getHash());
                    return;
                }
            }
            // We added all headers in the message to the chain. Now request some more!
            blockChainDownload(Sha256Hash.ZERO_HASH);
        } catch (VerificationException e) {
            log.warn("Block header verification failed", e);
        } catch (ScriptException e) {
            // There are no transactions and thus no scripts in these blocks, so this should never happen.
            throw new RuntimeException(e);
        }
    }
    
    private void processGetData(GetDataMessage getdata) throws IOException {
        log.info("Received getdata message: {}", getdata.toString());
        ArrayList<Message> items = new ArrayList<Message>();
        for (PeerEventListener listener : eventListeners) {
            synchronized (listener) {
                List<Message> listenerItems = listener.getData(this, getdata);
                if (listenerItems == null) continue;
                items.addAll(listenerItems);
            }
        }
        if (items.size() == 0) {
            return;
        }
        log.info("Sending {} items gathered from listeners to peer", items.size());
        for (Message item : items) {
            sendMessage(item);
        }
    }

    private void processTransaction(Transaction m) {
        log.info("Received broadcast tx {}", m.getHashAsString());
        for (PeerEventListener listener : eventListeners) {
            synchronized (listener) {
                listener.onTransaction(this, m);
            }
        }
    }

    private void processBlock(Block m) throws IOException {
        log.trace("Received broadcast block {}", m.getHashAsString());
        try {
            // Was this block requested by getBlock()?
            synchronized (pendingGetBlockFutures) {
                for (int i = 0; i < pendingGetBlockFutures.size(); i++) {
                    GetDataFuture<Block> f = pendingGetBlockFutures.get(i);
                    if (f.getItem().hash.equals(m.getHash())) {
                        // Yes, it was. So pass it through the future.
                        f.setResult(m);
                        // Blocks explicitly requested don't get sent to the block chain.
                        pendingGetBlockFutures.remove(i);
                        return;
                    }
                }
            }
            // Otherwise it's a block sent to us because the peer thought we needed it, so add it to the block chain.
            // This call will synchronize on blockChain.
            if (blockChain.add(m)) {
                // The block was successfully linked into the chain. Notify the user of our progress.
                invokeOnBlocksDownloaded(m);
            } else {
                // This block is unconnected - we don't know how to get from it back to the genesis block yet. That
                // must mean that there are blocks we are missing, so do another getblocks with a new block locator
                // to ask the peer to send them to us. This can happen during the initial block chain download where
                // the peer will only send us 500 at a time and then sends us the head block expecting us to request
                // the others.

                // TODO: Should actually request root of orphan chain here.
                blockChainDownload(m.getHash());
            }
        } catch (VerificationException e) {
            // We don't want verification failures to kill the thread.
            log.warn("Block verification failed", e);
        } catch (ScriptException e) {
            // We don't want script failures to kill the thread.
            log.warn("Script exception", e);
        }
    }

    private void invokeOnBlocksDownloaded(final Block m) {
        // It is possible for the peer block height difference to be negative when blocks have been solved and broadcast
        // since the time we first connected to the peer. However, it's weird and unexpected to receive a callback
        // with negative "blocks left" in this case, so we clamp to zero so the API user doesn't have to think about it.
        final int blocksLeft = Math.max(0, getPeerBlockHeightDifference());
        EventListenerInvoker.invoke(eventListeners, new EventListenerInvoker<PeerEventListener>() {
            @Override
            public void invoke(PeerEventListener listener) {
                listener.onBlocksDownloaded(Peer.this, m, blocksLeft);
            }
        });
    }

    private void processInv(InventoryMessage inv) throws IOException {
        // This should be called in the network loop thread for this peer.
        List<InventoryItem> items = inv.getItems();
        updateTransactionConfidenceLevels(items);

        // If this peer isn't responsible for downloading stuff, don't go further.
        if (!downloadData)
            return;

        // The peer told us about some blocks or transactions they have.
        Block topBlock = blockChain.getUnconnectedBlock();
        Sha256Hash topHash = (topBlock != null ? topBlock.getHash() : null);
        if (isNewBlockTickle(topHash, items)) {
            // An inv with a single hash containing our most recent unconnected block is a special inv,
            // it's kind of like a tickle from the peer telling us that it's time to download more blocks to catch up to
            // the block chain. We could just ignore this and treat it as a regular inv but then we'd download the head
            // block over and over again after each batch of 500 blocks, which is wasteful.
            blockChainDownload(topHash);
            return;
        }
        // Just copy the message contents across - request whatever we're told about.
        // TODO: Don't re-request items that were already fetched.
        GetDataMessage getdata = new GetDataMessage(params);
        for (InventoryItem item : items) {
            getdata.addItem(item);
        }
        // This will cause us to receive a bunch of block or tx messages.
        conn.writeMessage(getdata);
    }

    /**
     * When a peer broadcasts an "inv" containing a transaction hash, it means the peer validated it and won't accept 
     * double spends of those coins. So by measuring what proportion of our total connected peers have seen a 
     * transaction we can make a guesstimate of how likely it is to be included in a block, assuming our internet
     * connection is trustworthy.<p>
     *     
     * This method keeps a map of transaction hashes to {@link Transaction} objects. It may not have the associated
     * transaction objects available, if they weren't downloaded yet. Once a Transaction is downloaded, it's set as
     * the value in the txSeen map. If this Peer isn't the download peer, the {@link PeerGroup} will manage distributing
     * the Transaction objects to every peer, at which point the peer is expected to update the
     * {@link TransactionConfidence} object itself.
     * 
     * @param items Inventory items that were just announced.
     */
    private void updateTransactionConfidenceLevels(List<InventoryItem> items) {
        // Announced hashes may be updated by other threads in response to messages coming in from other peers.
        synchronized (announcedTransactionHashes) {
            for (InventoryItem item : items) {
                if (item.type != InventoryItem.Type.Transaction) continue;
                Transaction transaction = announcedTransactionHashes.get(item.hash);
                if (transaction == null) {
                    // We didn't see this tx before.
                    log.debug("Newly announced undownloaded transaction ", item.hash);
                    announcedTransactionHashes.put(item.hash, null);
                } else {
                    // It's been downloaded. Update the confidence levels. This may be called multiple times for
                    // the same transaction and the same peer, there is no obligation in the protocol to avoid
                    // redundant advertisements.
                    log.debug("Marking tx {} as seen by {}", item.hash, toString());
                    transaction.getConfidence().markBroadcastBy(address);
                }
            }
        }
    }

    /**
     * Called by {@link PeerGroup} to tell the Peer about a transaction that was just downloaded. If we have tracked
     * the announcement, update the transactions confidence level at this time. Otherwise wait for it to appear.
     */
    void trackTransaction(Transaction tx) {
        // May run on arbitrary peer threads.
        synchronized (announcedTransactionHashes) {
            if (announcedTransactionHashes.containsKey(tx.getHash())) {
                Transaction storedTx = announcedTransactionHashes.get(tx.getHash());
                Preconditions.checkState(storedTx == tx || storedTx == null, "single Transaction instance");
                log.debug("Provided with a downloaded transaction we have seen before: {}", tx.getHash());
                tx.getConfidence().markBroadcastBy(address);
            } else {
                log.debug("Provided with a downloaded transaction we didn't see broadcast yet: {}", tx.getHash());
            }
            announcedTransactionHashes.put(tx.getHash(), tx);
        }
    }

    /** A new block tickle is an inv with a hash containing the topmost block. */
    private boolean isNewBlockTickle(Sha256Hash topHash, List<InventoryItem> items) {
        return items.size() == 1 &&
               items.get(0).type == InventoryItem.Type.Block &&
               topHash != null &&
               items.get(0).hash.equals(topHash);
    }

    /**
     * Asks the connected peer for the block of the given hash, and returns a Future representing the answer.
     * If you want the block right away and don't mind waiting for it, just call .get() on the result. Your thread
     * will block until the peer answers. You can also use the Future object to wait with a timeout, or just check
     * whether it's done later.
     *
     * @param blockHash Hash of the block you wareare requesting.
     * @throws IOException
     */
    public Future<Block> getBlock(Sha256Hash blockHash) throws IOException {
        GetDataMessage getdata = new GetDataMessage(params);
        InventoryItem inventoryItem = new InventoryItem(InventoryItem.Type.Block, blockHash);
        getdata.addItem(inventoryItem);
        GetDataFuture<Block> future = new GetDataFuture<Block>(inventoryItem);
        // Add to the list of things we're waiting for. It's important this come before the network send to avoid
        // race conditions.
        synchronized (pendingGetBlockFutures) {
            pendingGetBlockFutures.add(future);
        }
        conn.writeMessage(getdata);
        return future;
    }

    /**
     * When downloading the block chain, the bodies will be skipped for blocks created before the given date. Any
     * transactions relevant to the wallet will therefore not be found, but if you know your wallet has no such
     * transactions it doesn't matter and can save a lot of bandwidth and processing time. Note that the times of blocks
     * isn't known until their headers are available and they are requested in chunks, so some headers may be downloaded
     * twice using this scheme, but this optimization can still be a large win for newly created wallets.
     *
     * @param secondsSinceEpoch Time in seconds since the epoch or 0 to reset to always downloading block bodies.
     */
    public void setFastCatchupTime(long secondsSinceEpoch) {
        if (secondsSinceEpoch == 0) {
            fastCatchupTimeSecs = params.genesisBlock.getTimeSeconds();
            downloadBlockBodies = true;
        } else {
            fastCatchupTimeSecs = secondsSinceEpoch;
            // If the given time is before the current chains head block time, then this has no effect (we already
            // downloaded everything we need).
            if (fastCatchupTimeSecs > blockChain.getChainHead().getHeader().getTimeSeconds()) {
                downloadBlockBodies = false;
            }
        }
    }
    
    /**
     * Links the given wallet to this peer. If you have multiple peers, you should use a {@link PeerGroup} to manage
     * them and use the {@link PeerGroup#addWallet(Wallet)} method instead of registering the wallet with each peer
     * independently, otherwise the wallet will receive duplicate notifications.
     */
    public void addWallet(Wallet wallet) {
        addEventListener(wallet.getPeerEventListener());
    }

    /** Unlinks the given wallet from peer. See {@link Peer#addWallet(Wallet)}. */
    public void removeWallet(Wallet wallet) {
        removeEventListener(wallet.getPeerEventListener());
    }

    // A GetDataFuture wraps the result of a getBlock or (in future) getTransaction so the owner of the object can
    // decide whether to wait forever, wait for a short while or check later after doing other work.
    private static class GetDataFuture<T extends Message> implements Future<T> {
        private boolean cancelled;
        private final InventoryItem item;
        private final CountDownLatch latch;
        private T result;

        GetDataFuture(InventoryItem item) {
            this.item = item;
            this.latch = new CountDownLatch(1);
        }

        public boolean cancel(boolean b) {
            // Cannot cancel a getdata - once sent, it's sent.
            cancelled = true;
            return false;
        }

        public boolean isCancelled() {
            return cancelled;
        }

        public boolean isDone() {
            return result != null || cancelled;
        }

        public T get() throws InterruptedException, ExecutionException {
            latch.await();
            return Preconditions.checkNotNull(result);
        }

        public T get(long l, TimeUnit timeUnit) throws InterruptedException, ExecutionException, TimeoutException {
            if (!latch.await(l, timeUnit))
                throw new TimeoutException();
            return Preconditions.checkNotNull(result);
        }

        InventoryItem getItem() {
            return item;
        }

        /** Called by the Peer when the result has arrived. Completes the task. */
        void setResult(T result) {
            // This should be called in the network loop thread for this peer
            this.result = result;
            // Now release the thread that is waiting. We don't need to synchronize here as the latch establishes
            // a memory barrier.
            latch.countDown();
        }
    }

    /**
     * Sends the given message on the peers network connection. Just uses {@link NetworkConnection#writeMessage(Message)}.
     */
    public void sendMessage(Message m) throws IOException {
        conn.writeMessage(m);
    }

    private void blockChainDownload(Sha256Hash toHash) throws IOException {
        // This may run in ANY thread.

        // The block chain download process is a bit complicated. Basically, we start with one or more blocks in a
        // chain that we have from a previous session. We want to catch up to the head of the chain BUT we don't know
        // where that chain is up to or even if the top block we have is even still in the chain - we
        // might have got ourselves onto a fork that was later resolved by the network.
        //
        // To solve this, we send the peer a block locator which is just a list of block hashes. It contains the
        // blocks we know about, but not all of them, just enough of them so the peer can figure out if we did end up
        // on a fork and if so, what the earliest still valid block we know about is likely to be.
        //
        // Once it has decided which blocks we need, it will send us an inv with up to 500 block messages. We may
        // have some of them already if we already have a block chain and just need to catch up. Once we request the
        // last block, if there are still more to come it sends us an "inv" containing only the hash of the head
        // block.
        //
        // That causes us to download the head block but then we find (in processBlock) that we can't connect
        // it to the chain yet because we don't have the intermediate blocks. So we rerun this function building a
        // new block locator describing where we're up to.
        //
        // The getblocks with the new locator gets us another inv with another bunch of blocks. We download them once
        // again. This time when the peer sends us an inv with the head block, we already have it so we won't download
        // it again - but we recognize this case as special and call back into blockChainDownload to continue the
        // process.
        //
        // So this is a complicated process but it has the advantage that we can download a chain of enormous length
        // in a relatively stateless manner and with constant memory usage.
        //
        // All this is made more complicated by the desire to skip downloading the bodies of blocks that pre-date the
        // 'fast catchup time', which is usually set to the creation date of the earliest key in the wallet. Because
        // we know there are no transactions using our keys before that date, we need only the headers. To do that we
        // use the "getheaders" command. Once we find we've gone past the target date, we throw away the downloaded
        // headers and then request the blocks from that point onwards. "getheaders" does not send us an inv, it just
        // sends us the data we requested in a "headers" message.
        log.info("blockChainDownload({})", toHash.toString());

        // TODO: Block locators should be abstracted out rather than special cased here.
        List<Sha256Hash> blockLocator = new ArrayList<Sha256Hash>(51);
        // For now we don't do the exponential thinning as suggested here:
        //
        //   https://en.bitcoin.it/wiki/Protocol_specification#getblocks
        //
        // This is because it requires scanning all the block chain headers, which is very slow. Instead we add the top
        // 50 block headers. If there is a re-org deeper than that, we'll end up downloading the entire chain. We
        // must always put the genesis block as the first entry.
        BlockStore store = blockChain.getBlockStore();
        StoredBlock cursor = blockChain.getChainHead();
        for (int i = 50; cursor != null && i > 0; i--) {
            blockLocator.add(cursor.getHeader().getHash());
            try {
                cursor = cursor.getPrev(store);
            } catch (BlockStoreException e) {
                log.error("Failed to walk the block chain whilst constructing a locator");
                throw new RuntimeException(e);
            }
        }
        // Only add the locator if we didn't already do so. If the chain is < 50 blocks we already reached it.
        if (cursor != null) {
            blockLocator.add(params.genesisBlock.getHash());
        }

        // The toHash field is set to zero already by the constructor. This is how we indicate "never stop".
        
        if (downloadBlockBodies) {
            GetBlocksMessage message = new GetBlocksMessage(params, blockLocator, toHash);
            conn.writeMessage(message);
        } else {
            // Downloading headers for a while instead of full blocks.
            GetHeadersMessage message = new GetHeadersMessage(params, blockLocator, toHash);
            conn.writeMessage(message);
        }
    }

    /**
     * Starts an asynchronous download of the block chain. The chain download is deemed to be complete once we've
     * downloaded the same number of blocks that the peer advertised having in its version handshake message.
     */
    public void startBlockChainDownload() throws IOException {
        setDownloadData(true);
        // TODO: peer might still have blocks that we don't have, and even have a heavier
        // chain even if the chain block count is lower.
        if (getPeerBlockHeightDifference() >= 0) {
            for (PeerEventListener listener : eventListeners) {
                synchronized (listener) {
                    listener.onChainDownloadStarted(this, getPeerBlockHeightDifference());
                }
            }

            // When we just want as many blocks as possible, we can set the target hash to zero.
            blockChainDownload(Sha256Hash.ZERO_HASH);
        }
    }

    /**
     * Returns the difference between our best chain height and the peers, which can either be positive if we are
     * behind the peer, or negative if the peer is ahead of us.
     */
    public int getPeerBlockHeightDifference() {
        // Chain will overflow signed int blocks in ~41,000 years.
        int chainHeight = (int) conn.getVersionMessage().bestHeight;
        // chainHeight should not be zero/negative because we shouldn't have given the user a Peer that is to another
        // client-mode node, nor should it be unconnected. If that happens it means the user overrode us somewhere or
        // there is a bug in the peer management code.
        Preconditions.checkState(chainHeight > 0, "Connected to peer with zero/negative chain height", chainHeight);
        return chainHeight - blockChain.getChainHead().getHeight();
    }

    /**
     * Terminates the network connection and stops the message handling loop.
     * 
     * <p>This does not wait for the loop to terminate.
     */
    public synchronized void disconnect() {
        running = false;
        try {
            // This is the correct way to stop an IO bound loop
            if (conn != null)
                conn.shutdown();
        } catch (IOException e) {
            // Don't care about this.
        }
    }

    /**
     * Returns true if this peer will try and download things it is sent in "inv" messages. Normally you only need
     * one peer to be downloading data. Defaults to true.
     */
    public boolean getDownloadData() {
        return downloadData;
    }

    /**
     * If set to false, the peer won't try and fetch blocks and transactions it hears about. Normally, only one
     * peer should download missing blocks. Defaults to true.
     */
    public void setDownloadData(boolean downloadData) {
        this.downloadData = downloadData;
    }
}
