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
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import org.jboss.netty.channel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;

/**
 * A Peer handles the high level communication with a Bitcoin node.
 *
 * <p>{@link Peer#getHandler()} is part of a Netty Pipeline with a Bitcoin serializer downstream of it.
 */
public class Peer {
    interface PeerLifecycleListener {
        /** Called when the peer is connected */
        public void onPeerConnected(Peer peer);
        /** Called when the peer is disconnected */
        public void onPeerDisconnected(Peer peer);
    }

    private static final Logger log = LoggerFactory.getLogger(Peer.class);

    private final NetworkParameters params;
    private final BlockChain blockChain;
    // When an API user explicitly requests a block or transaction from a peer, the InventoryItem is put here
    // whilst waiting for the response. Synchronized on itself. Is not used for downloads Peer generates itself.
    // TODO: Make this work for transactions as well.
    private final List<GetDataFuture<Block>> pendingGetBlockFutures;
    private PeerAddress address;
    private List<PeerEventListener> eventListeners;
    private List<PeerLifecycleListener> lifecycleListeners;
    // Whether to try and download blocks and transactions from this peer. Set to false by PeerGroup if not the
    // primary peer. This is to avoid redundant work and concurrency problems with downloading the same chain
    // in parallel.
    private boolean downloadData = true;
    // The version data to announce to the other side of the connections we make: useful for setting our "user agent"
    // equivalent and other things.
    private VersionMessage versionMessage;
    // A class that tracks recent transactions that have been broadcast across the network, counts how many
    // peers announced them and updates the transaction confidence data. It is passed to each Peer.
    private MemoryPool memoryPool;
    // A time before which we only download block headers, after that point we download block bodies.
    private long fastCatchupTimeSecs;
    // Whether we are currently downloading headers only or block bodies. Defaults to true, if the fast catchup time
    // is set AND our best block is before that date, switch to false until block headers beyond that point have been
    // received at which point it gets set to true again. This isn't relevant unless downloadData is true.
    private boolean downloadBlockBodies = true;
    // Keeps track of things we requested internally with getdata but didn't receive yet, so we can avoid re-requests.
    // It's not quite the same as pendingGetBlockFutures, as this is used only for getdatas done as part of downloading
    // the chain and so is lighter weight (we just keep a bunch of hashes not futures).
    //
    // It is important to avoid a nasty edge case where we can end up with parallel chain downloads proceeding
    // simultaneously if we were to receive a newly solved block whilst parts of the chain are streaming to us.
    private HashSet<Sha256Hash> pendingBlockDownloads = new HashSet<Sha256Hash>();

    private Channel channel;
    private VersionMessage peerVersionMessage;
    boolean isAcked;
    private PeerHandler handler;

    /**
     * Construct a peer that reads/writes from the given block chain.
     */
    public Peer(NetworkParameters params, BlockChain blockChain, VersionMessage ver) {
        this.params = params;
        this.blockChain = blockChain;
        this.versionMessage = ver;
        this.pendingGetBlockFutures = new ArrayList<GetDataFuture<Block>>();
        this.eventListeners = new CopyOnWriteArrayList<PeerEventListener>();
        this.lifecycleListeners = new CopyOnWriteArrayList<PeerLifecycleListener>();
        this.fastCatchupTimeSecs = params.genesisBlock.getTimeSeconds();
        this.isAcked = false;
        this.handler = new PeerHandler();
    }

    /**
     * Construct a peer that reads/writes from the given chain. Automatically creates a VersionMessage for you from the
     * given software name/version strings, which should be something like "MySimpleTool", "1.0"
     */
    public Peer(NetworkParameters params, BlockChain blockChain, String thisSoftwareName, String thisSoftwareVersion) {
        this(params, blockChain, null);
        this.versionMessage = new VersionMessage(params, blockChain.getBestChainHeight());
        this.versionMessage.appendToSubVer(thisSoftwareName, thisSoftwareVersion, null);
    }

    public synchronized void addEventListener(PeerEventListener listener) {
        eventListeners.add(listener);
    }

    public synchronized boolean removeEventListener(PeerEventListener listener) {
        return eventListeners.remove(listener);
    }

    synchronized void addLifecycleListener(PeerLifecycleListener listener) {
        lifecycleListeners.add(listener);
    }

    synchronized boolean removeLifecycleListener(PeerLifecycleListener listener) {
        return lifecycleListeners.remove(listener);
    }

    /**
     * Tells the peer to insert received transactions/transaction announcements into the given {@link MemoryPool}.
     * This is normally done for you by the {@link PeerGroup} so you don't have to think about it. Transactions stored
     * in a memory pool will have their confidence levels updated when a peer announces it, to reflect the greater
     * likelyhood that the transaction is valid.
     *
     * @param pool A new pool or null to unlink.
     */
    public synchronized void setMemoryPool(MemoryPool pool) {
        memoryPool = pool;
    }

    @Override
    public String toString() {
        if (address == null) {
            // User-provided NetworkConnection object.
            return "Peer()";
        } else {
            return "Peer(" + address.getAddr() + ":" + address.getPort() + ")";
        }
    }

    private void notifyDisconnect() {
        for (PeerLifecycleListener listener : lifecycleListeners) {
            synchronized (listener) {
                listener.onPeerDisconnected(Peer.this);
            }
        }
    }

    class PeerHandler extends SimpleChannelHandler {
        @Override
        public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e)
        throws Exception {
            super.channelClosed(ctx, e);
            notifyDisconnect();
        }

        @Override
        public void connectRequested(ChannelHandlerContext ctx, ChannelStateEvent e)
        throws Exception {
            super.connectRequested(ctx, e);
            channel = e.getChannel();
            address = new PeerAddress((InetSocketAddress)e.getValue());
        }

        /** Catch any exceptions, logging them and then closing the channel. */ 
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e)
        throws Exception {
            if (e.getCause() instanceof ConnectException || e.getCause() instanceof IOException) {
                // Short message for network errors
                log.info(toString() + " - " + e.getCause().getMessage());
            } else {
                log.warn(toString() + " - ", e.getCause());
            }

            e.getChannel().close();
        }

        /** Handle incoming Bitcoin messages */
        @Override
        public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
            Message m = (Message)e.getMessage();
            
            // Allow event listeners to filter the message stream. Listeners are allowed to drop messages by
            // returning null.
            synchronized (Peer.this) {
                for (PeerEventListener listener : eventListeners) {
                    synchronized (listener) {
                        m = listener.onPreMessageReceived(Peer.this, m);
                        if (m == null) break;
                    }
                }
            }

            if (m == null) return;

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
            } else if (m instanceof VersionMessage) {
                peerVersionMessage = (VersionMessage)m;
                EventListenerInvoker.invoke(lifecycleListeners,
                        new EventListenerInvoker<PeerLifecycleListener>() {
                    @Override
                    public void invoke(PeerLifecycleListener listener) {
                        listener.onPeerConnected(Peer.this);
                    }
                });
            } else if (m instanceof VersionAck) {
                if (peerVersionMessage == null) {
                    throw new ProtocolException("got a version ack before version");
                }
                if (isAcked) {
                    throw new ProtocolException("got more than one version ack");
                }
                isAcked = true;
            } else if (m instanceof Ping) {
                if (((Ping) m).hasNonce())
                    sendMessage(new Pong(((Ping) m).getNonce()));
            } else if (m instanceof Pong) {
                // We don't do anything with pongs right now, leave that to eventListeners
            } else {
                // TODO: Handle the other messages we can receive.
                log.warn("Received unhandled message: {}", m);
            }
        }

        public Peer getPeer() {
            return Peer.this;
        }
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
    
    /** Returns the Netty Pipeline stage handling the high level Bitcoin protocol. */
    public PeerHandler getHandler() {
        return handler;
    }

    private void processHeaders(HeadersMessage m) throws IOException, ProtocolException {
        // Runs in network loop thread for this peer.
        //
        // This method can run if a peer just randomly sends us a "headers" message (should never happen), or more
        // likely when we've requested them as part of chain download using fast catchup. We need to add each block to
        // the chain if it pre-dates the fast catchup time. If we go past it, we can stop processing the headers and
        // request the full blocks from that point on instead.
        Preconditions.checkState(!downloadBlockBodies, toString());

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
                    lastGetBlocksBegin = Sha256Hash.ZERO_HASH;  // Prevent this request being seen as a duplicate.
                    blockChainDownload(Sha256Hash.ZERO_HASH);
                    return;
                }
            }
            // We added all headers in the message to the chain. Request some more if we got up to the limit, otherwise
            // we are at the end of the chain.
            if (m.getBlockHeaders().size() >= HeadersMessage.MAX_HEADERS)
                blockChainDownload(Sha256Hash.ZERO_HASH);
        } catch (VerificationException e) {
            log.warn("Block header verification failed", e);
        } catch (ScriptException e) {
            // There are no transactions and thus no scripts in these blocks, so this should never happen.
            throw new RuntimeException(e);
        }
    }
    
    private synchronized void processGetData(GetDataMessage getdata) throws IOException {
        log.info("{}: Received getdata message: {}", address, getdata.toString());
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
        log.info("{}: Sending {} items gathered from listeners to peer", address, items.size());
        for (Message item : items) {
            sendMessage(item);
        }
    }

    private synchronized void processTransaction(Transaction tx) {
        log.debug("{}: Received broadcast tx {}", address, tx.getHashAsString());
        if (memoryPool != null) {
            // We may get back a different transaction object.
            tx = memoryPool.seen(tx, getAddress());
        }
        final Transaction ftx = tx;
        EventListenerInvoker.invoke(eventListeners, new EventListenerInvoker<PeerEventListener>() {
            @Override
            public void invoke(PeerEventListener listener) {
                listener.onTransaction(Peer.this, ftx);
            }
        });
    }

    private void processBlock(Block m) throws IOException {
        log.debug("{}: Received broadcast block {}", address, m.getHashAsString());
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
            if (!downloadData) {
                log.warn("Received block we did not ask for: {}", m.getHashAsString());
                return;
            }
            pendingBlockDownloads.remove(m.getHash());
            // Otherwise it's a block sent to us because the peer thought we needed it, so add it to the block chain.
            // This call will synchronize on blockChain.
            if (blockChain.add(m)) {
                // The block was successfully linked into the chain. Notify the user of our progress.
                invokeOnBlocksDownloaded(m);
            } else {
                // This block is an orphan - we don't know how to get from it back to the genesis block yet. That
                // must mean that there are blocks we are missing, so do another getblocks with a new block locator
                // to ask the peer to send them to us. This can happen during the initial block chain download where
                // the peer will only send us 500 at a time and then sends us the head block expecting us to request
                // the others.
                //
                // We must do two things here:
                // (1) Request from current top of chain to the oldest ancestor of the received block in the orphan set
                // (2) Filter out duplicate getblock requests (done in blockChainDownload).
                //
                // The reason for (1) is that otherwise if new blocks were solved during the middle of chain download
                // we'd do a blockChainDownload() on the new best chain head, which would cause us to try and grab the
                // chain twice (or more!) on the same connection! The block chain would filter out the duplicates but
                // only at a huge speed penalty. By finding the orphan root we ensure every getblocks looks the same
                // no matter how many blocks are solved, and therefore that the (2) duplicate filtering can work.
                blockChainDownload(blockChain.getOrphanRoot(m.getHash()).getHash());
            }
        } catch (VerificationException e) {
            // We don't want verification failures to kill the thread.
            log.warn("Block verification failed", e);
        } catch (ScriptException e) {
            // We don't want script failures to kill the thread.
            log.warn("Script exception", e);
        }
    }

    private synchronized void invokeOnBlocksDownloaded(final Block m) {
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

        // Separate out the blocks and transactions, we'll handle them differently
        List<InventoryItem> transactions = new LinkedList<InventoryItem>();
        List<InventoryItem> blocks = new LinkedList<InventoryItem>();

        for (InventoryItem item : items) {
            switch (item.type) {
                case Transaction: transactions.add(item); break;
                case Block: blocks.add(item); break;
                default: throw new IllegalStateException("Not implemented: " + item.type);
            }
        }

        GetDataMessage getdata = new GetDataMessage(params);

        Iterator<InventoryItem> it = transactions.iterator();
        while (it.hasNext()) {
            InventoryItem item = it.next();
            if (memoryPool == null) {
                if (downloadData) {
                    // If there's no memory pool only download transactions if we're configured to.
                    getdata.addItem(item);
                }
            } else {
                // Only download the transaction if we are the first peer that saw it be advertised. Other peers will also
                // see it be advertised in inv packets asynchronously, they co-ordinate via the memory pool. We could
                // potentially download transactions faster by always asking every peer for a tx when advertised, as remote
                // peers run at different speeds. However to conserve bandwidth on mobile devices we try to only download a
                // transaction once. This means we can miss broadcasts if the peer disconnects between sending us an inv and
                // sending us the transaction: currently we'll never try to re-fetch after a timeout.
                if (memoryPool.maybeWasSeen(item.hash)) {
                    // Some other peer already announced this so don't download.
                    it.remove();
                } else {
                    log.debug("{}: getdata on tx {}", address, item.hash);
                    getdata.addItem(item);
                }
                memoryPool.seen(item.hash, this.getAddress());
            }
        }

        if (blocks.size() > 0 && downloadData) {
            // Ideally, we'd only ask for the data here if we actually needed it. However that can imply a lot of
            // disk IO to figure out what we've got. Normally peers will not send us inv for things we already have
            // so we just re-request it here, and if we get duplicates the block chain / wallet will filter them out.
            for (InventoryItem item : blocks) {
                if (blockChain.isOrphan(item.hash)) {
                    // If an orphan was re-advertised, ask for more blocks.
                    blockChainDownload(blockChain.getOrphanRoot(item.hash).getHash());
                } else {
                    // Don't re-request blocks we already requested. Normally this should not happen. However there is
                    // an edge case: if a block is solved and we complete the inv<->getdata<->block<->getblocks cycle
                    // whilst other parts of the chain are streaming in, then the new getblocks request won't match the
                    // previous one: whilst the stopHash is the same (because we use the orphan root), the start hash
                    // will be different and so the getblocks req won't be dropped as a duplicate. We'll end up
                    // requesting a subset of what we already requested, which can lead to parallel chain downloads
                    // and other nastyness. So we just do a quick removal of redundant getdatas here too.
                    //
                    // Note that as of June 2012 the Satoshi client won't actually ever interleave blocks pushed as
                    // part of chain download with newly announced blocks, so it should always be taken care of by
                    // the duplicate check in blockChainDownload(). But the satoshi client may change in future so
                    // it's better to be safe here.
                    if (!pendingBlockDownloads.contains(item.hash)) {
                        getdata.addItem(item);
                        pendingBlockDownloads.add(item.hash);
                    }
                }
            }
            // If we're downloading the chain, doing a getdata on the last block we were told about will cause the
            // peer to advertize the head block to us in a single-item inv. When we download THAT, it will be an
            // orphan block, meaning we'll re-enter blockChainDownload() to trigger another getblocks between the
            // current best block we have and the orphan block. If more blocks arrive in the meantime they'll also
            // become orphan.
        }

        if (!getdata.getItems().isEmpty()) {
            // This will cause us to receive a bunch of block or tx messages.
            sendMessage(getdata);
        }
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
        log.info("Request to fetch block {}", blockHash);
        GetDataMessage getdata = new GetDataMessage(params);
        InventoryItem inventoryItem = new InventoryItem(InventoryItem.Type.Block, blockHash);
        getdata.addItem(inventoryItem);
        GetDataFuture<Block> future = new GetDataFuture<Block>(inventoryItem);
        // Add to the list of things we're waiting for. It's important this come before the network send to avoid
        // race conditions.
        synchronized (pendingGetBlockFutures) {
            pendingGetBlockFutures.add(future);
        }
        
        sendMessage(getdata);
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
     * Sends the given message on the peers Channel.
     */
    public void sendMessage(Message m) throws IOException {
        Channels.write(channel, m);
    }

    // Keep track of the last request we made to the peer in blockChainDownload so we can avoid redundant and harmful
    // getblocks requests. This does not have to be synchronized because blockChainDownload cannot be called from
    // multiple threads simultaneously.
    private Sha256Hash lastGetBlocksBegin, lastGetBlocksEnd;

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
        StoredBlock chainHead = blockChain.getChainHead();
        Sha256Hash chainHeadHash = chainHead.getHeader().getHash();
        // Did we already make this request? If so, don't do it again.
        if (Objects.equal(lastGetBlocksBegin, chainHeadHash) && Objects.equal(lastGetBlocksEnd, toHash)) {
            log.info("blockChainDownload({}): ignoring duplicated request", toHash.toString());
            return;
        }
        log.info("{}: blockChainDownload({}) current head = {}", new Object[] { toString(),
                toHash.toString(), chainHead.getHeader().getHashAsString() });
        StoredBlock cursor = chainHead;
        for (int i = 100; cursor != null && i > 0; i--) {
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

        // Record that we requested this range of blocks so we can filter out duplicate requests in the event of a
        // block being solved during chain download.
        lastGetBlocksBegin = chainHeadHash;
        lastGetBlocksEnd = toHash;

        if (downloadBlockBodies) {
            GetBlocksMessage message = new GetBlocksMessage(params, blockLocator, toHash);
            sendMessage(message);
        } else {
            // Downloading headers for a while instead of full blocks.
            GetHeadersMessage message = new GetHeadersMessage(params, blockLocator, toHash);
            sendMessage(message);
        }
    }

    /**
     * Starts an asynchronous download of the block chain. The chain download is deemed to be complete once we've
     * downloaded the same number of blocks that the peer advertised having in its version handshake message.
     */
    public synchronized void startBlockChainDownload() throws IOException {
        setDownloadData(true);
        // TODO: peer might still have blocks that we don't have, and even have a heavier
        // chain even if the chain block count is lower.
        if (getPeerBlockHeightDifference() >= 0) {
            EventListenerInvoker.invoke(eventListeners, new EventListenerInvoker<PeerEventListener>() {
                @Override
                public void invoke(PeerEventListener listener) {
                    listener.onChainDownloadStarted(Peer.this, getPeerBlockHeightDifference());
                }
            });

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
        int chainHeight = (int) peerVersionMessage.bestHeight;
        // chainHeight should not be zero/negative because we shouldn't have given the user a Peer that is to another
        // client-mode node, nor should it be unconnected. If that happens it means the user overrode us somewhere or
        // there is a bug in the peer management code.
        Preconditions.checkState(chainHeight > 0, "Connected to peer with zero/negative chain height", chainHeight);
        return chainHeight - blockChain.getChainHead().getHeight();
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
    
    /**
     * @return the IP address and port of peer.
     */
    public PeerAddress getAddress() {
        return address;
    }
    
    /**
     * @return various version numbers claimed by peer.
     */
    public VersionMessage getPeerVersionMessage() {
      return peerVersionMessage;
    }

    /**
     * @return various version numbers we claim.
     */
    public VersionMessage getVersionMessage() {
      return versionMessage;
    }

    /**
     * @return the height of the best chain as claimed by peer.
     */
    public long getBestHeight() {
      return peerVersionMessage.bestHeight;
    }
}
