/**
 * Copyright 2013 Google Inc.
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
import com.google.bitcoin.utils.ListenerRegistration;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import net.jcip.annotations.GuardedBy;
import org.jboss.netty.channel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

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

    protected final ReentrantLock lock = Threading.lock("peer");

    private final NetworkParameters params;
    private final AbstractBlockChain blockChain;
    private volatile PeerAddress vAddress;
    private final CopyOnWriteArrayList<ListenerRegistration<PeerEventListener>> eventListeners;
    private final CopyOnWriteArrayList<PeerLifecycleListener> lifecycleListeners;
    // Whether to try and download blocks and transactions from this peer. Set to false by PeerGroup if not the
    // primary peer. This is to avoid redundant work and concurrency problems with downloading the same chain
    // in parallel.
    private volatile boolean vDownloadData;
    // The version data to announce to the other side of the connections we make: useful for setting our "user agent"
    // equivalent and other things.
    private final VersionMessage versionMessage;
    // How many block messages the peer has announced to us. Peers only announce blocks that attach to their best chain
    // so we can use this to calculate the height of the peers chain, by adding it to the initial height in the version
    // message. This method can go wrong if the peer re-orgs onto a shorter (but harder) chain, however, this is rare.
    private final AtomicInteger blocksAnnounced = new AtomicInteger();
    // A class that tracks recent transactions that have been broadcast across the network, counts how many
    // peers announced them and updates the transaction confidence data. It is passed to each Peer.
    private final MemoryPool memoryPool;
    // Each wallet added to the peer will be notified of downloaded transaction data.
    private final CopyOnWriteArrayList<Wallet> wallets;
    // A time before which we only download block headers, after that point we download block bodies.
    @GuardedBy("lock") private long fastCatchupTimeSecs;
    // Whether we are currently downloading headers only or block bodies. Starts at true. If the fast catchup time is
    // set AND our best block is before that date, switch to false until block headers beyond that point have been
    // received at which point it gets set to true again. This isn't relevant unless vDownloadData is true.
    @GuardedBy("lock") private boolean downloadBlockBodies = true;
    // Whether to request filtered blocks instead of full blocks if the protocol version allows for them.
    @GuardedBy("lock") private boolean useFilteredBlocks = false;
    // The current Bloom filter set on the connection, used to tell the remote peer what transactions to send us.
    private volatile BloomFilter vBloomFilter;
    // The last filtered block we received, we're waiting to fill it out with transactions.
    private FilteredBlock currentFilteredBlock = null;
    // How many filtered blocks have been received during the lifetime of this connection. Used to decide when to
    // refresh the server-side side filter by sending a new one (it degrades over time as false positives are added
    // on the remote side, see BIP 37 for a discussion of this).
    private int filteredBlocksReceived;
    // How frequently to refresh the filter. This should become dynamic in future and calculated depending on the
    // actual false positive rate. For now a good value was determined empirically around January 2013.
    private static final int RESEND_BLOOM_FILTER_BLOCK_COUNT = 25000;
    // Keeps track of things we requested internally with getdata but didn't receive yet, so we can avoid re-requests.
    // It's not quite the same as getDataFutures, as this is used only for getdatas done as part of downloading
    // the chain and so is lighter weight (we just keep a bunch of hashes not futures).
    //
    // It is important to avoid a nasty edge case where we can end up with parallel chain downloads proceeding
    // simultaneously if we were to receive a newly solved block whilst parts of the chain are streaming to us.
    private final HashSet<Sha256Hash> pendingBlockDownloads = new HashSet<Sha256Hash>();
    // The lowest version number we're willing to accept. Lower than this will result in an immediate disconnect.
    private volatile int vMinProtocolVersion = Pong.MIN_PROTOCOL_VERSION;
    // When an API user explicitly requests a block or transaction from a peer, the InventoryItem is put here
    // whilst waiting for the response. Is not used for downloads Peer generates itself.
    private static class GetDataRequest {
        Sha256Hash hash;
        SettableFuture future;
        // If the peer does not support the notfound message, we'll use ping/pong messages to simulate it. This is
        // a nasty hack that relies on the fact that bitcoin-qt is single threaded and processes messages in order.
        // The nonce field records which pong should clear this request as "not found".
        long nonce;
    }
    private final CopyOnWriteArrayList<GetDataRequest> getDataFutures;

    // Outstanding pings against this peer and how long the last one took to complete.
    private final ReentrantLock lastPingTimesLock = new ReentrantLock();
    @GuardedBy("lastPingTimesLock") private long[] lastPingTimes = null;
    private final CopyOnWriteArrayList<PendingPing> pendingPings;
    private static final int PING_MOVING_AVERAGE_WINDOW = 20;

    private volatile Channel vChannel;
    private volatile VersionMessage vPeerVersionMessage;
    private boolean isAcked;
    private final PeerHandler handler;

    /**
     * Construct a peer that reads/writes from the given block chain.
     */
    public Peer(NetworkParameters params, AbstractBlockChain chain, VersionMessage ver) {
        this(params, chain, ver, null);
    }

    /**
     * Construct a peer that reads/writes from the given block chain and memory pool. Transactions stored
     * in a memory pool will have their confidence levels updated when a peer announces it, to reflect the greater
     * likelyhood that the transaction is valid.
     */
    public Peer(NetworkParameters params, @Nullable AbstractBlockChain chain, VersionMessage ver, @Nullable MemoryPool mempool) {
        this.params = Preconditions.checkNotNull(params);
        this.versionMessage = Preconditions.checkNotNull(ver);
        this.blockChain = chain;  // Allowed to be null.
        this.vDownloadData = chain != null;
        this.getDataFutures = new CopyOnWriteArrayList<GetDataRequest>();
        this.eventListeners = new CopyOnWriteArrayList<ListenerRegistration<PeerEventListener>>();
        this.lifecycleListeners = new CopyOnWriteArrayList<PeerLifecycleListener>();
        this.fastCatchupTimeSecs = params.getGenesisBlock().getTimeSeconds();
        this.isAcked = false;
        this.handler = new PeerHandler();
        this.pendingPings = new CopyOnWriteArrayList<PendingPing>();
        this.wallets = new CopyOnWriteArrayList<Wallet>();
        this.memoryPool = mempool;
    }

    /**
     * Construct a peer that reads/writes from the given chain. Automatically creates a VersionMessage for you from the
     * given software name/version strings, which should be something like "MySimpleTool", "1.0" and which will tell the
     * remote node to relay transaction inv messages before it has received a filter.
     */
    public Peer(NetworkParameters params, AbstractBlockChain blockChain, String thisSoftwareName, String thisSoftwareVersion) {
        this(params, blockChain, new VersionMessage(params, blockChain.getBestChainHeight(), true));
        this.versionMessage.appendToSubVer(thisSoftwareName, thisSoftwareVersion, null);
    }

    /**
     * Registers the given object as an event listener that will be invoked on the user thread. Note that listeners
     * added this way will <b>not</b> receive {@link PeerEventListener#getData(Peer, GetDataMessage)} or
     * {@link PeerEventListener#onPreMessageReceived(Peer, Message)} calls because those require that the listener
     * be added using {@link Threading#SAME_THREAD}, which requires the other addListener form.
     */
    public void addEventListener(PeerEventListener listener) {
        addEventListener(listener, Threading.USER_THREAD);
    }

    /**
     * Registers the given object as an event listener that will be invoked by the given executor. Note that listeners
     * added using any other executor than {@link Threading#SAME_THREAD} will <b>not</b> receive
     * {@link PeerEventListener#getData(Peer, GetDataMessage)} or
     * {@link PeerEventListener#onPreMessageReceived(Peer, Message)} calls because this class is not willing to cross
     * threads in order to get the results of those hook methods.
     */
    public void addEventListener(PeerEventListener listener, Executor executor) {
        eventListeners.add(new ListenerRegistration<PeerEventListener>(listener, executor));
    }

    public boolean removeEventListener(PeerEventListener listener) {
        return ListenerRegistration.removeFromList(listener, eventListeners);
    }

    void addLifecycleListener(PeerLifecycleListener listener) {
        lifecycleListeners.add(listener);
    }

    boolean removeLifecycleListener(PeerLifecycleListener listener) {
        return lifecycleListeners.remove(listener);
    }

    @Override
    public String toString() {
        PeerAddress addr = vAddress;
        if (addr == null) {
            // User-provided NetworkConnection object.
            return "Peer()";
        } else {
            return addr.toString();
        }
    }

    private void notifyDisconnect() {
        for (PeerLifecycleListener listener : lifecycleListeners) {
            listener.onPeerDisconnected(Peer.this);
        }
    }

    class PeerHandler extends SimpleChannelHandler {
        @Override
        public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            super.channelClosed(ctx, e);
            notifyDisconnect();
        }

        @Override
        public void connectRequested(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            vAddress = new PeerAddress((InetSocketAddress)e.getValue());
            vChannel = e.getChannel();
            super.connectRequested(ctx, e);
        }

        /** Catch any exceptions, logging them and then closing the channel. */
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
            String s;
            PeerAddress addr = vAddress;
            s = addr == null ? "?" : addr.toString();
            final Throwable cause = e.getCause();
            if (cause instanceof ConnectException || cause instanceof IOException) {
                // Short message for network errors
                log.info(s + " - " + cause.getMessage());
            } else {
                log.warn(s + " - ", cause);
                Thread.UncaughtExceptionHandler handler = Threading.uncaughtExceptionHandler;
                if (handler != null)
                    handler.uncaughtException(Thread.currentThread(), cause);
            }

            e.getChannel().close();
        }

        /** Handle incoming Bitcoin messages */
        @Override
        public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
            Message m = (Message)e.getMessage();
            processMessage(e, m);
        }

        public Peer getPeer() {
            return Peer.this;
        }
    }

    private void processMessage(MessageEvent e, Message m) throws Exception {
        // Allow event listeners to filter the message stream. Listeners are allowed to drop messages by
        // returning null.
        for (ListenerRegistration<PeerEventListener> registration : eventListeners) {
            // Skip any listeners that are supposed to run in another thread as we don't want to block waiting
            // for it, which might cause circular deadlock.
            if (registration.executor == Threading.SAME_THREAD) {
                m = registration.listener.onPreMessageReceived(this, m);
                if (m == null) break;
            }
        }
        if (m == null) return;

        // If we are in the middle of receiving transactions as part of a filtered block push from the remote node,
        // and we receive something that's not a transaction, then we're done.
        if (currentFilteredBlock != null && !(m instanceof Transaction)) {
            endFilteredBlock(currentFilteredBlock);
            currentFilteredBlock = null;
        }

        if (m instanceof NotFoundMessage) {
            // This is sent to us when we did a getdata on some transactions that aren't in the peers memory pool.
            // Because NotFoundMessage is a subclass of InventoryMessage, the test for it must come before the next.
            processNotFoundMessage((NotFoundMessage) m);
        } else if (m instanceof InventoryMessage) {
            processInv((InventoryMessage) m);
        } else if (m instanceof Block) {
            processBlock((Block) m);
        } else if (m instanceof FilteredBlock) {
            startFilteredBlock((FilteredBlock) m);
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
            processAlert((AlertMessage) m);
        } else if (m instanceof VersionMessage) {
            vPeerVersionMessage = (VersionMessage) m;
        } else if (m instanceof VersionAck) {
            if (vPeerVersionMessage == null) {
                throw new ProtocolException("got a version ack before version");
            }
            if (isAcked) {
                throw new ProtocolException("got more than one version ack");
            }
            isAcked = true;
            for (PeerLifecycleListener listener : lifecycleListeners)
                listener.onPeerConnected(this);
            // We check min version after onPeerConnected as channel.close() will
            // call onPeerDisconnected, and we should probably call onPeerConnected first.
            final int version = vMinProtocolVersion;
            if (vPeerVersionMessage.clientVersion < version) {
                log.warn("Connected to a peer speaking protocol version {} but need {}, closing",
                        vPeerVersionMessage.clientVersion, version);
                e.getChannel().close();
            }
        } else if (m instanceof Ping) {
            if (((Ping) m).hasNonce())
                sendMessage(new Pong(((Ping) m).getNonce()));
        } else if (m instanceof Pong) {
            processPong((Pong)m);
        } else {
            log.warn("Received unhandled message: {}", m);
        }
    }

    private void startFilteredBlock(FilteredBlock m) throws IOException {
        // Filtered blocks come before the data that they refer to, so stash it here and then fill it out as
        // messages stream in. We'll call endFilteredBlock when a non-tx message arrives (eg, another
        // FilteredBlock) or when a tx that isn't needed by that block is found. A ping message is sent after
        // a getblocks, to force the non-tx message path.
        currentFilteredBlock = m;
        // Potentially refresh the server side filter. Because the remote node adds hits back into the filter
        // to save round-tripping back through us, the filter degrades over time as false positives get added,
        // triggering yet more false positives. We refresh it every so often to get the FP rate back down.
        filteredBlocksReceived++;
        if (filteredBlocksReceived % RESEND_BLOOM_FILTER_BLOCK_COUNT == RESEND_BLOOM_FILTER_BLOCK_COUNT - 1) {
            sendMessage(vBloomFilter);
        }
    }

    private void processNotFoundMessage(NotFoundMessage m) {
        // This is received when we previously did a getdata but the peer couldn't find what we requested in it's
        // memory pool. Typically, because we are downloading dependencies of a relevant transaction and reached
        // the bottom of the dependency tree (where the unconfirmed transactions connect to transactions that are
        // in the chain).
        //
        // We go through and cancel the pending getdata futures for the items we were told weren't found.
        for (GetDataRequest req : getDataFutures) {
            for (InventoryItem item : m.getItems()) {
                if (item.hash.equals(req.hash)) {
                    log.info("{}: Bottomed out dep tree at {}", this, req.hash);
                    req.future.cancel(true);
                    getDataFutures.remove(req);
                    break;
                }
            }
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
        boolean downloadBlockBodies;
        long fastCatchupTimeSecs;

        lock.lock();
        try {
            if (blockChain == null) {
                // Can happen if we are receiving unrequested data, or due to programmer error.
                log.warn("Received headers when Peer is not configured with a chain.");
                return;
            }
            fastCatchupTimeSecs = this.fastCatchupTimeSecs;
            downloadBlockBodies = this.downloadBlockBodies;
        } finally {
            lock.unlock();
        }

        try {
            checkState(!downloadBlockBodies, toString());
            for (int i = 0; i < m.getBlockHeaders().size(); i++) {
                Block header = m.getBlockHeaders().get(i);
                // Process headers until we pass the fast catchup time, or are about to catch up with the head
                // of the chain - always process the last block as a full/filtered block to kick us out of the
                // fast catchup mode (in which we ignore new blocks).
                boolean passedTime = header.getTimeSeconds() >= fastCatchupTimeSecs;
                boolean reachedTop = blockChain.getBestChainHeight() >= vPeerVersionMessage.bestHeight;
                if (!passedTime && !reachedTop) {
                    if (!vDownloadData) {
                        // Not download peer anymore, some other peer probably became better.
                        log.info("Lost download peer status, throwing away downloaded headers.");
                        return;
                    }
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
                    lock.lock();
                    try {
                        log.info("Passed the fast catchup time, discarding {} headers and requesting full blocks",
                                m.getBlockHeaders().size() - i);
                        this.downloadBlockBodies = true;
                        // Prevent this request being seen as a duplicate.
                        this.lastGetBlocksBegin = Sha256Hash.ZERO_HASH;
                        blockChainDownloadLocked(Sha256Hash.ZERO_HASH);
                    } finally {
                        lock.unlock();
                    }
                    return;
                }
            }
            // We added all headers in the message to the chain. Request some more if we got up to the limit, otherwise
            // we are at the end of the chain.
            if (m.getBlockHeaders().size() >= HeadersMessage.MAX_HEADERS) {
                lock.lock();
                try {
                    blockChainDownloadLocked(Sha256Hash.ZERO_HASH);
                } finally {
                    lock.unlock();
                }
            }
        } catch (VerificationException e) {
            log.warn("Block header verification failed", e);
        } catch (PrunedException e) {
            // Unreachable when in SPV mode.
            throw new RuntimeException(e);
        }
    }

    private void processGetData(GetDataMessage getdata) throws IOException {
        log.info("{}: Received getdata message: {}", vAddress, getdata.toString());
        ArrayList<Message> items = new ArrayList<Message>();
        for (ListenerRegistration<PeerEventListener> registration : eventListeners) {
            if (registration.executor != Threading.SAME_THREAD) continue;
            List<Message> listenerItems = registration.listener.getData(this, getdata);
            if (listenerItems == null) continue;
            items.addAll(listenerItems);
        }
        if (items.size() == 0) {
            return;
        }
        log.info("{}: Sending {} items gathered from listeners to peer", vAddress, items.size());
        for (Message item : items) {
            sendMessage(item);
        }
    }

    private void processTransaction(Transaction tx) throws VerificationException, IOException {
        // Check a few basic syntax issues to ensure the received TX isn't nonsense.
        tx.verify();
        final Transaction fTx;
        lock.lock();
        try {
            log.debug("{}: Received tx {}", vAddress, tx.getHashAsString());
            if (memoryPool != null) {
                // We may get back a different transaction object.
                tx = memoryPool.seen(tx, getAddress());
            }
            fTx = tx;
            // Label the transaction as coming in from the P2P network (as opposed to being created by us, direct import,
            // etc). This helps the wallet decide how to risk analyze it later.
            fTx.getConfidence().setSource(TransactionConfidence.Source.NETWORK);
            if (maybeHandleRequestedData(fTx)) {
                return;
            }
            if (currentFilteredBlock != null) {
                if (!currentFilteredBlock.provideTransaction(tx)) {
                    // Got a tx that didn't fit into the filtered block, so we must have received everything.
                    endFilteredBlock(currentFilteredBlock);
                    currentFilteredBlock = null;
                }
                // Don't tell wallets or listeners about this tx as they'll learn about it when the filtered block is
                // fully downloaded instead.
                return;
            }
            // It's a broadcast transaction. Tell all wallets about this tx so they can check if it's relevant or not.
            for (final Wallet wallet : wallets) {
                try {
                    if (wallet.isPendingTransactionRelevant(fTx)) {
                        // This transaction seems interesting to us, so let's download its dependencies. This has several
                        // purposes: we can check that the sender isn't attacking us by engaging in protocol abuse games,
                        // like depending on a time-locked transaction that will never confirm, or building huge chains
                        // of unconfirmed transactions (again - so they don't confirm and the money can be taken
                        // back with a Finney attack). Knowing the dependencies also lets us store them in a serialized
                        // wallet so we always have enough data to re-announce to the network and get the payment into
                        // the chain, in case the sender goes away and the network starts to forget.
                        // TODO: Not all the above things are implemented.

                        Futures.addCallback(downloadDependencies(fTx), new FutureCallback<List<Transaction>>() {
                            public void onSuccess(List<Transaction> dependencies) {
                                try {
                                    log.info("{}: Dependency download complete!", vAddress);
                                    wallet.receivePending(fTx, dependencies);
                                } catch (VerificationException e) {
                                    log.error("{}: Wallet failed to process pending transaction {}",
                                            vAddress, fTx.getHashAsString());
                                    log.error("Error was: ", e);
                                    // Not much more we can do at this point.
                                }
                            }

                            public void onFailure(Throwable throwable) {
                                log.error("Could not download dependencies of tx {}", fTx.getHashAsString());
                                log.error("Error was: ", throwable);
                                // Not much more we can do at this point.
                            }
                        });

                    }
                } catch (VerificationException e) {
                    log.error("Wallet failed to verify tx", e);
                    // Carry on, listeners may still want to know.
                }
            }
        } finally {
            lock.unlock();
        }
        // Tell all listeners about this tx so they can decide whether to keep it or not. If no listener keeps a
        // reference around then the memory pool will forget about it after a while too because it uses weak references.
        for (final ListenerRegistration<PeerEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onTransaction(Peer.this, fTx);
                }
            });
        }
    }

    /**
     * <p>Returns a future that wraps a list of all transactions that the given transaction depends on, recursively.
     * Only transactions in peers memory pools are included; the recursion stops at transactions that are in the
     * current best chain. So it doesn't make much sense to provide a tx that was already in the best chain and
     * a precondition checks this.</p>
     *
     * <p>For example, if tx has 2 inputs that connect to transactions A and B, and transaction B is unconfirmed and
     * has one input connecting to transaction C that is unconfirmed, and transaction C connects to transaction D
     * that is in the chain, then this method will return either {B, C} or {C, B}. No ordering is guaranteed.</p>
     *
     * <p>This method is useful for apps that want to learn about how long an unconfirmed transaction might take
     * to confirm, by checking for unexpectedly time locked transactions, unusually deep dependency trees or fee-paying
     * transactions that depend on unconfirmed free transactions.</p>
     *
     * <p>Note that dependencies downloaded this way will not trigger the onTransaction method of event listeners.</p>
     */
    public ListenableFuture<List<Transaction>> downloadDependencies(Transaction tx) {
        checkNotNull(memoryPool, "Must have a configured MemoryPool object to download dependencies.");
        TransactionConfidence.ConfidenceType txConfidence = tx.getConfidence().getConfidenceType();
        Preconditions.checkArgument(txConfidence != TransactionConfidence.ConfidenceType.BUILDING);
        log.info("{}: Downloading dependencies of {}", vAddress, tx.getHashAsString());
        final LinkedList<Transaction> results = new LinkedList<Transaction>();
        // future will be invoked when the entire dependency tree has been walked and the results compiled.
        final ListenableFuture future = downloadDependenciesInternal(tx, new Object(), results);
        final SettableFuture<List<Transaction>> resultFuture = SettableFuture.create();
        Futures.addCallback(future, new FutureCallback() {
            public void onSuccess(Object _) {
                resultFuture.set(results);
            }

            public void onFailure(Throwable throwable) {
                resultFuture.setException(throwable);
            }
        });
        return resultFuture;
    }

    // The marker object in the future returned is the same as the parameter. It is arbitrary and can be anything.
    private ListenableFuture<Object> downloadDependenciesInternal(final Transaction tx,
                                                                  final Object marker,
                                                                  final List<Transaction> results) {
        checkNotNull(memoryPool, "Must have a configured MemoryPool object to download dependencies.");
        final SettableFuture<Object> resultFuture = SettableFuture.create();
        final Sha256Hash rootTxHash = tx.getHash();
        // We want to recursively grab its dependencies. This is so listeners can learn important information like
        // whether a transaction is dependent on a timelocked transaction or has an unexpectedly deep dependency tree
        // or depends on a no-fee transaction.
        //
        // Firstly find any that are already in the memory pool so if they weren't garbage collected yet, they won't
        // be deleted. Use COW sets to make unit tests deterministic and because they are small. It's slower for
        // the case of transactions with tons of inputs.
        Set<Transaction> dependencies = new CopyOnWriteArraySet<Transaction>();
        Set<Sha256Hash> needToRequest = new CopyOnWriteArraySet<Sha256Hash>();
        for (TransactionInput input : tx.getInputs()) {
            // There may be multiple inputs that connect to the same transaction.
            Sha256Hash hash = input.getOutpoint().getHash();
            Transaction dep = memoryPool.get(hash);
            if (dep == null) {
                needToRequest.add(hash);
            } else {
                dependencies.add(dep);
            }
        }
        results.addAll(dependencies);
        lock.lock();
        try {
            // Build the request for the missing dependencies.
            List<ListenableFuture<Transaction>> futures = Lists.newArrayList();
            GetDataMessage getdata = new GetDataMessage(params);
            final long nonce = (long)(Math.random()*Long.MAX_VALUE);
            if (needToRequest.size() > 1)
                log.info("{}: Requesting {} transactions for dep resolution", vAddress, needToRequest.size());
            for (Sha256Hash hash : needToRequest) {
                getdata.addTransaction(hash);
                GetDataRequest req = new GetDataRequest();
                req.hash = hash;
                req.future = SettableFuture.create();
                if (!isNotFoundMessageSupported()) {
                    req.nonce = nonce;
                }
                futures.add(req.future);
                getDataFutures.add(req);
            }
            // The transactions we already grabbed out of the mempool must still be considered by the code below.
            for (Transaction dep : dependencies) {
                futures.add(Futures.immediateFuture(dep));
            }
            ListenableFuture<List<Transaction>> successful = Futures.successfulAsList(futures);
            Futures.addCallback(successful, new FutureCallback<List<Transaction>>() {
                public void onSuccess(List<Transaction> transactions) {
                    // Once all transactions either were received, or we know there are no more to come ...
                    // Note that transactions will contain "null" for any positions that weren't successful.
                    List<ListenableFuture<Object>> childFutures = Lists.newLinkedList();
                    for (Transaction tx : transactions) {
                        if (tx == null) continue;
                        log.info("{}: Downloaded dependency of {}: {}", new Object[]{vAddress,
                                rootTxHash, tx.getHashAsString()});
                        results.add(tx);
                        // Now recurse into the dependencies of this transaction too.
                        childFutures.add(downloadDependenciesInternal(tx, marker, results));
                    }
                    if (childFutures.size() == 0) {
                        // Short-circuit: we're at the bottom of this part of the tree.
                        resultFuture.set(marker);
                    } else {
                        // There are some children to download. Wait until it's done (and their children and their
                        // children...) to inform the caller that we're finished.
                        Futures.addCallback(Futures.successfulAsList(childFutures), new FutureCallback<List<Object>>() {
                            public void onSuccess(List<Object> objects) {
                                resultFuture.set(marker);
                            }

                            public void onFailure(Throwable throwable) {
                                resultFuture.setException(throwable);
                            }
                        });
                    }
                }

                public void onFailure(Throwable throwable) {
                    resultFuture.setException(throwable);
                }
            });
            // Start the operation.
            sendMessage(getdata);
            if (!isNotFoundMessageSupported()) {
                // If the peer isn't new enough to support the notfound message, we use a nasty hack instead and
                // assume if we send a ping message after the getdata message, it'll be processed after all answers
                // from getdata are done, so we can watch for the pong message as a substitute.
                log.info("{}: Dep resolution waiting for a pong with nonce {}", this, nonce);
                ping(nonce).addListener(new Runnable() {
                    public void run() {
                        // The pong came back so clear out any transactions we requested but didn't get.
                        for (GetDataRequest req : getDataFutures) {
                            if (req.nonce == nonce) {
                                log.info("{}: Bottomed out dep tree at {}", this, req.hash);
                                req.future.cancel(true);
                                getDataFutures.remove(req);
                            }
                        }
                    }
                }, Threading.SAME_THREAD);
            }
        } catch (Exception e) {
            log.error("{}: Couldn't send getdata in downloadDependencies({})", this, tx.getHash());
            resultFuture.setException(e);
            return resultFuture;
        } finally {
            lock.unlock();
        }
        return resultFuture;
    }

    private void processBlock(Block m) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("{}: Received broadcast block {}", vAddress, m.getHashAsString());
        }
        // Was this block requested by getBlock()?
        if (maybeHandleRequestedData(m)) return;
        if (blockChain == null) {
            log.warn("Received block but was not configured with an AbstractBlockChain");
            return;
        }
        // Did we lose download peer status after requesting block data?
        if (!vDownloadData) {
            log.debug("{}: Received block we did not ask for: {}", vAddress, m.getHashAsString());
            return;
        }
        pendingBlockDownloads.remove(m.getHash());
        try {
            // Otherwise it's a block sent to us because the peer thought we needed it, so add it to the block chain.
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
                // (2) Filter out duplicate getblock requests (done in blockChainDownloadLocked).
                //
                // The reason for (1) is that otherwise if new blocks were solved during the middle of chain download
                // we'd do a blockChainDownloadLocked() on the new best chain head, which would cause us to try and grab the
                // chain twice (or more!) on the same connection! The block chain would filter out the duplicates but
                // only at a huge speed penalty. By finding the orphan root we ensure every getblocks looks the same
                // no matter how many blocks are solved, and therefore that the (2) duplicate filtering can work.
                //
                // We only do this if we are not currently downloading headers. If we are then we don't want to kick
                // off a request for lots more headers in parallel.
                lock.lock();
                try {
                    if (downloadBlockBodies) {
                        final Block orphanRoot = checkNotNull(blockChain.getOrphanRoot(m.getHash()));
                        blockChainDownloadLocked(orphanRoot.getHash());
                    } else {
                        log.info("Did not start chain download on solved block due to in-flight header download.");
                    }
                } finally {
                    lock.unlock();
                }
            }
        } catch (VerificationException e) {
            // We don't want verification failures to kill the thread.
            log.warn("{}: Block verification failed", vAddress, e);
        } catch (PrunedException e) {
            // Unreachable when in SPV mode.
            throw new RuntimeException(e);
        }
    }

    // TODO: Fix this duplication.
    private void endFilteredBlock(FilteredBlock m) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("{}: Received broadcast filtered block {}", vAddress, m.getHash().toString());
        }
        if (!vDownloadData) {
            log.debug("{}: Received block we did not ask for: {}", vAddress, m.getHash().toString());
            return;
        }
        if (blockChain == null) {
            log.warn("Received filtered block but was not configured with an AbstractBlockChain");
            return;
        }
        // Note that we currently do nothing about peers which maliciously do not include transactions which
        // actually match our filter or which simply do not send us all the transactions we need: it can be fixed
        // by cross-checking peers against each other.
        pendingBlockDownloads.remove(m.getBlockHeader().getHash());
        try {
            // Otherwise it's a block sent to us because the peer thought we needed it, so add it to the block chain.
            // The FilteredBlock m here contains a list of hashes, and may contain Transaction objects for a subset
            // of the hashes (those that were sent to us by the remote peer). Any hashes that haven't had a tx
            // provided in processTransaction are ones that were announced to us previously via an 'inv' so the
            // assumption is we have already downloaded them and either put them in the wallet, or threw them away
            // for being false positives.
            //
            // TODO: Fix the following protocol race.
            // It is possible for this code to go wrong such that we miss a confirmation. If the remote peer announces
            // a relevant transaction via an 'inv' and then it immediately announces the block that confirms
            // the tx before we had a chance to download it+its dependencies and provide them to the wallet, then we
            // will add the block to the chain here without the tx being in the wallet and thus it will miss its
            // confirmation and become stuck forever. The fix is to notice that there's a pending getdata for a tx
            // that appeared in this block and delay processing until it arrived ... it's complicated by the fact that
            // the data may be requested by a different peer to this one.
            if (blockChain.add(m)) {
                // The block was successfully linked into the chain. Notify the user of our progress.
                invokeOnBlocksDownloaded(m.getBlockHeader());
            } else {
                // This block is an orphan - we don't know how to get from it back to the genesis block yet. That
                // must mean that there are blocks we are missing, so do another getblocks with a new block locator
                // to ask the peer to send them to us. This can happen during the initial block chain download where
                // the peer will only send us 500 at a time and then sends us the head block expecting us to request
                // the others.
                //
                // We must do two things here:
                // (1) Request from current top of chain to the oldest ancestor of the received block in the orphan set
                // (2) Filter out duplicate getblock requests (done in blockChainDownloadLocked).
                //
                // The reason for (1) is that otherwise if new blocks were solved during the middle of chain download
                // we'd do a blockChainDownloadLocked() on the new best chain head, which would cause us to try and grab the
                // chain twice (or more!) on the same connection! The block chain would filter out the duplicates but
                // only at a huge speed penalty. By finding the orphan root we ensure every getblocks looks the same
                // no matter how many blocks are solved, and therefore that the (2) duplicate filtering can work.
                lock.lock();
                try {
                    final Block orphanRoot = checkNotNull(blockChain.getOrphanRoot(m.getHash()));
                    blockChainDownloadLocked(orphanRoot.getHash());
                } finally {
                    lock.unlock();
                }
            }
        } catch (VerificationException e) {
            // We don't want verification failures to kill the thread.
            log.warn("{}: FilteredBlock verification failed", vAddress, e);
        } catch (PrunedException e) {
            // We pruned away some of the data we need to properly handle this block. We need to request the needed
            // data from the remote peer and fix things. Or just give up.
            // TODO: Request e.getHash() and submit it to the block store before any other blocks
            throw new RuntimeException(e);
        }
    }

    private boolean maybeHandleRequestedData(Message m) {
        boolean found = false;
        Sha256Hash hash = m.getHash();
        for (GetDataRequest req : getDataFutures) {
            if (hash.equals(req.hash)) {
                req.future.set(m);
                getDataFutures.remove(req);
                found = true;
                // Keep going in case there are more.
            }
        }
        return found;
    }

    private void invokeOnBlocksDownloaded(final Block m) {
        // It is possible for the peer block height difference to be negative when blocks have been solved and broadcast
        // since the time we first connected to the peer. However, it's weird and unexpected to receive a callback
        // with negative "blocks left" in this case, so we clamp to zero so the API user doesn't have to think about it.
        final int blocksLeft = Math.max(0, (int) vPeerVersionMessage.bestHeight - checkNotNull(blockChain).getBestChainHeight());
        for (final ListenerRegistration<PeerEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onBlocksDownloaded(Peer.this, m, blocksLeft);
                }
            });
        }
    }

    private void processInv(InventoryMessage inv) throws IOException {
        List<InventoryItem> items = inv.getItems();

        // Separate out the blocks and transactions, we'll handle them differently
        List<InventoryItem> transactions = new LinkedList<InventoryItem>();
        List<InventoryItem> blocks = new LinkedList<InventoryItem>();

        for (InventoryItem item : items) {
            switch (item.type) {
                case Transaction:
                    transactions.add(item);
                    break;
                case Block:
                    blocks.add(item);
                    break;
                default:
                    throw new IllegalStateException("Not implemented: " + item.type);
            }
        }

        final boolean downloadData = this.vDownloadData;

        if (transactions.size() == 0 && blocks.size() == 1) {
            // Single block announcement. If we're downloading the chain this is just a tickle to make us continue
            // (the block chain download protocol is very implicit and not well thought out). If we're not downloading
            // the chain then this probably means a new block was solved and the peer believes it connects to the best
            // chain, so count it. This way getBestChainHeight() can be accurate.
            if (downloadData && blockChain != null) {
                if (!blockChain.isOrphan(blocks.get(0).hash)) {
                    blocksAnnounced.incrementAndGet();
                }
            } else {
                blocksAnnounced.incrementAndGet();
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
                    log.debug("{}: getdata on tx {}", vAddress, item.hash);
                    getdata.addItem(item);
                }
                // This can trigger transaction confidence listeners.
                memoryPool.seen(item.hash, this.getAddress());
            }
        }

        // If we are requesting filteredblocks we have to send a ping after the getdata so that we have a clear
        // end to the final FilteredBlock's transactions (in the form of a pong) sent to us
        boolean pingAfterGetData = false;

        lock.lock();
        try {
            if (blocks.size() > 0 && downloadData && blockChain != null) {
                // Ideally, we'd only ask for the data here if we actually needed it. However that can imply a lot of
                // disk IO to figure out what we've got. Normally peers will not send us inv for things we already have
                // so we just re-request it here, and if we get duplicates the block chain / wallet will filter them out.
                for (InventoryItem item : blocks) {
                    if (blockChain.isOrphan(item.hash) && downloadBlockBodies) {
                        // If an orphan was re-advertised, ask for more blocks unless we are not currently downloading
                        // full block data because we have a getheaders outstanding.
                        final Block orphanRoot = checkNotNull(blockChain.getOrphanRoot(item.hash));
                        blockChainDownloadLocked(orphanRoot.getHash());
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
                        // the duplicate check in blockChainDownloadLocked(). But the satoshi client may change in future so
                        // it's better to be safe here.
                        if (!pendingBlockDownloads.contains(item.hash)) {
                            if (vPeerVersionMessage.isBloomFilteringSupported() && useFilteredBlocks) {
                                getdata.addItem(new InventoryItem(InventoryItem.Type.FilteredBlock, item.hash));
                                pingAfterGetData = true;
                            } else {
                                getdata.addItem(item);
                            }
                            pendingBlockDownloads.add(item.hash);
                        }
                    }
                }
                // If we're downloading the chain, doing a getdata on the last block we were told about will cause the
                // peer to advertize the head block to us in a single-item inv. When we download THAT, it will be an
                // orphan block, meaning we'll re-enter blockChainDownloadLocked() to trigger another getblocks between the
                // current best block we have and the orphan block. If more blocks arrive in the meantime they'll also
                // become orphan.
            }
        } finally {
            lock.unlock();
        }

        if (!getdata.getItems().isEmpty()) {
            // This will cause us to receive a bunch of block or tx messages.
            sendMessage(getdata);
        }

        if (pingAfterGetData)
            sendMessage(new Ping((long) (Math.random() * Long.MAX_VALUE)));
    }

    /**
     * Asks the connected peer for the block of the given hash, and returns a future representing the answer.
     * If you want the block right away and don't mind waiting for it, just call .get() on the result. Your thread
     * will block until the peer answers.
     */
    public ListenableFuture<Block> getBlock(Sha256Hash blockHash) throws IOException {
        // This does not need to be locked.
        log.info("Request to fetch block {}", blockHash);
        GetDataMessage getdata = new GetDataMessage(params);
        getdata.addBlock(blockHash);
        return sendSingleGetData(getdata);
    }

    /**
     * Asks the connected peer for the given transaction from its memory pool. Transactions in the chain cannot be
     * retrieved this way because peers don't have a transaction ID to transaction-pos-on-disk index, and besides,
     * in future many peers will delete old transaction data they don't need.
     */
    public ListenableFuture<Transaction> getPeerMempoolTransaction(Sha256Hash hash) throws IOException {
        // This does not need to be locked.
        // TODO: Unit test this method.
        log.info("Request to fetch peer mempool tx  {}", hash);
        GetDataMessage getdata = new GetDataMessage(params);
        getdata.addTransaction(hash);
        return sendSingleGetData(getdata);
    }

    /** Sends a getdata with a single item in it. */
    private ListenableFuture sendSingleGetData(GetDataMessage getdata) throws IOException {
        // This does not need to be locked.
        Preconditions.checkArgument(getdata.getItems().size() == 1);
        GetDataRequest req = new GetDataRequest();
        req.future = SettableFuture.create();
        req.hash = getdata.getItems().get(0).hash;
        getDataFutures.add(req);
        sendMessage(getdata);
        return req.future;
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
    public void setDownloadParameters(long secondsSinceEpoch, boolean useFilteredBlocks) {
        lock.lock();
        try {
            Preconditions.checkNotNull(blockChain);
            if (secondsSinceEpoch == 0) {
                fastCatchupTimeSecs = params.getGenesisBlock().getTimeSeconds();
                downloadBlockBodies = true;
            } else {
                fastCatchupTimeSecs = secondsSinceEpoch;
                // If the given time is before the current chains head block time, then this has no effect (we already
                // downloaded everything we need).
                if (fastCatchupTimeSecs > blockChain.getChainHead().getHeader().getTimeSeconds()) {
                    downloadBlockBodies = false;
                }
            }
            this.useFilteredBlocks = useFilteredBlocks;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Links the given wallet to this peer. If you have multiple peers, you should use a {@link PeerGroup} to manage
     * them and use the {@link PeerGroup#addWallet(Wallet)} method instead of registering the wallet with each peer
     * independently, otherwise the wallet will receive duplicate notifications.
     */
    public void addWallet(Wallet wallet) {
        wallets.add(wallet);
    }

    /** Unlinks the given wallet from peer. See {@link Peer#addWallet(Wallet)}. */
    public void removeWallet(Wallet wallet) {
        wallets.remove(wallet);
    }

    /**
     * Sends the given message on the peers Channel.
     */
    public ChannelFuture sendMessage(Message m) {
        // This does not need to be locked.
        return Channels.write(vChannel, m);
    }

    // Keep track of the last request we made to the peer in blockChainDownloadLocked so we can avoid redundant and harmful
    // getblocks requests.
    @GuardedBy("lock")
    private Sha256Hash lastGetBlocksBegin, lastGetBlocksEnd;

    @GuardedBy("lock")
    private void blockChainDownloadLocked(Sha256Hash toHash) throws IOException {
        checkState(lock.isHeldByCurrentThread());
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
        // it again - but we recognize this case as special and call back into blockChainDownloadLocked to continue the
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
        BlockStore store = checkNotNull(blockChain).getBlockStore();
        StoredBlock chainHead = blockChain.getChainHead();
        Sha256Hash chainHeadHash = chainHead.getHeader().getHash();
        // Did we already make this request? If so, don't do it again.
        if (Objects.equal(lastGetBlocksBegin, chainHeadHash) && Objects.equal(lastGetBlocksEnd, toHash)) {
            log.info("blockChainDownloadLocked({}): ignoring duplicated request", toHash.toString());
            return;
        }
        log.debug("{}: blockChainDownloadLocked({}) current head = {}", new Object[]{toString(),
                toHash.toString(), chainHead.getHeader().getHashAsString()});
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
            blockLocator.add(params.getGenesisBlock().getHash());
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
    public void startBlockChainDownload() throws IOException {
        setDownloadData(true);
        // TODO: peer might still have blocks that we don't have, and even have a heavier
        // chain even if the chain block count is lower.
        final int blocksLeft = getPeerBlockHeightDifference();
        if (blocksLeft >= 0) {
            for (final ListenerRegistration<PeerEventListener> registration : eventListeners) {
                registration.executor.execute(new Runnable() {
                    @Override
                    public void run() {
                        registration.listener.onChainDownloadStarted(Peer.this, blocksLeft);
                    }
                });
            }
            // When we just want as many blocks as possible, we can set the target hash to zero.
            lock.lock();
            try {
                blockChainDownloadLocked(Sha256Hash.ZERO_HASH);
            } finally {
                lock.unlock();
            }
        }
    }

    private class PendingPing {
        // The future that will be invoked when the pong is heard back.
        public SettableFuture<Long> future;
        // The random nonce that lets us tell apart overlapping pings/pongs.
        public final long nonce;
        // Measurement of the time elapsed.
        public final long startTimeMsec;

        public PendingPing(long nonce) {
            future = SettableFuture.create();
            this.nonce = nonce;
            startTimeMsec = Utils.now().getTime();
        }

        public void complete() {
            checkNotNull(future, "Already completed");
            Long elapsed = Utils.now().getTime() - startTimeMsec;
            Peer.this.addPingTimeData(elapsed);
            log.debug("{}: ping time is {} msec", Peer.this.toString(), elapsed);
            future.set(elapsed);
            future = null;
        }
    }

    /** Adds a ping time sample to the averaging window. */
    private void addPingTimeData(long sample) {
        lastPingTimesLock.lock();
        try {
            if (lastPingTimes == null) {
                lastPingTimes = new long[PING_MOVING_AVERAGE_WINDOW];
                // Initialize the averaging window to the first sample.
                Arrays.fill(lastPingTimes, sample);
            } else {
                // Shift all elements backwards by one.
                System.arraycopy(lastPingTimes, 1, lastPingTimes, 0, lastPingTimes.length - 1);
                // And append the new sample to the end.
                lastPingTimes[lastPingTimes.length - 1] = sample;
            }
        } finally {
            lastPingTimesLock.unlock();
        }
    }

    /**
     * Sends the peer a ping message and returns a future that will be invoked when the pong is received back.
     * The future provides a number which is the number of milliseconds elapsed between the ping and the pong.
     * Once the pong is received the value returned by {@link com.google.bitcoin.core.Peer#getLastPingTime()} is
     * updated.
     * @throws ProtocolException if the peer version is too low to support measurable pings.
     */
    public ListenableFuture<Long> ping() throws IOException, ProtocolException {
        return ping((long) (Math.random() * Long.MAX_VALUE));
    }

    protected ListenableFuture<Long> ping(long nonce) throws IOException, ProtocolException {
        final VersionMessage ver = vPeerVersionMessage;
        if (!ver.isPingPongSupported())
            throw new ProtocolException("Peer version is too low for measurable pings: " + ver);
        PendingPing pendingPing = new PendingPing(nonce);
        pendingPings.add(pendingPing);
        sendMessage(new Ping(pendingPing.nonce));
        return pendingPing.future;
    }

    /**
     * Returns the elapsed time of the last ping/pong cycle. If {@link com.google.bitcoin.core.Peer#ping()} has never
     * been called or we did not hear back the "pong" message yet, returns {@link Long#MAX_VALUE}.
     */
    public long getLastPingTime() {
        lastPingTimesLock.lock();
        try {
            if (lastPingTimes == null)
                return Long.MAX_VALUE;
            return lastPingTimes[lastPingTimes.length - 1];
        } finally {
            lastPingTimesLock.unlock();
        }
    }

    /**
     * Returns a moving average of the last N ping/pong cycles. If {@link com.google.bitcoin.core.Peer#ping()} has never
     * been called or we did not hear back the "pong" message yet, returns {@link Long#MAX_VALUE}. The moving average
     * window is 5 buckets.
     */
    public long getPingTime() {
        lastPingTimesLock.lock();
        try {
            if (lastPingTimes == null)
                return Long.MAX_VALUE;
            long sum = 0;
            for (long i : lastPingTimes) sum += i;
            return (long)((double) sum / lastPingTimes.length);
        } finally {
            lastPingTimesLock.unlock();
        }
    }

    private void processPong(Pong m) {
        // Iterates over a snapshot of the list, so we can run unlocked here.
        for (PendingPing ping : pendingPings) {
            if (m.getNonce() == ping.nonce) {
                pendingPings.remove(ping);
                // This line may trigger an event listener that re-runs ping().
                ping.complete();
                return;
            }
        }
    }

    /**
     * Returns the difference between our best chain height and the peers, which can either be positive if we are
     * behind the peer, or negative if the peer is ahead of us.
     */
    public int getPeerBlockHeightDifference() {
        checkNotNull(blockChain, "No block chain configured");
        // Chain will overflow signed int blocks in ~41,000 years.
        int chainHeight = (int) getBestHeight();
        // chainHeight should not be zero/negative because we shouldn't have given the user a Peer that is to another
        // client-mode node, nor should it be unconnected. If that happens it means the user overrode us somewhere or
        // there is a bug in the peer management code.
        checkState(params.allowEmptyPeerChain() || chainHeight > 0, "Connected to peer with zero/negative chain height", chainHeight);
        return chainHeight - blockChain.getBestChainHeight();
    }

    private boolean isNotFoundMessageSupported() {
        return vPeerVersionMessage.clientVersion >= 70001;
    }

    /**
     * Returns true if this peer will try and download things it is sent in "inv" messages. Normally you only need
     * one peer to be downloading data. Defaults to true.
     */
    public boolean getDownloadData() {
        return vDownloadData;
    }

    /**
     * If set to false, the peer won't try and fetch blocks and transactions it hears about. Normally, only one
     * peer should download missing blocks. Defaults to true. Changing this value from false to true may trigger
     * a request to the remote peer for the contents of its memory pool, if Bloom filtering is active.
     */
    public void setDownloadData(boolean downloadData) {
        this.vDownloadData = downloadData;
    }

    /**
     * @return the IP address and port of peer.
     */
    public PeerAddress getAddress() {
        return vAddress;
    }

    /** Returns version data announced by the remote peer. */
    public VersionMessage getPeerVersionMessage() {
      return vPeerVersionMessage;
    }

    /** Returns version data we announce to our remote peers. */
    public VersionMessage getVersionMessage() {
      return versionMessage;
    }

    /**
     * @return the height of the best chain as claimed by peer: sum of its ver announcement and blocks announced since.
     */
    public long getBestHeight() {
      return vPeerVersionMessage.bestHeight + blocksAnnounced.get();
    }

    /**
     * The minimum P2P protocol version that is accepted. If the peer speaks a protocol version lower than this, it
     * will be disconnected.
     * @return if not-null then this is the future for the Peer disconnection event.
     */
    @Nullable public ChannelFuture setMinProtocolVersion(int minProtocolVersion) {
        this.vMinProtocolVersion = minProtocolVersion;
        if (getVersionMessage().clientVersion < minProtocolVersion) {
            log.warn("{}: Disconnecting due to new min protocol version {}", this, minProtocolVersion);
            return Channels.close(vChannel);
        } else {
            return null;
        }
    }

    /**
     * <p>Sets a Bloom filter on this connection. This will cause the given {@link BloomFilter} object to be sent to the
     * remote peer and if either a memory pool has been set using the constructor or the
     * vDownloadData property is true, a {@link MemoryPoolMessage} is sent as well to trigger downloading of any
     * pending transactions that may be relevant.</p>
     *
     * <p>The Peer does not automatically request filters from any wallets added using {@link Peer#addWallet(Wallet)}.
     * This is to allow callers to avoid redundantly recalculating the same filter repeatedly when using multiple peers
     * and multiple wallets together.</p>
     *
     * <p>Therefore, you should not use this method if your app uses a {@link PeerGroup}. It is called for you.</p>
     *
     * <p>If the remote peer doesn't support Bloom filtering, then this call is ignored. Once set you presently cannot
     * unset a filter, though the underlying p2p protocol does support it.</p>
     */
    public void setBloomFilter(BloomFilter filter) throws IOException {
        checkNotNull(filter, "Clearing filters is not currently supported");
        final VersionMessage ver = vPeerVersionMessage;
        if (ver == null || !ver.isBloomFilteringSupported())
            return;
        vBloomFilter = filter;
        boolean shouldQueryMemPool = memoryPool != null || vDownloadData;
        log.info("{}: Sending Bloom filter{}", this, shouldQueryMemPool ? " and querying mempool" : "");
        ChannelFuture future = sendMessage(filter);
        if (shouldQueryMemPool)
            future.addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture future) throws Exception {
                    sendMessage(new MemoryPoolMessage());
                }
            });
    }

    /**
     * Returns the last {@link BloomFilter} set by {@link Peer#setBloomFilter(BloomFilter)}. Bloom filters tell
     * the remote node what transactions to send us, in a compact manner.
     */
    public BloomFilter getBloomFilter() {
        return vBloomFilter;
    }
}
