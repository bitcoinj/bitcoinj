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

import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import com.google.bitcoin.utils.EventListenerInvoker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Maintain a number of connections to peers.<p>
 * 
 * PeerGroup tries to maintain a constant number of connections to a set of distinct peers.
 * Each peer runs a network listener in its own thread.  When a connection is lost, a new peer
 * will be tried after a delay as long as the number of connections less than the maximum.<p>
 * 
 * Connections are made to addresses from a provided list.  When that list is exhausted,
 * we start again from the head of the list.<p>
 * 
 * The PeerGroup can broadcast a transaction to the currently connected set of peers.  It can
 * also handle download of the blockchain from peers, restarting the process when peers die.
 *
 * @author miron@google.com (Miron Cuperman a.k.a devrandom)
 */
public class PeerGroup {
    private static final int DEFAULT_CONNECTIONS = 4;

    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);

    public static final int DEFAULT_CONNECTION_DELAY_MILLIS = 5 * 1000;
    private static final int THREAD_KEEP_ALIVE_SECONDS = 1;

    // Addresses to try to connect to, excluding active peers
    private BlockingQueue<PeerAddress> inactives;
    // Connection initiation thread
    private PeerGroupThread peerGroupThread;
    // True if the connection initiation thread should be running
    private boolean running;
    // A pool of threads for peers, of size maxConnection
    private ThreadPoolExecutor peerPool;
    // Currently active peers
    private Set<Peer> peers;
    // The peer we are currently downloading the chain from
    private Peer downloadPeer;
    // Callback for events related to chain download
    private PeerEventListener downloadListener;
    // Callbacks for events related to peer connection/disconnection
    private List<PeerEventListener> peerEventListeners;
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private Set<PeerDiscovery> peerDiscoverers;
    // The version message to use for new connections.
    private VersionMessage versionMessage;

    private NetworkParameters params;
    private BlockChain chain;
    private int connectionDelayMillis;
    private long fastCatchupTimeSecs;
    private ArrayList<Wallet> wallets;
    private AbstractPeerEventListener getDataListener;

    /**
     * Creates a PeerGroup with the given parameters and a default 5 second connection timeout. If you don't care
     * about blocks or pending transactions, you can just provide a MemoryBlockStore and a newly created Wallet.
     *
     * @param params Network parameters
     * @param chain a BlockChain object that will receive and handle block messages.
     */
    public PeerGroup(NetworkParameters params, BlockChain chain) {
        this(params, chain, DEFAULT_CONNECTION_DELAY_MILLIS);
    }

    /**
     * Creates a PeerGroup with the given parameters. The connectionDelayMillis parameter controls how long the
     * PeerGroup will wait between attempts to connect to nodes or read from any added peer discovery sources.
     */
    public PeerGroup(NetworkParameters params, BlockChain chain, int connectionDelayMillis) {
        this.params = params;
        this.chain = chain;
        this.connectionDelayMillis = connectionDelayMillis;
        this.fastCatchupTimeSecs = params.genesisBlock.getTimeSeconds();
        this.wallets = new ArrayList<Wallet>(1);

        // Set up a default template version message that doesn't tell the other side what kind of BitCoinJ user
        // this is.
        this.versionMessage = new VersionMessage(params, chain.getBestChainHeight());

        inactives = new LinkedBlockingQueue<PeerAddress>();
        // TODO: Remove usage of synchronized sets here in favor of simple coarse-grained locking.
        peers = Collections.synchronizedSet(new HashSet<Peer>());
        peerDiscoverers = new CopyOnWriteArraySet<PeerDiscovery>(); 
        peerPool = new ThreadPoolExecutor(
                DEFAULT_CONNECTIONS,
                DEFAULT_CONNECTIONS,
                THREAD_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(1),
                new PeerGroupThreadFactory());
        // peerEventListeners get a subset of events seen by the group. We add our own internal listener to this so
        // when we download a transaction, we can distribute it to each Peer in the pool so they can update the
        // transactions confidence level if they've seen it be announced/when they see it be announced.
        peerEventListeners = new ArrayList<PeerEventListener>();
        addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onTransaction(Peer peer, Transaction t) {
                handleBroadcastTransaction(t);
            }
        });

        // This event listener is added to every peer. It's here so when we announce transactions via an "inv", every
        // peer can fetch them.
        getDataListener = new AbstractPeerEventListener() {
            @Override
            public List<Message> getData(Peer peer, GetDataMessage m) {
                return handleGetData(m);
            }
        };
    }

    private synchronized List<Message> handleGetData(GetDataMessage m) {
        // Scans the wallets for transactions in the getdata message and returns them. Invoked in parallel on peer threads.
        HashMap<Sha256Hash, Message> transactions = new HashMap<Sha256Hash, Message>();
        for (Wallet w : wallets) {
            synchronized (w) {
                for (InventoryItem item : m.getItems()) {
                    Transaction tx = w.getTransaction(item.hash);
                    if (tx == null) continue;
                    transactions.put(tx.getHash(), tx);
                }
            }
        }
        return new LinkedList<Message>(transactions.values());
    }

    private synchronized void handleBroadcastTransaction(Transaction tx) {
        // Called on the download peer thread when we have downloaded an advertised Transaction. Distribute it to all
        // the peers in the group so they can update the confidence if they saw it be advertised or when they do see it.
        for (Peer p : peers) {
            p.trackTransaction(tx);
        }
    }

    /**
     * Sets the {@link VersionMessage} that will be announced on newly created connections. A version message is
     * primarily interesting because it lets you customize the "subVer" field which is used a bit like the User-Agent
     * field from HTTP. It means your client tells the other side what it is, see
     * <a href="https://en.bitcoin.it/wiki/BIP_0014">BIP 14</a>.
     *
     * The VersionMessage you provide is copied and the best chain height/time filled in for each new connection,
     * therefore you don't have to worry about setting that. The provided object is really more of a template.
     */
    public synchronized void setVersionMessage(VersionMessage ver) {
        versionMessage = ver;
    }

    /**
     * Returns the version message provided by setVersionMessage or a default if none was given.
     */
    public synchronized VersionMessage getVersionMessage() {
        return versionMessage;
    }

    /**
     * Sets information that identifies this software to remote nodes. This is a convenience wrapper for creating 
     * a new {@link VersionMessage}, calling {@link VersionMessage#appendToSubVer(String, String, String)} on it,
     * and then calling {@link PeerGroup#setVersionMessage(VersionMessage)} on the result of that. See the docs for
     * {@link VersionMessage#appendToSubVer(String, String, String)} for information on what the fields should contain.
     *
     * @param name
     * @param version
     */
    public void setUserAgent(String name, String version, String comments) {
        VersionMessage ver = new VersionMessage(params, 0);
        ver.appendToSubVer(name, version, comments);
        setVersionMessage(ver);
    }

    /**
     * Sets information that identifies this software to remote nodes. This is a convenience wrapper for creating
     * a new {@link VersionMessage}, calling {@link VersionMessage#appendToSubVer(String, String, String)} on it,
     * and then calling {@link PeerGroup#setVersionMessage(VersionMessage)} on the result of that. See the docs for
     * {@link VersionMessage#appendToSubVer(String, String, String)} for information on what the fields should contain.
     *
     * @param name
     * @param version
     */
    public void setUserAgent(String name, String version) {
        setUserAgent(name, version, null);
    }


    /**
     * <p>Adds a listener that will be notified on a library controlled thread when:</p>
     * <ol>
     *     <li>New peers are connected to.</li>
     *     <li>Peers are disconnected from.</li>
     *     <li>A message is received by the download peer (there is always one peer which is elected as a peer which
     *     will be used to retrieve data).
     *     <li>Blocks are downloaded by the download peer.</li>
     *     </li>
     * </ol>
     * <p>The listener will be locked during callback execution, which in turn will cause network message processing
     * to stop until the listener returns.</p>
     */
    public synchronized void addEventListener(PeerEventListener listener) {
        assert listener != null;
        peerEventListeners.add(listener);
    }

    /** The given event listener will no longer be called with events. */
    public synchronized boolean removeEventListener(PeerEventListener listener) {
        return peerEventListeners.remove(listener);
    }

    /**
     * Use this to directly add an already initialized and connected {@link Peer} object. Normally, you would prefer
     * to use {@link PeerGroup#addAddress(PeerAddress)} and let this object handle construction of the peer for you.
     * This method is useful when you are working closely with the network code (and in unit tests).<p>
     *
     * Note that if this peer group already has the maximum number of peers running (see {@link PeerGroup#DEFAULT_CONNECTIONS})
     * then this method will block until other peers are disconnected.<p>
     *
     * Calling this will result in calls to any registered {@link PeerEventListener}s. Block chain download may occur.
     */
    public void addPeer(Peer peer) {
        synchronized (this) {
            if (!running)
                throw new IllegalStateException("Must call start() before adding peers.");
            log.info("Adding directly to group: {}", peer);
        }
        // This starts the peer thread running. Note: this is not synchronized. If it were, we could not
        // use WAIT_FOR_STARTUP mode below because the newly created thread will call handleNewPeer() which is locked.
        executePeer(null, peer, false, ExecuteBlockMode.WAIT_FOR_STARTUP);
    }
    
    /**
     * Depending on the environment, this should normally be between 1 and 10, default is 4.
     *
     * @param maxConnections the maximum number of peer connections that this group will try to make.
     */
    public synchronized void setMaxConnections(int maxConnections) {
        peerPool.setCorePoolSize(Math.min(maxConnections, DEFAULT_CONNECTIONS));
        peerPool.setMaximumPoolSize(maxConnections);
    }

    public synchronized int getMaxConnections() {
        return peerPool.getMaximumPoolSize();
    }
    
    /**
     * Returns a newly allocated list containing the currently connected peers. If all you care about is the count,
     * use numConnectedPeers().
     */
    public synchronized List<Peer> getConnectedPeers() {
        ArrayList<Peer> result = new ArrayList<Peer>(peers.size());
        result.addAll(peers);
        return result;
    }

    /**
     * Add an address to the list of potential peers to connect to
     */
    public void addAddress(PeerAddress peerAddress) {
        // TODO(miron) consider deduplication
        inactives.add(peerAddress);
    }

    /**
     * Add addresses from a discovery source to the list of potential peers to connect to
     */
    public void addPeerDiscovery(PeerDiscovery peerDiscovery) {
        peerDiscoverers.add(peerDiscovery);
    }

    /**
     * Starts the background thread that makes connections.
     */
    public synchronized void start() {
        this.peerGroupThread = new PeerGroupThread();
        running = true;
        this.peerGroupThread.start();
    }

    /**
     * Stop this PeerGroup.
     *
     * <p>The peer group will be asynchronously shut down.  Some time after it is shut down all peers
     * will be disconnected and no threads will be running.
     * 
     * <p>It is an error to call any other method on PeerGroup after calling this one.
     */
    public synchronized void stop() {
        if (running) {
            running = false;
            peerGroupThread.interrupt();
        }
    }

    /**
     * Queues a transaction for asynchronous broadcast. The transaction will be considered broadcast and forgotten 
     * about (by the PeerGroup) once it's been written out to at least one node, but that does not guarantee inclusion
     * in the chain - incorrect fees or a flaky remote node can cause this as well. Wallets attached with 
     * {@link PeerGroup#addWallet(Wallet)} will have their pending transactions announced to every newly connected
     * node.
     *
     * @return a Future that can be used to wait for the async broadcast to complete.
     */
    public Future<Transaction> broadcastTransaction(final Transaction tx) {
        FutureTask<Transaction> future = new FutureTask<Transaction>(new Runnable() {
            public void run() {
                // This is run with the peer group already locked.
                for (Peer peer : peers) {
                    try {
                        peer.sendMessage(tx);
                    } catch (IOException e) {
                        log.warn("Caught IOException whilst sending transaction: {}", e.getMessage());
                    }
                }
            }
        }, tx);
        peerGroupThread.addTask(future);
        return future;
    }

    /**
     * Link the given wallet to this PeerGroup. This is used for two purposes:
     * <ol>
     *   <li>So the wallet receives broadcast transactions.</li>
     *   <li>Announcing pending transactions that didn't get into the chain yet to our peers.</li>
     * </ol>
     */
    public synchronized void addWallet(Wallet wallet) {
        if (wallet == null)
            throw new IllegalArgumentException("wallet is null");
        wallets.add(wallet);
        addEventListener(wallet.getPeerEventListener());
        announcePendingWalletTransactions(Collections.singletonList(wallet), peers);
    }

    /**
     * Unlinks the given wallet so it no longer receives broadcast transactions or has its transactions announced.
     */
    public void removeWallet(Wallet wallet) {
        if (wallet == null)
            throw new IllegalArgumentException("wallet is null");
        wallets.remove(wallet);
        removeEventListener(wallet.getPeerEventListener());
    }

    /**
     * Returns the number of currently connected peers. To be informed when this count changes, register a 
     * {@link PeerEventListener} and use the onPeerConnected/onPeerDisconnected methods.
     */
    public synchronized int numConnectedPeers() {
        synchronized (peers) {
            return peers.size();
        }
    }

    public synchronized boolean isRunning() {
        return running;
    }

    /**
     * Performs various tasks for the peer group: connects to new nodes to keep the currently connected node count at
     * the right level, runs peer discovery if we run out, and broadcasts transactions that were submitted via
     * broadcastTransaction().
     */
    private final class PeerGroupThread extends Thread {
        private LinkedBlockingQueue<FutureTask> tasks;

        public PeerGroupThread() {
            super("Peer group thread");
            tasks = new LinkedBlockingQueue<FutureTask>();
            // Ensure we don't fight with UI threads.
            setPriority(Math.max(Thread.MIN_PRIORITY, Thread.currentThread().getPriority() - 1));
            setDaemon(true);
        }

        public void run() {
            try {
                while (isRunning()) {
                    // Modify the peer group under its lock, always.
                    int numPeers;
                    
                    synchronized (PeerGroup.this) {
                        numPeers = peers.size();
                    }
                    
                    if (inactives.size() == 0) {
                        discoverPeers();
                    } else if (numPeers < getMaxConnections()) {
                        tryNextPeer();
                    }

                    // Wait for a task or the connection polling timeout to elapse. Tasks are only eligible to run
                    // when there is at least one active peer.
                    // TODO: Remove the need for this polling, only wake up the peer group thread when there's actually
                    // something useful to do.
                    if (numPeers > 0) {
                        FutureTask task = tasks.poll(connectionDelayMillis, TimeUnit.MILLISECONDS);
                        if (task != null) {
                            synchronized (PeerGroup.this) {
                                task.run();
                            }
                        }
                    } else {
                        // TODO: This should actually be waiting for a peer to become active OR the timeout to elapse.
                        Thread.sleep(connectionDelayMillis);
                    }
                }
            } catch (InterruptedException ex) {
            }
            
            // We were asked to stop.  Reset running flag and disconnect all peers.  Peers could
            // still linger until their event loop is scheduled.
            synchronized (PeerGroup.this) {
                running = false;
                peerPool.shutdown();
                shutdownPeerDiscovery();
                synchronized (peers) {
                    for (Peer peer : peers) {
                        peer.disconnect();
                    }
                }
                peers = null; // Fail quickly if someone tries to access peers while we are shutting down.
            }
        }

        private void discoverPeers() {
            for (PeerDiscovery peerDiscovery : peerDiscoverers) {
                InetSocketAddress[] addresses;
                try {
                    addresses = peerDiscovery.getPeers();
                } catch (PeerDiscoveryException e) {
                    // Will try again later.
                    log.error("Failed to discover peer addresses from discovery source", e);
                    return;
                }

                for (int i = 0; i < addresses.length; i++) {
                    inactives.add(new PeerAddress(addresses[i]));
                }

                if (inactives.size() > 0) break;
            }
        }
        
        private void shutdownPeerDiscovery() {
            for (PeerDiscovery peerDiscovery : peerDiscoverers) {
                peerDiscovery.shutdown();
            }
        }

        /**
         * Try connecting to a peer.  If we exceed the number of connections, delay and try again.
         */
        private void tryNextPeer() throws InterruptedException {
            PeerAddress address = inactives.take();
            while (true) {
                try {
                    VersionMessage ver = getVersionMessage().duplicate();
                    ver.bestHeight = chain.getBestChainHeight();
                    ver.time = Utils.now().getTime() / 1000;
                    Peer peer = new Peer(params, address, chain, ver);
                    executePeer(address, peer, true, ExecuteBlockMode.RETURN_IMMEDIATELY);
                    break;
                } catch (RejectedExecutionException e) {
                    // Reached maxConnections, try again after a delay

                    // TODO - consider being smarter about retry.  No need to retry
                    // if we reached maxConnections or if peer queue is empty.  Also consider
                    // exponential backoff on peers and adjusting the sleep time according to the
                    // lowest backoff value in queue.
                }
                
                synchronized (PeerGroup.this) {
                    // Check if we are shutting down before next try
                    if (!running)
                        break;
                }
                
                // If we got here, we should retry this address because an error unrelated
                // to the peer has occurred.
                Thread.sleep(connectionDelayMillis);
            }
        }

        /**
         * Add a task to be executed on the peer thread. Tasks are run with the peer group locked and when there is
         * at least one peer.
         */
        public synchronized <T> void addTask(FutureTask<T> task) {
            tasks.add(task);
        }
    }

    private enum ExecuteBlockMode {
        WAIT_FOR_STARTUP, RETURN_IMMEDIATELY
    }

    private void executePeer(final PeerAddress address, final Peer peer, final boolean shouldConnect,
                             final ExecuteBlockMode blockUntilRunning) {
        final CountDownLatch latch = new CountDownLatch(1);
        peerPool.execute(new Runnable() {
            public void run() {
                try {
                    if (shouldConnect) {
                        log.info("Connecting to " + peer);
                        peer.connect();
                    }
                    synchronized (PeerGroup.this) {
                        // We may have started shutting down the group since we started connecting.
                        // In this case, we must not add ourself to the list of peers because the controller
                        // thread already went through it.
                        if (!running) {
                            peer.disconnect();
                            return;
                        }
                        peers.add(peer);
                    }
                    handleNewPeer(peer);
                    if (blockUntilRunning == ExecuteBlockMode.WAIT_FOR_STARTUP)
                        latch.countDown();
                    peer.run();
                } catch (PeerException ex) {
                    // Do not propagate PeerException - log and try next peer. Suppress stack traces for
                    // exceptions we expect as part of normal network behaviour.
                    final Throwable cause = ex.getCause();
                    if (cause instanceof SocketTimeoutException) {
                        log.info("Timeout talking to " + peer + ": " + cause.getMessage());
                    } else if (cause instanceof ConnectException) {
                        log.info("Could not connect to " + peer + ": " + cause.getMessage());
                    } else if (cause instanceof IOException) {
                        log.info("Error talking to " + peer + ": " + cause.getMessage());
                    } else {
                        log.error("Unexpected exception whilst talking to " + peer, ex);
                    }
                } finally {
                    boolean needHandleDeath;
                    synchronized (PeerGroup.this) {
                        // We may be terminating because of a controlled shutdown. If so, don't inform the user of individual
                        // peer connections or select a new download peer.  Disconnection is the responsibility of the controlling
                        // thread in this case.
                        if (!running)
                            return;

                        // Disconnect and put the address back on the queue. We will retry this peer after all
                        // other peers have been tried.
                        peer.disconnect();

                        needHandleDeath = peers.remove(peer);
                    }
                    
                    // This is unsynchronized since it can take a while.
                    if (needHandleDeath)
                        handlePeerDeath(peer);

                    // We may not know the address if the peer was added directly.
                    if (address != null)
                        inactives.add(address);
                }
            }
        });

        if (blockUntilRunning == ExecuteBlockMode.WAIT_FOR_STARTUP) {
            try {
                latch.await();
            } catch (InterruptedException e) {
            }
        }
    }

    /**
     * Start downloading the blockchain from the first available peer.
     * <p/>
     * <p>If no peers are currently connected, the download will be started
     * once a peer starts.  If the peer dies, the download will resume with another peer.
     *
     * @param listener a listener for chain download events, may not be null
     */
    public synchronized void startBlockChainDownload(PeerEventListener listener) {
        this.downloadListener = listener;
        // TODO: be more nuanced about which peer to download from.  We can also try
        // downloading from multiple peers and handle the case when a new peer comes along
        // with a longer chain after we thought we were done.
        synchronized (peers) {
            if (!peers.isEmpty()) {
                startBlockChainDownloadFromPeer(peers.iterator().next());
            }
        }
    }

    /**
     * Download the blockchain from peers. Convenience that uses a {@link DownloadListener} for you.<p>
     * 
     * This method waits until the download is complete.  "Complete" is defined as downloading
     * from at least one peer all the blocks that are in that peer's inventory.
     */
    public void downloadBlockChain() {
        DownloadListener listener = new DownloadListener();
        startBlockChainDownload(listener);
        try {
            listener.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    protected synchronized void handleNewPeer(final Peer peer) {
        log.info("Handling new {}", peer);
        // If we want to download the chain, and we aren't currently doing so, do so now.
        if (downloadListener != null && downloadPeer == null) {
            log.info("  starting block chain download");
            startBlockChainDownloadFromPeer(peer);
        } else if (downloadPeer == null) {
            setDownloadPeer(peer);
        } else {
            peer.setDownloadData(false);
        }
        // Now tell the peers about any transactions we have which didn't appear in the chain yet. These are not
        // necessarily spends we created. They may also be transactions broadcast across the network that we saw,
        // which are relevant to us, and which we therefore wish to help propagate (ie they send us coins).
        peer.addEventListener(getDataListener);
        announcePendingWalletTransactions(wallets, Collections.singleton(peer));
        EventListenerInvoker.invoke(peerEventListeners, new EventListenerInvoker<PeerEventListener>() {
            @Override
            public void invoke(PeerEventListener listener) {
                listener.onPeerConnected(peer, peers.size());
            }
        });
    }

    /** Returns true if at least one peer received an inv. */
    private synchronized boolean announcePendingWalletTransactions(List<Wallet> announceWallets,
                                                                   Set<Peer> announceToPeers) {
        // Build up an inv announcing the hashes of all pending transactions in all our wallets.
        InventoryMessage inv = new InventoryMessage(params);
        for (Wallet w : announceWallets) {
            for (Transaction tx : w.getPendingTransactions()) {
                inv.addTransaction(tx);
            }
        }
        // Don't send empty inv messages.
        if (inv.getItems().size() == 0) {
            return true;
        }
        boolean success = false;
        for (Peer p : announceToPeers) {
            try {
                p.sendMessage(inv);
                success = true;
            } catch (IOException e) {
                log.warn("Failed to announce 'inv' to peer: {}", p);
            }
        }
        return success;
    }

    private synchronized void setDownloadPeer(Peer peer) {
        if (downloadPeer != null) {
            log.info("Unsetting download peer: {}", downloadPeer);
            downloadPeer.setDownloadData(false);
            for (PeerEventListener listener : peerEventListeners) {
                downloadPeer.removeEventListener(listener);
            }
        }
        downloadPeer = peer;
        if (downloadPeer != null) {
            log.info("Setting download peer: {}", downloadPeer);
            downloadPeer.setDownloadData(true);
            downloadPeer.setFastCatchupTime(fastCatchupTimeSecs);
            for (PeerEventListener listener : peerEventListeners) {
                downloadPeer.addEventListener(listener);
            }
        }
    }

    /**
     * Tells the PeerGroup to download only block headers before a certain time and bodies after that. See
     * {@link Peer#setFastCatchupTime(long)} for further explanation. Call this before starting block chain download.
     */
    public synchronized void setFastCatchupTimeSecs(long secondsSinceEpoch) {
        fastCatchupTimeSecs = secondsSinceEpoch;
        if (downloadPeer != null) {
            downloadPeer.setFastCatchupTime(secondsSinceEpoch);
        }
    }

    protected synchronized void handlePeerDeath(final Peer peer) {
        if (!isRunning()) {
            log.info("Peer death while shutting down");
            return;
        }
        assert !peers.contains(peer);
        if (peer == downloadPeer) {
            log.info("Download peer died. Picking a new one.");
            setDownloadPeer(null);
            // Pick a new one and possibly tell it to download the chain.
            synchronized (peers) {
                if (!peers.isEmpty()) {
                    Peer next = peers.iterator().next();
                    setDownloadPeer(next);
                    if (downloadListener != null) {
                        startBlockChainDownloadFromPeer(next);
                    }
                }
            }
        }
        peer.removeEventListener(getDataListener);
        EventListenerInvoker.invoke(peerEventListeners, new EventListenerInvoker<PeerEventListener>() {
            @Override
            public void invoke(PeerEventListener listener) {
                listener.onPeerDisconnected(peer, peers.size());
            }
        });
    }

    private synchronized void startBlockChainDownloadFromPeer(Peer peer) {
        try {
            peer.addEventListener(downloadListener);
            setDownloadPeer(peer);
            // startBlockChainDownload will setDownloadData(true) on itself automatically.
            peer.startBlockChainDownload();
        } catch (IOException e) {
            log.error("failed to start block chain download from " + peer, e);
            return;
        }
    }

    static class PeerGroupThreadFactory implements ThreadFactory {
        static final AtomicInteger poolNumber = new AtomicInteger(1);
        final ThreadGroup group;
        final AtomicInteger threadNumber = new AtomicInteger(1);
        final String namePrefix;

        PeerGroupThreadFactory() {
            group = Thread.currentThread().getThreadGroup();
            namePrefix = "PeerGroup-" +
                    poolNumber.getAndIncrement() +
                    "-thread-";
        }

        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r,
                    namePrefix + threadNumber.getAndIncrement(),
                    0);
            // Lower the priority of the peer threads. This is to avoid competing with UI threads created by the API
            // user when doing lots of work, like downloading the block chain. We select a priority level one lower
            // than the parent thread, or the minimum.
            t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.currentThread().getPriority() - 1));
            t.setDaemon(true);
            return t;
        }
    }
}
