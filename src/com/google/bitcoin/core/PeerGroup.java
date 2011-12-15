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

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;

/**
 * Maintain a number of connections to peers.
 * <p/>
 * <p>PeerGroup tries to maintain a constant number of connections to a set of distinct peers.
 * Each peer runs a network listener in its own thread.  When a connection is lost, a new peer
 * will be tried after a delay as long as the number of connections less than the maximum.
 * <p/>
 * <p>Connections are made to addresses from a provided list.  When that list is exhausted,
 * we start again from the head of the list.
 * <p/>
 * <p>The PeerGroup can broadcast a transaction to the currently connected set of peers.  It can
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
    private Thread connectThread;
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
    private Set<PeerEventListener> peerEventListeners;
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private Set<PeerDiscovery> peerDiscoverers;

    private NetworkParameters params;
    private BlockChain chain;
    private int connectionDelayMillis;
    private long fastCatchupTimeSecs;

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

        inactives = new LinkedBlockingQueue<PeerAddress>();
        peers = Collections.synchronizedSet(new HashSet<Peer>());
        peerEventListeners = Collections.synchronizedSet(new HashSet<PeerEventListener>());
        peerDiscoverers = Collections.synchronizedSet(new HashSet<PeerDiscovery>());
        peerPool = new ThreadPoolExecutor(
                DEFAULT_CONNECTIONS,
                DEFAULT_CONNECTIONS,
                THREAD_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(1),
                new PeerGroupThreadFactory());
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
    public void addEventListener(PeerEventListener listener) {
        peerEventListeners.add(listener);
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeEventListener(PeerEventListener listener) {
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
     * use numPeers().
     */
    public synchronized List<Peer> getPeers() {
        ArrayList<Peer> result = new ArrayList<Peer>(peers.size());
        result.addAll(peers);
        return result;
    }

    /**
     * Returns the number of currently connected peers. To be informed when this count changes, register a 
     * {@link PeerEventListener} and use the onPeerConnected/onPeerDisconnected methods.
     */
    public synchronized int numPeers() {
        return peers.size();
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
        this.connectThread = new Thread(new PeerExecutionRunnable(), "Peer group thread");
        running = true;
        this.connectThread.start();
    }

    /**
     * Stop this PeerGroup.<p>
     *
     * The peer group will be asynchronously shut down.  After it is shut down all peers will be disconnected and no
     * threads will be running.
     */
    public synchronized void stop() {
        if (running) {
            connectThread.interrupt();
        }
    }

    /**
     * Broadcast a transaction to all connected peers
     *
     * @return whether we sent to at least one peer
     */
    public boolean broadcastTransaction(Transaction tx) {
        boolean success = false;
        synchronized (peers) {
            for (Peer peer : peers) {
                try {
                    peer.broadcastTransaction(tx);
                    success = true;
                } catch (IOException e) {
                    log.error("failed to broadcast to " + peer, e);
                }
            }
        }
        return success;
    }

    /**
     * Link the given wallet to this PeerGroup so it receives broadcast transactions. A convenience method that just
     * does <tt>addEventListener(wallet.getPeerEventListener());</tt>. See also removeWallet.
     */
    public void addWallet(Wallet wallet) {
        addEventListener(wallet.getPeerEventListener());
    }

    /**
     * Unlinks the given wallet so it no longer receives broadcast transactions.
     */
    public void removeWallet(Wallet wallet) {
        removeEventListener(wallet.getPeerEventListener());
    }

    private final class PeerExecutionRunnable implements Runnable {
        /*
         * Repeatedly get the next peer address from the inactive queue and try to connect.
         * 
         * <p>We can be terminated with Thread.interrupt.  When an interrupt is received,
         * we will ask the executor to shutdown and ask each peer to disconnect.  At that point
         * no threads or network connections will be active.
         */
        public void run() {
            try {
                while (running) {
                    if (inactives.size() == 0) {
                        discoverPeers();
                    } else {
                        tryNextPeer();
                    }

                    // We started a new peer connection, delay before trying another one
                    Thread.sleep(connectionDelayMillis);
                }
            } catch (InterruptedException ex) {
            }
            synchronized (PeerGroup.this) {
                running = false;
                peerPool.shutdown();
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

        /**
         * Try connecting to a peer.  If we exceed the number of connections, delay and try again.
         */
        private void tryNextPeer() throws InterruptedException {
            final PeerAddress address = inactives.take();
            while (true) {
                try {
                    Peer peer = new Peer(params, address, chain.getChainHead().getHeight(), chain);
                    executePeer(address, peer, true, ExecuteBlockMode.RETURN_IMMEDIATELY);
                    break;
                } catch (RejectedExecutionException e) {
                    // Reached maxConnections, try again after a delay

                    // TODO - consider being smarter about retry.  No need to retry
                    // if we reached maxConnections or if peer queue is empty.  Also consider
                    // exponential backoff on peers and adjusting the sleep time according to the
                    // lowest backoff value in queue.
                }
                
                // If we got here, we should retry this address because an error unrelated
                // to the peer has occurred.
                Thread.sleep(connectionDelayMillis);
            }
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
                    // We may be terminating because of a controlled shutdown. If so, don't inform the user of individual
                    // peer connections or select a new download peer.  Disconnection is the responsibility of the controlling
                    // thread in this case.
                    if (!running)
                        return;

                    // Disconnect and put the address back on the queue. We will retry this peer after all
                    // other peers have been tried.
                    peer.disconnect();

                    // We may not know the address if the peer was added directly.
                    if (address != null)
                        inactives.add(address);
                    if (peers.remove(peer))
                        handlePeerDeath(peer);
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
     * Download the blockchain from peers.<p>
     * <p/>
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

    protected synchronized void handleNewPeer(Peer peer) {
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
        synchronized (peerEventListeners) {
            for (PeerEventListener listener : peerEventListeners) {
                synchronized (listener) {
                    listener.onPeerConnected(peer, peers.size());
                }
            }
        }
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
            for (PeerEventListener listener : peerEventListeners) {
                downloadPeer.addEventListener(listener);
            }
        }
    }

    protected synchronized void handlePeerDeath(Peer peer) {
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

        synchronized (peerEventListeners) {
            for (PeerEventListener listener : peerEventListeners) {
                synchronized (listener) {
                    listener.onPeerDisconnected(peer, peers.size());
                }
            }
        }
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
