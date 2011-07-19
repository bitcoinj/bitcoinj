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
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Maintain a number of connections to peers.
 * 
 * <p>PeerGroup tries to maintain a constant number of connections to a set of distinct peers.
 * Each peer runs a network listener in its own thread.  When a connection is lost, a new peer
 * will be tried after a delay as long as the number of connections less than the maximum.
 * 
 * <p>Connections are made to addresses from a provided list.  When that list is exhausted,
 * we start again from the head of the list.
 * 
 * <p>The PeerGroup can broadcast a transaction to the currently connected set of peers.  It can
 * also handle download of the blockchain from peers, restarting the process when peers die.
 * 
 * @author miron@google.com (Miron Cuperman a.k.a devrandom)
 *
 */
public class PeerGroup {
    private static final int DEFAULT_CONNECTIONS = 4;

    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    
    private static final int CONNECTION_DELAY_MILLIS = 5 * 1000;
    private static final int CORE_THREADS = 1;
    private static final int THREAD_KEEP_ALIVE_SECONDS = 1;

    // Maximum number of connections this peerGroup will make
    private int maxConnections;
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
    
    private NetworkParameters params;
    private BlockStore blockStore;
    private BlockChain chain;

    /**
     * Create a PeerGroup
     */
    public PeerGroup(BlockStore blockStore, NetworkParameters params, BlockChain chain) {
        this.maxConnections = DEFAULT_CONNECTIONS;
        this.blockStore = blockStore;
        this.params = params;
        this.chain = chain;
        
        inactives = new LinkedBlockingQueue<PeerAddress>();
        
        peers = Collections.synchronizedSet(new HashSet<Peer>());
        peerPool = new ThreadPoolExecutor(CORE_THREADS, this.maxConnections,
                THREAD_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(1),
                new PeerGroupThreadFactory());
    }

    /**
     * Depending on the environment, this should normally be between 1 and 10, default is 4.
     * 
     * @param maxConnections the maximum number of peer connections that this group will try to make.
     */
    public void setMaxConnections(int maxConnections) {
        this.maxConnections = maxConnections;
    }
    
    public int getMaxConnections() {
        return maxConnections;
    }
    
    /** Add an address to the list of potential peers to connect to */
    public void addAddress(PeerAddress peerAddress) {
        // TODO(miron) consider deduplication
        inactives.add(peerAddress);
    }
    
    /** Add addresses from a discovery source to the list of potential peers to connect to */
    public void addPeerDiscovery(PeerDiscovery peerDiscovery) {
        // TODO(miron) consider remembering the discovery source and retrying occasionally 
        InetSocketAddress[] addresses;
        try {
            addresses = peerDiscovery.getPeers();
        } catch (PeerDiscoveryException e) {
            log.error("Failed to discover peer addresses from discovery source", e);
            return;
        }
        
        for (int i = 0; i < addresses.length; i++) {
            inactives.add(new PeerAddress(addresses[i]));
        }
    }
    
    /** Starts the background thread that makes connections. */
    public void start() {
        this.connectThread = new Thread(new PeerExecutionRunnable(), "Peer group thread");
        running = true;
        this.connectThread.start();
    }

    /**
     * Stop this PeerGroup
     * 
     * <p>The peer group will be asynchronously shut down.  After it is shut down
     * all peers will be disconnected and no threads will be running.
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
        for (Peer peer : peers) {
            try {
                peer.broadcastTransaction(tx);
                success = true;
            } catch (IOException e) {
                log.error("failed to broadcast to " + peer, e);
            }
        }
        return success;
    }

    private final class PeerExecutionRunnable implements Runnable {
        /**
         * Repeatedly get the next peer address from the inactive queue
         * and try to connect.
         * 
         * <p>We can be terminated with Thread.interrupt.  When an interrupt is received,
         * we will ask the executor to shutdown and ask each peer to disconnect.  At that point
         * no threads or network connections will be active.
         */
        @Override
        public void run() {
            try {
                while (running) {
                    tryNextPeer();
                    
                    // We started a new peer connection, delay before trying another one
                    Thread.sleep(CONNECTION_DELAY_MILLIS);
                }
            } catch (InterruptedException ex) {
                synchronized (this) {
                    running = false;
                }
            }

            peerPool.shutdownNow();

            for (Peer peer : peers) {
                peer.disconnect();
            }
        }

        /*
         * Try connecting to a peer.  If we exceed the number of connections, delay and try
         * again.
         */
        private void tryNextPeer() throws InterruptedException {
            final PeerAddress address = inactives.take();
            while (true) {
                try {
                    final Peer peer = new Peer(params, address,
                            blockStore.getChainHead().getHeight(), chain);
                    Runnable command = new Runnable() {
                        @Override
                        public void run() {
                            try {
                                log.info("connecting to " + peer);
                                peer.connect();
                                peers.add(peer);
                                handleNewPeer(peer);
                                log.info("running " + peer);
                                peer.run();
                            } 
                            finally {
                                // In all cases, put the address back on the queue.
                                // We will retry this peer after all other peers have been tried.
                                inactives.add(address);
                                peers.remove(peer);
                                handlePeerDeath(peer);
                            }
                        }
                    };
                    peerPool.execute(command);
                    break;
                } catch (RejectedExecutionException e) {
                    // Reached maxConnections, try again after a delay

                    // TODO - consider being smarter about retry.  No need to retry
                    // if we reached maxConnections or if peer queue is empty.  Also consider
                    // exponential backoff on peers and adjusting the sleep time according to the
                    // lowest backoff value in queue.
                } catch (BlockStoreException e) {
                    // Fatal error
                    log.error("Block store corrupt?", e);
                    running = false;
                    break;
                }
                
                // If we got here, we should retry this address because an error unrelated
                // to the peer has occurred.
                Thread.sleep(CONNECTION_DELAY_MILLIS);
            }
        }
    }

    /**
     * Start downloading the blockchain from the first available peer.
     * 
     * <p>If no peers are currently connected, the download will be started
     * once a peer starts.  If the peer dies, the download will resume with another peer.
     * 
     * @param listener a listener for chain download events, may not be null
     */
    public synchronized void startBlockChainDownload(PeerEventListener listener) {
        this.downloadListener = listener;
        // TODO be more nuanced about which peer to download from.  We can also try
        // downloading from multiple peers and handle the case when a new peer comes along
        // with a longer chain after we thought we were done.
        if (!peers.isEmpty())
            startBlockChainDownloadFromPeer(peers.iterator().next());
    }
    
    /**
     * Download the blockchain from peers.
     * 
     * <p>This method wait until the download is complete.  "Complete" is defined as downloading
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
        if (downloadListener != null && downloadPeer == null)
            startBlockChainDownloadFromPeer(peer);
    }
    
    protected synchronized void handlePeerDeath(Peer peer) {
        if (peer == downloadPeer) {
            downloadPeer = null;
            if (downloadListener != null && !peers.isEmpty())
                startBlockChainDownloadFromPeer(peers.iterator().next());
        }
    }

    private synchronized void startBlockChainDownloadFromPeer(Peer peer) {
        peer.addEventListener(downloadListener);
        try {
            peer.startBlockChainDownload();
        } catch (IOException e) {
            log.error("failed to start block chain download from " + peer, e);
            return;
        }
        downloadPeer = peer;
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

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r,
                                  namePrefix + threadNumber.getAndIncrement(),
                                  0);
            t.setDaemon(true);
            return t;
        }
    }
}
