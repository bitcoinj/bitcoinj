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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
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
 * @author miron@google.com (Miron Cuperman a.k.a devrandom)
 *
 */
public class PeerGroup {
    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    
    private static final int CONNECTION_DELAY_MILLIS = 5 * 1000;
    private static final int CORE_THREADS = 1;
    private static final int THREAD_KEEP_ALIVE_SECONDS = 1;

    // Maximum number of connections this peerGroup will make
    private int maxConnections;
    private BlockingQueue<PeerAddress> inactives;
    private Thread thread;
    private boolean running;
    private ThreadPoolExecutor executor;
    private NetworkParameters params;
    private BlockStore blockStore;
    private BlockChain chain;
    private Set<Peer> peers;
    private Peer downloadPeer;

    private PeerEventListener downloadListener;

    /**
     */
    public PeerGroup(int maxConnections, BlockStore blockStore, NetworkParameters params, BlockChain chain) {
        this.maxConnections = maxConnections;
        this.blockStore = blockStore;
        this.params = params;
        this.chain = chain;
        
        inactives = new LinkedBlockingQueue<PeerAddress>();
        
        peers = Collections.synchronizedSet(new HashSet<Peer>());
        executor = new ThreadPoolExecutor(CORE_THREADS, this.maxConnections,
                THREAD_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(1),
                new PeerGroupThreadFactory());
    }

    /** Add an address to the list of potential peers to connect to */
    public void addAddress(PeerAddress peerAddress) {
        inactives.add(peerAddress);
    }
    
    /** Starts the background thread that makes connections. */
    public void start() {
        this.thread = new Thread(new PeerExecutionRunnable(), "Peer group thread");
        running = true;
        this.thread.start();
    }

    /**
     * Stop this PeerGroup 
     */
    public synchronized void stop() {
        if (running) {
            thread.interrupt();
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

            executor.shutdownNow();

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
                                // In all cases, put the address back on the queue
                                inactives.add(address);
                                peers.remove(peer);
                                handlePeerDeath(peer);
                            }
                        }
                    };
                    executor.execute(command);
                    break;
                }
                catch (RejectedExecutionException e) {
                    // Reached maxConnections, try again after a delay
                } catch (BlockStoreException e) {
                    log.error("block store corrupt?", e);
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
     */
    public synchronized void startBlockChainDownload(PeerEventListener listener) {
        this.downloadListener = listener;
        if (!peers.isEmpty())
            startBlockChainDownloadFromPeer(peers.iterator().next());
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

    private void startBlockChainDownloadFromPeer(Peer peer) {
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
            SecurityManager s = System.getSecurityManager();
            group = (s != null)? s.getThreadGroup() :
                                 Thread.currentThread().getThreadGroup();
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
