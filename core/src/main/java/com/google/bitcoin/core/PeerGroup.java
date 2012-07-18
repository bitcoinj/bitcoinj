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

import com.google.bitcoin.core.Peer.PeerHandler;
import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import com.google.bitcoin.utils.EventListenerInvoker;
import com.google.common.base.Preconditions;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.channel.*;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

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

    // Addresses to try to connect to, excluding active peers
    private BlockingQueue<PeerAddress> inactives;
    // Connection initiation thread
    private PeerGroupThread peerGroupThread;
    // True if the connection initiation thread should be running
    private boolean running;
    // Currently active peers
    private Set<Peer> peers;
    // Currently connecting peers
    private Set<Peer> pendingPeers;
    private Map<Peer, ChannelFuture> channelFutures;
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
    // A class that tracks recent transactions that have been broadcast across the network, counts how many
    // peers announced them and updates the transaction confidence data. It is passed to each Peer.
    private final MemoryPool memoryPool;
    private int maxConnections;

    private final NetworkParameters params;
    private final BlockChain chain;
    private int connectionDelayMillis;
    private long fastCatchupTimeSecs;
    private ArrayList<Wallet> wallets;
    private AbstractPeerEventListener getDataListener;

    private ClientBootstrap bootstrap;

    private class PeerStartupListener extends AbstractPeerEventListener {
        public void onPeerConnected(Peer peer, int peerCount) {
            pendingPeers.remove(peer);
            peers.add(peer);
            handleNewPeer(peer);
        }

        public void onPeerDisconnected(Peer peer, int peerCount) {
            pendingPeers.remove(peer);
            peers.remove(peer);
            channelFutures.remove(peer);
            handlePeerDeath(peer);
        }
    }

    // Visible for testing
    PeerEventListener startupListener = new PeerStartupListener();

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
     * Creates a PeerGroup with the given parameters. The connectionDelayMillis parameter controls 
     * 
     * @param params bitcoin network parameters
     * @param chain the block chain maintained by the network
     * @param connectionDelayMillis how long to wait between attempts to connect to nodes or read
     *                              from any added peer discovery sources
     */
    public PeerGroup(final NetworkParameters params, final BlockChain chain,
            int connectionDelayMillis) {
        this(params, chain, connectionDelayMillis, new ClientBootstrap(
                new NioClientSocketChannelFactory(
                        Executors.newCachedThreadPool(), 
                        Executors.newCachedThreadPool())));
        bootstrap.setPipelineFactory(makePipelineFactory(params, chain));
    }

    PeerGroup(final NetworkParameters params, final BlockChain chain,
            int connectionDelayMillis, ClientBootstrap bootstrap) {
        this.params = params;
        this.chain = chain;
        this.connectionDelayMillis = connectionDelayMillis;
        this.fastCatchupTimeSecs = params.genesisBlock.getTimeSeconds();
        this.wallets = new ArrayList<Wallet>(1);
        this.maxConnections = DEFAULT_CONNECTIONS;

        // Set up a default template version message that doesn't tell the other side what kind of BitCoinJ user
        // this is.
        this.versionMessage = new VersionMessage(params, chain.getBestChainHeight());

        memoryPool = new MemoryPool();
        this.bootstrap = bootstrap;

        inactives = new LinkedBlockingQueue<PeerAddress>();
        // TODO: Remove usage of synchronized sets here in favor of simple coarse-grained locking.
        peers = Collections.synchronizedSet(new HashSet<Peer>());
        pendingPeers = Collections.synchronizedSet(new HashSet<Peer>());
        channelFutures = Collections.synchronizedMap(new HashMap<Peer, ChannelFuture>());
        peerDiscoverers = new CopyOnWriteArraySet<PeerDiscovery>(); 
        peerEventListeners = new ArrayList<PeerEventListener>();
        // This event listener is added to every peer. It's here so when we announce transactions via an "inv", every
        // peer can fetch them.
        getDataListener = new AbstractPeerEventListener() {
            @Override
            public List<Message> getData(Peer peer, GetDataMessage m) {
                return handleGetData(m);
            }
        };
    }

    // Create a Netty pipeline factory.  The pipeline factory will create a network processing
    // pipeline with the bitcoin serializer ({@code TCPNetworkConnection}) downstream
    // of the higher level {@code Peer}.  Received packets will first be decoded, then passed
    // {@code Peer}.  Sent packets will be created by the {@code Peer}, then encoded and sent.
    private ChannelPipelineFactory makePipelineFactory(
            final NetworkParameters params, final BlockChain chain) {
        return new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                VersionMessage ver = getVersionMessage().duplicate();
                ver.bestHeight = chain.getBestChainHeight();
                ver.time = Utils.now().getTime() / 1000;

                ChannelPipeline p = Channels.pipeline();
                
                Peer peer = new Peer(params, chain, ver);
                peer.addEventListener(startupListener);
                pendingPeers.add(peer);
                TCPNetworkConnection codec =
                    new TCPNetworkConnection(params,
                            peer.getVersionMessage());
                p.addLast("codec", codec.getHandler());
                p.addLast("peer", peer.getHandler());
                return p;
            }
        };
    }

    /** The maximum number of connections that we will create to peers. */
    public void setMaxConnections(int maxConnections) {
        this.maxConnections = maxConnections;
    }

    /** The maximum number of connections that we will create to peers. */
    public int getMaxConnections() {
        return maxConnections;
    }

    private synchronized List<Message> handleGetData(GetDataMessage m) {
        // Scans the wallets for transactions in the getdata message and returns them. Invoked in parallel
        // on peer threads.
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
        peerEventListeners.add(checkNotNull(listener));
    }

    /** The given event listener will no longer be called with events. */
    public synchronized boolean removeEventListener(PeerEventListener listener) {
        return peerEventListeners.remove(checkNotNull(listener));
    }
    
    /**
     * Returns a newly allocated list containing the currently connected peers. If all you care about is the count,
     * use numConnectedPeers().
     */
    public synchronized List<Peer> getConnectedPeers() {
        ArrayList<Peer> result = new ArrayList<Peer>(peers.size());
        synchronized (peers) {
            result.addAll(peers);
        }
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

    // Visible for testing.
    synchronized void mockStart(PeerGroupThread peerGroupThread) {
        this.peerGroupThread = peerGroupThread;
        running = true;
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
    public synchronized Future<Transaction> broadcastTransaction(final Transaction tx) {
        FutureTask<Transaction> future = new FutureTask<Transaction>(new Runnable() {
            public void run() {
                // This is run with the peer group already locked.
                synchronized (peers) {
                    for (Peer peer : peers) {
                        try {
                            log.info("{}: Sending transaction {}", peer.getAddress(), tx.getHashAsString());
                            peer.sendMessage(tx);
                        } catch (IOException e) {
                            log.warn("Caught IOException whilst sending transaction: {}", e.getMessage());
                        }
                    }
                }
            }
        }, tx);
        peerGroupThread.addTask(future);
        return future;
    }

    /**
     * <p>Link the given wallet to this PeerGroup. This is used for three purposes:</p>
     * <ol>
     *   <li>So the wallet receives broadcast transactions.</li>
     *   <li>Announcing pending transactions that didn't get into the chain yet to our peers.</li>
     *   <li>Set the fast catchup time using {@link PeerGroup#setFastCatchupTimeSecs(long)}, to optimize chain
     *       download.</li>
     * </ol>
     * <p>Note that this should be done before chain download commences because if you add a wallet with keys earlier
     * than the current chain head, the relevant parts of the chain won't be redownloaded for you.</p>
     */
    public synchronized void addWallet(Wallet wallet) {
	    Preconditions.checkNotNull(wallet);
        wallets.add(wallet);
        addEventListener(wallet.getPeerEventListener());
        announcePendingWalletTransactions(Collections.singletonList(wallet), peers);

        // Don't bother downloading block bodies before the oldest keys in all our wallets. Make sure we recalculate
        // if a key is added. Of course, by then we may have downloaded the chain already. Ideally adding keys would
        // automatically rewind the block chain and redownload the blocks to find transactions relevant to those keys,
        // all transparently and in the background. But we are a long way from that yet.
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onKeyAdded(ECKey key) {
                recalculateFastCatchupTime();
            }
        });
        recalculateFastCatchupTime();
    }

    private synchronized void recalculateFastCatchupTime() {
        long earliestKeyTime = Long.MAX_VALUE;
        for (Wallet w : wallets) {
            earliestKeyTime = Math.min(earliestKeyTime, w.getEarliestKeyCreationTime());
        }
        setFastCatchupTimeSecs(earliestKeyTime);
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
        return peers.size();
    }

    public synchronized boolean isRunning() {
        return running;
    }

    /**
     * Performs various tasks for the peer group: connects to new nodes to keep the currently connected node count at
     * the right level, runs peer discovery if we run out, and broadcasts transactions that were submitted via
     * broadcastTransaction().
     */
    class PeerGroupThread extends Thread {
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
            
            log.info("shutdown start");

            // We were asked to stop.  Reset running flag and disconnect all peer channels asynchronously.
            // Peers could still linger until their channels close.
            synchronized (PeerGroup.this) {
                running = false;
                shutdownPeerDiscovery();
                synchronized (channelFutures.values()) {
                    for (ChannelFuture future : channelFutures.values()) {
                        future.getChannel().close();
                    }
                }
                bootstrap.releaseExternalResources();
            }
            
            log.info("shutdown done");
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
         * Try connecting to a peer.
         */
        private void tryNextPeer() throws InterruptedException {
            PeerAddress address = inactives.take();
            connectTo(address.toSocketAddress());
        }

        /**
         * Add a task to be executed on the peer thread. Tasks are run with the peer group locked and when there is
         * at least one peer.
         */
        public synchronized <T> void addTask(FutureTask<T> task) {
            tasks.add(task);
        }
    }

    /**
     * Connect to a peer by creating a Netty channel to the destination address.
     * 
     * @param address destination IP and port
     * 
     * @return a ChannelFuture that can be used to wait for the socket to connect.  A socket
     *           connection does not mean that protocol handshake has occured.
     */
    public ChannelFuture connectTo(SocketAddress address) {
        ChannelFuture future = bootstrap.connect(address);
        TCPNetworkConnection.NetworkHandler networkHandler =
                (TCPNetworkConnection.NetworkHandler) future.getChannel().getPipeline().get("codec");
        if (networkHandler != null) {
            // This can be null in unit tests or apps that don't use TCP connections.
            networkHandler.getOwnerObject().setRemoteAddress(address);
        }
        Peer peer = peerFromChannelFuture(future);
        channelFutures.put(peer, future);
        return future;
    }

    static public Peer peerFromChannelFuture(ChannelFuture future) {
        return peerFromChannel(future.getChannel());
    }
    
    static public Peer peerFromChannel(Channel channel) {
        return ((PeerHandler)channel.getPipeline().get("peer")).getPeer();
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
        // Runs on a peer thread for every peer that is newly connected.
        log.info("{}: New peer", peer);
        // Link the peer to the memory pool so broadcast transactions have their confidence levels updated.
        peer.setMemoryPool(memoryPool);
        // If we want to download the chain, and we aren't currently doing so, do so now.
        if (downloadListener != null && downloadPeer == null) {
            log.info("  starting block chain download");
            startBlockChainDownloadFromPeer(peer);
        } else if (downloadPeer == null) {
            setDownloadPeer(peer);
        } else {
            peer.setDownloadData(false);
        }
        // Make sure the peer knows how to upload transactions that are requested from us.
        peer.addEventListener(getDataListener);
        // Now tell the peers about any transactions we have which didn't appear in the chain yet. These are not
        // necessarily spends we created. They may also be transactions broadcast across the network that we saw,
        // which are relevant to us, and which we therefore wish to help propagate (ie they send us coins).
        //
        // Note that this can cause a DoS attack against us if a malicious remote peer knows what keys we own, and
        // then sends us fake relevant transactions. We'll attempt to relay the bad transactions, our badness score
        // in the Satoshi client will increase and we'll get disconnected.
        //
        // TODO: Find a way to balance the desire to propagate useful transactions against obscure DoS attacks.
        announcePendingWalletTransactions(wallets, Collections.singleton(peer));
        // And set up event listeners for clients. This will allow them to find out about new transactions and blocks.
        for (PeerEventListener listener : peerEventListeners) {
            peer.addEventListener(listener);
        }
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
                log.info("{}: Announcing {} pending wallet transactions", p.getAddress(), inv.getItems().size());
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
        }
        downloadPeer = peer;
        if (downloadPeer != null) {
            log.info("Setting download peer: {}", downloadPeer);
            downloadPeer.setDownloadData(true);
            downloadPeer.setFastCatchupTime(fastCatchupTimeSecs);
        }
    }

    /**
     * Returns the {@link MemoryPool} created by this peer group to synchronize its peers. The pool tracks advertised
     * and downloaded transactions so their confidence can be measured as a proportion of how many peers announced it.
     * With an un-tampered with internet connection, the more peers announce a transaction the more confidence you can
     * have that it's really valid.
     */
    public MemoryPool getMemoryPool() {
        // Locking unneeded as memoryPool is final.
        return memoryPool;
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

    /**
     * Returns the current fast catchup time. The contents of blocks before this time won't be downloaded as they
     * cannot contain any interesting transactions. If you use {@link PeerGroup#addWallet(Wallet)} this just returns
     * the min of the wallets earliest key times.
     * @return a time in seconds since the epoch
     */
    public synchronized long getFastCatchupTimeSecs() {
        return fastCatchupTimeSecs;
    }

    protected synchronized void handlePeerDeath(final Peer peer) {
        if (!isRunning()) {
            log.info("Peer death while shutting down");
            return;
        }
        checkArgument(!peers.contains(peer));
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
