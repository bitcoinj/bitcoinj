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

import com.google.bitcoin.core.Peer.PeerHandler;
import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import com.google.bitcoin.utils.Locks;
import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.*;
import net.jcip.annotations.GuardedBy;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.channel.*;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.channel.group.DefaultChannelGroup;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>Runs a set of connections to the P2P network, brings up connections to replace disconnected nodes and manages
 * the interaction between them all. Most applications will want to use one of these.</p>
 * 
 * <p>PeerGroup tries to maintain a constant number of connections to a set of distinct peers.
 * Each peer runs a network listener in its own thread.  When a connection is lost, a new peer
 * will be tried after a delay as long as the number of connections less than the maximum.</p>
 * 
 * <p>Connections are made to addresses from a provided list.  When that list is exhausted,
 * we start again from the head of the list.</p>
 * 
 * <p>The PeerGroup can broadcast a transaction to the currently connected set of peers.  It can
 * also handle download of the blockchain from peers, restarting the process when peers die.</p>
 *
 * <p>PeerGroup implements the {@link Service} interface. This means before it will do anything,
 * you must call the {@link com.google.common.util.concurrent.Service#start()} method (which returns
 * a future) or {@link com.google.common.util.concurrent.Service#startAndWait()} method, which will block
 * until peer discovery is completed and some outbound connections have been initiated (it will return
 * before handshaking is done, however). You should call {@link com.google.common.util.concurrent.Service#stop()}
 * when finished. Note that not all methods of PeerGroup are safe to call from a UI thread as some may do
 * network IO, but starting and stopping the service should be fine.</p>
 */
public class PeerGroup extends AbstractIdleService {
    private static final int DEFAULT_CONNECTIONS = 4;

    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    protected final ReentrantLock lock = Locks.lock("peergroup");

    // These lists are all thread-safe so do not have to be accessed under the PeerGroup lock.
    // Addresses to try to connect to, excluding active peers.
    private final List<PeerAddress> inactives;
    // Currently active peers. This is an ordered list rather than a set to make unit tests predictable.
    @GuardedBy("lock") private final List<Peer> peers;
    // Currently connecting peers.
    @GuardedBy("lock") private final List<Peer> pendingPeers;
    private final ChannelGroup channels;

    // The peer that has been selected for the purposes of downloading announced data.
    @GuardedBy("lock") private Peer downloadPeer;
    // Callback for events related to chain download
    @GuardedBy("lock") private PeerEventListener downloadListener;
    // Callbacks for events related to peer connection/disconnection
    private final CopyOnWriteArrayList<PeerEventListener> peerEventListeners;
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private CopyOnWriteArraySet<PeerDiscovery> peerDiscoverers;
    // The version message to use for new connections.
    private VersionMessage versionMessage;
    // A class that tracks recent transactions that have been broadcast across the network, counts how many
    // peers announced them and updates the transaction confidence data. It is passed to each Peer.
    private final MemoryPool memoryPool;
    // How many connections we want to have open at the current time. If we lose connections, we'll try opening more
    // until we reach this count.
    @GuardedBy("lock") private int maxConnections;

    // Runs a background thread that we use for scheduling pings to our peers, so we can measure their performance
    // and network latency. We ping peers every pingIntervalMsec milliseconds.
    private volatile Timer pingTimer;
    /** How many milliseconds to wait after receiving a pong before sending another ping. */
    public static final long DEFAULT_PING_INTERVAL_MSEC = 2000;
    private long pingIntervalMsec = DEFAULT_PING_INTERVAL_MSEC;

    private final NetworkParameters params;
    private final AbstractBlockChain chain;
    private long fastCatchupTimeSecs;
    private final CopyOnWriteArrayList<Wallet> wallets;

    // This event listener is added to every peer. It's here so when we announce transactions via an "inv", every
    // peer can fetch them.
    private AbstractPeerEventListener getDataListener = new AbstractPeerEventListener() {
        @Override
        public List<Message> getData(Peer peer, GetDataMessage m) {
            return handleGetData(m);
        }
    };

    private ClientBootstrap bootstrap;
    private int minBroadcastConnections = 0;
    private AbstractWalletEventListener walletEventListener = new AbstractWalletEventListener() {
        @Override
        public void onKeyAdded(ECKey key) {
            lock.lock();
            try {
                recalculateFastCatchupAndFilter();
            } finally {
                lock.unlock();
            }
        }
    };

    private class PeerStartupListener implements Peer.PeerLifecycleListener {
        public void onPeerConnected(Peer peer) {
            handleNewPeer(peer);
        }

        public void onPeerDisconnected(Peer peer) {
            // The channel will be automatically removed from channels.
            handlePeerDeath(peer);
        }
    }

    // Visible for testing
    Peer.PeerLifecycleListener startupListener = new PeerStartupListener();

    // A bloom filter generated from all connected wallets that is given to new peers
    private BloomFilter bloomFilter;
    /** A reasonable default for the bloom filter false positive rate on mainnet.
     * Users for which low data usage is of utmost concern, 0.0001 may be better, for users
     * to whom anonymity is of utmost concern, 0.001 should provide very good privacy */
    public static final double DEFAULT_BLOOM_FILTER_FP_RATE = 0.0005;
    // The false positive rate for bloomFilter
    private double bloomFilterFPRate = DEFAULT_BLOOM_FILTER_FP_RATE;
    // We use a constant tweak to avoid giving up privacy when we regenerate our filter with new keys
    private final long bloomFilterTweak = (long) (Math.random() * Long.MAX_VALUE);
    private int lastBloomFilterElementCount;

    /**
     * Creates a PeerGroup with the given parameters. No chain is provided so this node will report its chain height
     * as zero to other peers. This constructor is useful if you just want to explore the network but aren't interested
     * in downloading block data.
     *
     * @param params Network parameters
     */
    public PeerGroup(NetworkParameters params) {
        this(params, null);
    }

    /**
     * Creates a PeerGroup for the given network and chain. Blocks will be passed to the chain as they are broadcast
     * and downloaded. This is probably the constructor you want to use.
     */
    public PeerGroup(NetworkParameters params, AbstractBlockChain chain) {
        this(params, chain, null);
    }
    
    /**
     * <p>Creates a PeerGroup for the given network and chain, using the provided Netty {@link ClientBootstrap} object.
     * </p>
     *
     * <p>A ClientBootstrap creates raw (TCP) connections to other nodes on the network. Normally you won't need to
     * provide one - use the other constructors. Providing your own bootstrap is useful if you want to control
     * details like how many network threads are used, the connection timeout value and so on. To do this, you can
     * use {@link PeerGroup#createClientBootstrap()} method and then customize the resulting object. Example:</p>
     *
     * <pre>
     *   ClientBootstrap bootstrap = PeerGroup.createClientBootstrap();
     *   bootstrap.setOption("connectTimeoutMillis", 3000);
     *   PeerGroup peerGroup = new PeerGroup(params, chain, bootstrap);
     * </pre>
     *
     * <p>The ClientBootstrap provided does not need a channel pipeline factory set. If one wasn't set, the provided
     * bootstrap will be modified to have one that sets up the pipelines correctly.</p>
     */
    public PeerGroup(NetworkParameters params, AbstractBlockChain chain, ClientBootstrap bootstrap) {
        this.params = params;
        this.chain = chain;  // Can be null.
        this.fastCatchupTimeSecs = params.getGenesisBlock().getTimeSeconds();
        this.wallets = new CopyOnWriteArrayList<Wallet>();

        // This default sentinel value will be overridden by one of two actions:
        //   - adding a peer discovery source sets it to the default
        //   - using connectTo() will increment it by one
        this.maxConnections = 0;

        int height = chain == null ? 0 : chain.getBestChainHeight();
        // We never request that the remote node wait for a bloom filter yet, as we have no wallets
        this.versionMessage = new VersionMessage(params, height, true);

        memoryPool = new MemoryPool();

        // Configure Netty. The "ClientBootstrap" creates connections to other nodes. It can be configured in various
        // ways to control the network.
        if (bootstrap == null) {
            this.bootstrap = createClientBootstrap();
            this.bootstrap.setPipelineFactory(makePipelineFactory(params, chain));
        } else {
            this.bootstrap = bootstrap;
        }

        inactives = Collections.synchronizedList(new ArrayList<PeerAddress>());
        peers = new ArrayList<Peer>();
        pendingPeers = new ArrayList<Peer>();
        channels = new DefaultChannelGroup();
        peerDiscoverers = new CopyOnWriteArraySet<PeerDiscovery>(); 
        peerEventListeners = new CopyOnWriteArrayList<PeerEventListener>();
    }

    /**
     * Helper method that just sets up a normal Netty ClientBootstrap using the default options, except for a custom
     * thread factory that gives worker threads useful names and lowers their priority (to avoid competing with UI
     * threads). You don't normally need to call this - if you aren't sure what it does, just use the regular
     * constructors for {@link PeerGroup} that don't take a ClientBootstrap object.
     */
    public static ClientBootstrap createClientBootstrap() {
        ExecutorService bossExecutor = Executors.newCachedThreadPool(new PeerGroupThreadFactory());
        ExecutorService workerExecutor = Executors.newCachedThreadPool(new PeerGroupThreadFactory());
        NioClientSocketChannelFactory channelFactory = new NioClientSocketChannelFactory(bossExecutor, workerExecutor);
        ClientBootstrap bs = new ClientBootstrap(channelFactory);
        bs.setOption("connectTimeoutMillis", 2000);
        return bs;
    }

    // Create a Netty pipeline factory.  The pipeline factory will create a network processing
    // pipeline with the bitcoin serializer ({@code TCPNetworkConnection}) downstream
    // of the higher level {@code Peer}.  Received packets will first be decoded, then passed
    // {@code Peer}.  Sent packets will be created by the {@code Peer}, then encoded and sent.
    private ChannelPipelineFactory makePipelineFactory(final NetworkParameters params, final AbstractBlockChain chain) {
        return new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                // This runs unlocked.
                VersionMessage ver = getVersionMessage().duplicate();
                ver.bestHeight = chain == null ? 0 : chain.getBestChainHeight();
                ver.time = Utils.now().getTime() / 1000;

                ChannelPipeline p = Channels.pipeline();

                Peer peer = new Peer(params, chain, ver, memoryPool);
                peer.addLifecycleListener(startupListener);
                pendingPeers.add(peer);
                TCPNetworkConnection codec = new TCPNetworkConnection(params, peer.getVersionMessage());
                p.addLast("codec", codec.getHandler());
                p.addLast("peer", peer.getHandler());
                return p;
            }
        };
    }

    /**
     * Adjusts the desired number of connections that we will create to peers. Note that if there are already peers
     * open and the new value is lower than the current number of peers, those connections will be terminated. Likewise
     * if there aren't enough current connections to meet the new requested max size, some will be added.
     */
    public void setMaxConnections(int maxConnections) {
        int adjustment;
        lock.lock();
        try {
            this.maxConnections = maxConnections;
            if (!isRunning()) return;
        } finally {
            lock.unlock();
        }
        // We may now have too many or too few open connections. Add more or drop some to get to the right amount.
        adjustment = maxConnections - channels.size();
        while (adjustment > 0) {
            try {
                connectToAnyPeer();
            } catch (PeerDiscoveryException e) {
                throw new RuntimeException(e);
            }
            adjustment--;
        }
        while (adjustment < 0) {
            channels.iterator().next().close();
            adjustment++;
        }
    }

    /** The maximum number of connections that we will create to peers. */
    public int getMaxConnections() {
        lock.lock();
        try {
            return maxConnections;
        } finally {
            lock.unlock();
        }
    }

    private List<Message> handleGetData(GetDataMessage m) {
        // Scans the wallets and memory pool for transactions in the getdata message and returns them.
        // Runs on peer threads.
        lock.lock();
        try {
            LinkedList<Message> transactions = new LinkedList<Message>();
            LinkedList<InventoryItem> items = new LinkedList<InventoryItem>(m.getItems());
            Iterator<InventoryItem> it = items.iterator();
            while (it.hasNext()) {
                InventoryItem item = it.next();
                // Check the mempool first.
                Transaction tx = memoryPool.get(item.hash);
                if (tx != null) {
                    transactions.add(tx);
                    it.remove();
                } else {
                    // Check the wallets.
                    for (Wallet w : wallets) {
                        tx = w.getTransaction(item.hash);
                        if (tx == null) continue;
                        transactions.add(tx);
                        it.remove();
                        break;
                    }
                }
            }
            return transactions;
        } finally {
            lock.unlock();
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
    public void setVersionMessage(VersionMessage ver) {
        lock.lock();
        try {
            versionMessage = ver;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the version message provided by setVersionMessage or a default if none was given.
     */
    public VersionMessage getVersionMessage() {
        lock.lock();
        try {
            return versionMessage;
        } finally {
            lock.unlock();
        }
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
        //TODO Check that height is needed here (it wasnt, but it should be, no?)
        int height = chain == null ? 0 : chain.getBestChainHeight();
        VersionMessage ver = new VersionMessage(params, height, false);
        updateVersionMessageRelayTxesBeforeFilter(ver);
        ver.appendToSubVer(name, version, comments);
        setVersionMessage(ver);
    }
    
    // Updates the relayTxesBeforeFilter flag of ver
    private void updateVersionMessageRelayTxesBeforeFilter(VersionMessage ver) {
        // We will provide the remote node with a bloom filter (ie they shouldn't relay yet)
        // iff chain == null || !chain.shouldVerifyTransactions() and a wallet is added
        // Note that the default here means that no tx invs will be received if no wallet is ever added
        lock.lock();
        try {
            ver.relayTxesBeforeFilter = chain != null && chain.shouldVerifyTransactions() && wallets.size() > 0;
        } finally {
            lock.unlock();
        }
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
    public void addEventListener(PeerEventListener listener) {
        peerEventListeners.add(checkNotNull(listener));
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeEventListener(PeerEventListener listener) {
        return peerEventListeners.remove(checkNotNull(listener));
    }

    /**
     * Returns a newly allocated list containing the currently connected peers. If all you care about is the count,
     * use numConnectedPeers().
     */
    public List<Peer> getConnectedPeers() {
        lock.lock();
        try {
            return new ArrayList<Peer>(peers);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a list containing Peers that did not complete connection yet.
     */
    public List<Peer> getPendingPeers() {
        lock.lock();
        try {
            return new ArrayList<Peer>(pendingPeers);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Add an address to the list of potential peers to connect to. It won't necessarily be used unless there's a need
     * to build new connections to reach the max connection count.
     *
     * @param peerAddress IP/port to use.
     */
    public void addAddress(PeerAddress peerAddress) {
        int newMax;
        lock.lock();
        try {
            inactives.add(peerAddress);
            newMax = getMaxConnections() + 1;
        } finally {
            lock.unlock();
        }
        setMaxConnections(newMax);
    }

    /** Convenience method for addAddress(new PeerAddress(address, params.port)); */
    public void addAddress(InetAddress address) {
        addAddress(new PeerAddress(address, params.getPort()));
    }

    /**
     * Add addresses from a discovery source to the list of potential peers to connect to. If max connections has not
     * been configured, or set to zero, then it's set to the default at this point.
     */
    public void addPeerDiscovery(PeerDiscovery peerDiscovery) {
        lock.lock();
        try {
            if (getMaxConnections() == 0)
                setMaxConnections(DEFAULT_CONNECTIONS);
            peerDiscoverers.add(peerDiscovery);
        } finally {
            lock.unlock();
        }
    }

    protected void discoverPeers() throws PeerDiscoveryException {
        // This does not need to be locked.
        long start = System.currentTimeMillis();
        Set<PeerAddress> addressSet = Sets.newHashSet();
        for (PeerDiscovery peerDiscovery : peerDiscoverers) {
            InetSocketAddress[] addresses;
            addresses = peerDiscovery.getPeers(5, TimeUnit.SECONDS);
            for (InetSocketAddress address : addresses) addressSet.add(new PeerAddress(address));
            if (addressSet.size() > 0) break;
        }
        synchronized (inactives) {
            inactives.addAll(addressSet);
        }
        log.info("Peer discovery took {}msec", System.currentTimeMillis() - start);
    }

    /** Picks a peer from discovery and connects to it. If connection fails, picks another and tries again. */
    protected void connectToAnyPeer() throws PeerDiscoveryException {
        final State state = state();
        if (!(state == State.STARTING || state == State.RUNNING)) return;

        final PeerAddress addr;
        synchronized (inactives) {
            if (inactives.size() == 0) {
                discoverPeers();
            }
            if (inactives.size() == 0) {
                log.debug("Peer discovery didn't provide us any more peers, not trying to build new connection.");
                return;
            }
            addr = inactives.remove(inactives.size() - 1);
        }
        // Don't do connectTo whilst holding the PeerGroup lock because this can trigger some amazingly deep stacks
        // and potentially circular deadlock in the case of immediate failure (eg, attempt to access IPv6 node from
        // a non-v6 capable machine). It doesn't relay control immediately to the netty boss thread as you may expect.
        //
        // This method eventually constructs a Peer and puts it into pendingPeers. If the connection fails to establish,
        // handlePeerDeath will be called, which will potentially call this method again to replace the dead or failed
        // connection.
        connectTo(addr.toSocketAddress(), false);
    }

    @Override
    protected void startUp() throws Exception {
        // This is run in a background thread by the AbstractIdleService implementation.
        pingTimer = new Timer("Peer pinging thread", true);
        // Bring up the requested number of connections. If a connect attempt fails,
        // new peers will be tried until there is a success, so just calling connectToAnyPeer for the wanted number
        // of peers is sufficient.
        for (int i = 0; i < getMaxConnections(); i++) {
            try {
                connectToAnyPeer();
            } catch (PeerDiscoveryException e) {
                if (e.getCause() instanceof InterruptedException) return;
                log.error(e.getMessage());
            }
        }
    }

    @Override
    protected void shutDown() throws Exception {
        // This is run on a separate thread by the AbstractIdleService implementation.
        pingTimer.cancel();
        // Blocking close of all sockets. TODO: there is a race condition here, for the solution see:
        // http://biasedbit.com/netty-releaseexternalresources-hangs/
        channels.close().await();
        // All thread pools should be stopped by this call.
        bootstrap.releaseExternalResources();
        for (PeerDiscovery peerDiscovery : peerDiscoverers) {
            peerDiscovery.shutdown();
        }
    }

    /**
     * <p>Link the given wallet to this PeerGroup. This is used for three purposes:</p>
     *
     * <ol>
     *   <li>So the wallet receives broadcast transactions.</li>
     *   <li>Announcing pending transactions that didn't get into the chain yet to our peers.</li>
     *   <li>Set the fast catchup time using {@link PeerGroup#setFastCatchupTimeSecs(long)}, to optimize chain
     *       download.</li>
     * </ol>
     *
     * <p>Note that this should be done before chain download commences because if you add a wallet with keys earlier
     * than the current chain head, the relevant parts of the chain won't be redownloaded for you.</p>
     *
     * <p>The Wallet will have an event listener registered on it, so to avoid leaks remember to use
     * {@link PeerGroup#removeWallet(Wallet)} on it if you wish to keep the Wallet but lose the PeerGroup.</p>
     */
    public void addWallet(Wallet wallet) {
        lock.lock();
        try {
            Preconditions.checkNotNull(wallet);
            Preconditions.checkState(!wallets.contains(wallet));
            wallets.add(wallet);
            announcePendingWalletTransactions(Collections.singletonList(wallet), peers);

            // Don't bother downloading block bodies before the oldest keys in all our wallets. Make sure we recalculate
            // if a key is added. Of course, by then we may have downloaded the chain already. Ideally adding keys would
            // automatically rewind the block chain and redownload the blocks to find transactions relevant to those keys,
            // all transparently and in the background. But we are a long way from that yet.
            wallet.addEventListener(walletEventListener);
            recalculateFastCatchupAndFilter();
            updateVersionMessageRelayTxesBeforeFilter(getVersionMessage());
        } finally {
            lock.unlock();
        }
    }

    /**
     * Unlinks the given wallet so it no longer receives broadcast transactions or has its transactions announced.
     */
    public void removeWallet(Wallet wallet) {
        wallets.remove(checkNotNull(wallet));
        wallet.removeEventListener(walletEventListener);
    }

    private void recalculateFastCatchupAndFilter() {
        checkState(lock.isLocked());
        // Fully verifying mode doesn't use this optimization (it can't as it needs to see all transactions).
        if (chain != null && chain.shouldVerifyTransactions())
            return;
        long earliestKeyTime = Long.MAX_VALUE;
        int elements = 0;
        for (Wallet w : wallets) {
            earliestKeyTime = Math.min(earliestKeyTime, w.getEarliestKeyCreationTime());
            elements += w.getBloomFilterElementCount();
        }

        if (elements > 0) {
            // We stair-step our element count so that we avoid creating a filter with different parameters
            // as much as possible as that results in a loss of privacy.
            // The constant 100 here is somewhat arbitrary, but makes sense for small to medium wallets -
            // it will likely mean we never need to create a filter with different parameters.
            lastBloomFilterElementCount = elements > lastBloomFilterElementCount ? elements + 100 : lastBloomFilterElementCount;
            BloomFilter filter = new BloomFilter(lastBloomFilterElementCount, bloomFilterFPRate, bloomFilterTweak);
            for (Wallet w : wallets)
                filter.merge(w.getBloomFilter(lastBloomFilterElementCount, bloomFilterFPRate, bloomFilterTweak));
            bloomFilter = filter;
            for (Peer peer : peers)
                try {
                    peer.setBloomFilter(filter);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
        }
        // Do this last so that bloomFilter is already set when it gets called.
        setFastCatchupTimeSecs(earliestKeyTime);
    }
    
    /**
     * Sets the false positive rate of bloom filters given to peers.
     * Be careful regenerating the bloom filter too often, as it decreases anonymity because remote nodes can
     * compare transactions against both the new and old filters to significantly decrease the false positive rate.
     * 
     * See the docs for {@link BloomFilter#BloomFilter(int, double, long)} for a brief explanation of anonymity when
     * using bloom filters.
     */
    public void setBloomFilterFalsePositiveRate(double bloomFilterFPRate) {
        lock.lock();
        try {
            this.bloomFilterFPRate = bloomFilterFPRate;
            recalculateFastCatchupAndFilter();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the number of currently connected peers. To be informed when this count changes, register a 
     * {@link PeerEventListener} and use the onPeerConnected/onPeerDisconnected methods.
     */
    public int numConnectedPeers() {
        return peers.size();
    }

    /**
     * Connect to a peer by creating a Netty channel to the destination address.
     * 
     * @param address destination IP and port.
     * @return a ChannelFuture that can be used to wait for the socket to connect.  A socket
     *           connection does not mean that protocol handshake has occured.
     */
    public ChannelFuture connectTo(SocketAddress address) {
        return connectTo(address, true);
    }

    // Internal version.
    protected ChannelFuture connectTo(SocketAddress address, boolean incrementMaxConnections) {
        ChannelFuture future = bootstrap.connect(address);
        // Make sure that the channel group gets access to the channel only if it connects successfully (otherwise
        // it cannot be closed and trying to do so will cause problems).
        future.addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) throws Exception {
                if (future.isSuccess())
                    channels.add(future.getChannel());
            }
        });
        // When the channel has connected and version negotiated successfully, handleNewPeer will end up being called on
        // a worker thread.

        // Set up the address on the TCPNetworkConnection handler object.
        // TODO: This is stupid and racy, get rid of it.
        TCPNetworkConnection.NetworkHandler networkHandler =
                (TCPNetworkConnection.NetworkHandler) future.getChannel().getPipeline().get("codec");
        if (networkHandler != null) {
            // This can be null in unit tests or apps that don't use TCP connections.
            networkHandler.getOwnerObject().setRemoteAddress(address);
        }
        if (incrementMaxConnections) {
            // We don't use setMaxConnections here as that would trigger a recursive attempt to establish a new
            // outbound connection.
            lock.lock();
            try {
                maxConnections++;
            } finally {
                lock.unlock();
            }
        }
        return future;
    }

    static public Peer peerFromChannelFuture(ChannelFuture future) {
        return peerFromChannel(future.getChannel());
    }

    static public Peer peerFromChannel(Channel channel) {
        return ((PeerHandler)channel.getPipeline().get("peer")).getPeer();
    }

    /**
     * <p>Start downloading the blockchain from the first available peer.</p>
     *
     * <p>If no peers are currently connected, the download will be started once a peer starts.  If the peer dies,
     * the download will resume with another peer.</p>
     *
     * @param listener a listener for chain download events, may not be null
     */
    public void startBlockChainDownload(PeerEventListener listener) {
        lock.lock();
        try {
            this.downloadListener = listener;
            // TODO: be more nuanced about which peer to download from.  We can also try
            // downloading from multiple peers and handle the case when a new peer comes along
            // with a longer chain after we thought we were done.
            if (!peers.isEmpty()) {
                startBlockChainDownloadFromPeer(peers.iterator().next());
            }
        } finally {
            lock.unlock();
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

    protected void handleNewPeer(final Peer peer) {
        int newSize = -1;
        lock.lock();
        try {
            // Runs on a netty worker thread for every peer that is newly connected. Peer is not locked at this point.
            // Sets up the newly connected peer so it can do everything it needs to.
            log.info("{}: New peer", peer);
            pendingPeers.remove(peer);
            peers.add(peer);
            newSize = peers.size();
            // Give the peer a filter that can be used to probabilistically drop transactions that
            // aren't relevant to our wallet. We may still receive some false positives, which is
            // OK because it helps improve wallet privacy. Old nodes will just ignore the message.
            try {
                if (bloomFilter != null) peer.setBloomFilter(bloomFilter);
            } catch (IOException e) {
            } // That was quick...already disconnected
            // Link the peer to the memory pool so broadcast transactions have their confidence levels updated.
            peer.setDownloadData(false);
            // TODO: The peer should calculate the fast catchup time from the added wallets here.
            for (Wallet wallet : wallets)
                peer.addWallet(wallet);
            // Re-evaluate download peers.
            Peer newDownloadPeer = selectDownloadPeer(peers);
            if (downloadPeer != newDownloadPeer) {
                setDownloadPeer(newDownloadPeer);
                boolean shouldDownloadChain = downloadListener != null && chain != null;
                if (shouldDownloadChain) {
                    startBlockChainDownloadFromPeer(downloadPeer);
                }
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
            // TODO: Find a way to balance the desire to propagate useful transactions against DoS attacks.
            announcePendingWalletTransactions(wallets, Collections.singletonList(peer));
            // And set up event listeners for clients. This will allow them to find out about new transactions and blocks.
            for (PeerEventListener listener : peerEventListeners) {
                peer.addEventListener(listener);
            }
            setupPingingForNewPeer(peer);
        } finally {
            lock.unlock();
        }
        for (PeerEventListener listener : peerEventListeners)
            listener.onPeerConnected(peer, newSize);
    }

    private void setupPingingForNewPeer(final Peer peer) {
        checkState(lock.isLocked());
        if (peer.getPeerVersionMessage().clientVersion < Pong.MIN_PROTOCOL_VERSION)
            return;
        if (getPingIntervalMsec() <= 0)
            return;  // Disabled.
        // Start the process of pinging the peer. Do a ping right now and then ensure there's a fixed delay between
        // each ping. If the peer is taken out of the peers list then the cycle will stop.
        final Runnable[] pingRunnable = new Runnable[1];
        pingRunnable[0] = new Runnable() {
            private boolean firstRun = true;
            public void run() {
                // Ensure that the first ping happens immediately and later pings after the requested delay.
                if (firstRun) {
                    firstRun = false;
                    try {
                        peer.ping().addListener(this, MoreExecutors.sameThreadExecutor());
                    } catch (Exception e) {
                        log.warn("{}: Exception whilst trying to ping peer: {}", peer, e.toString());
                        return;
                    }
                    return;
                }

                final long interval = getPingIntervalMsec();
                if (interval <= 0)
                    return;  // Disabled.
                pingTimer.schedule(new TimerTask() {
                    @Override
                    public void run() {
                        try {
                            if (!peers.contains(peer) || !PeerGroup.this.isRunning())
                                return;  // Peer was removed/shut down.
                            peer.ping().addListener(pingRunnable[0], MoreExecutors.sameThreadExecutor());
                        } catch (Exception e) {
                            log.warn("{}: Exception whilst trying to ping peer: {}", peer, e.toString());
                        }
                    }
                }, interval);
            }
        };
        pingRunnable[0].run();
    }

    /** Returns true if at least one peer received an inv. */
    private boolean announcePendingWalletTransactions(List<Wallet> announceWallets,
                                                      List<Peer> announceToPeers) {
        checkState(lock.isLocked());
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
            log.info("{}: Announcing {} pending wallet transactions", p.getAddress(), inv.getItems().size());
            p.sendMessage(inv);
            success = true;
        }
        return success;
    }

    private void setDownloadPeer(Peer peer) {
        lock.lock();
        try {
            if (downloadPeer == peer) {
                return;
            }
            if (chain == null) {
                // PeerGroup creator did not want us to download any data. We still track the download peer for
                // informational purposes.
                downloadPeer = peer;
                return;
            }
            if (downloadPeer != null) {
                log.info("Unsetting download peer: {}", downloadPeer);
                downloadPeer.setDownloadData(false);
            }
            downloadPeer = peer;
            if (downloadPeer != null) {
                log.info("Setting download peer: {}", downloadPeer);
                downloadPeer.setDownloadData(true);
                downloadPeer.setDownloadParameters(fastCatchupTimeSecs, bloomFilter != null);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the {@link MemoryPool} created by this peer group to synchronize its peers. The pool tracks advertised
     * and downloaded transactions so their confidence can be measured as a proportion of how many peers announced it.
     * With an un-tampered with internet connection, the more peers announce a transaction the more confidence you can
     * have that it's really valid.
     */
    public MemoryPool getMemoryPool() {
        return memoryPool;
    }

    /**
     * Tells the PeerGroup to download only block headers before a certain time and bodies after that. Call this
     * before starting block chain download.
     * Do not use a time > NOW - 1 block, as it will break some block download logic.
     */
    public void setFastCatchupTimeSecs(long secondsSinceEpoch) {
        lock.lock();
        try {
            Preconditions.checkState(chain == null || !chain.shouldVerifyTransactions(), "Fast catchup is incompatible with fully verifying");
            fastCatchupTimeSecs = secondsSinceEpoch;
            if (downloadPeer != null) {
                downloadPeer.setDownloadParameters(secondsSinceEpoch, bloomFilter != null);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the current fast catchup time. The contents of blocks before this time won't be downloaded as they
     * cannot contain any interesting transactions. If you use {@link PeerGroup#addWallet(Wallet)} this just returns
     * the min of the wallets earliest key times.
     * @return a time in seconds since the epoch
     */
    public long getFastCatchupTimeSecs() {
        lock.lock();
        try {
            return fastCatchupTimeSecs;
        } finally {
            lock.unlock();
        }
    }

    protected void handlePeerDeath(final Peer peer) {
        // This can run on any Netty worker thread. Because connectToAnyPeer() must run unlocked to avoid circular
        // deadlock, this method must run largely unlocked too. Some members are thread-safe and others aren't, so
        // we synchronize only the parts that need it.

        // Peer deaths can occur during startup if a connect attempt after peer discovery aborts immediately.
        final State state = state();
        if (state != State.RUNNING && state != State.STARTING) return;

        int numPeers = 0;
        int numConnectedPeers = 0;
        lock.lock();
        try {
            pendingPeers.remove(peer);
            peers.remove(peer);
            log.info("{}: Peer died", peer.getAddress());
            if (peer == downloadPeer) {
                log.info("Download peer died. Picking a new one.");
                setDownloadPeer(null);
                // Pick a new one and possibly tell it to download the chain.
                final Peer newDownloadPeer = selectDownloadPeer(peers);
                if (newDownloadPeer != null) {
                    setDownloadPeer(newDownloadPeer);
                    if (downloadListener != null) {
                        startBlockChainDownloadFromPeer(newDownloadPeer);
                    }
                }
            }
            numPeers = peers.size() + pendingPeers.size();
            numConnectedPeers = peers.size();
        } finally {
            lock.unlock();
        }
        // Replace this peer with a new one to keep our connection count up, if necessary.
        if (numPeers < getMaxConnections()) {
            try {
                connectToAnyPeer();
            } catch (PeerDiscoveryException e) {
                log.error(e.getMessage());
            }
        }
        peer.removeEventListener(getDataListener);
        for (Wallet wallet : wallets) {
            peer.removeWallet(wallet);
        }
        for (PeerEventListener listener : peerEventListeners) {
            listener.onPeerDisconnected(peer, numConnectedPeers);
            peer.removeEventListener(listener);
        }
    }

    private void startBlockChainDownloadFromPeer(Peer peer) {
        lock.lock();
        try {
            peer.addEventListener(downloadListener);
            setDownloadPeer(peer);
            // startBlockChainDownload will setDownloadData(true) on itself automatically.
            peer.startBlockChainDownload();
        } catch (IOException e) {
            log.error("failed to start block chain download from " + peer, e);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a future that is triggered when the number of connected peers is equal to the given number of connected
     * peers. By using this with {@link com.google.bitcoin.core.PeerGroup#getMaxConnections()} you can wait until the
     * network is fully online. To block immediately, just call get() on the result.
     *
     * @param numPeers How many peers to wait for.
     * @return a future that will be triggered when the number of connected peers >= numPeers
     */
    public ListenableFuture<PeerGroup> waitForPeers(final int numPeers) {
        lock.lock();
        try {
            if (peers.size() >= numPeers) {
                return Futures.immediateFuture(this);
            }
        } finally {
            lock.unlock();
        }
        final SettableFuture<PeerGroup> future = SettableFuture.create();
        addEventListener(new AbstractPeerEventListener() {
            @Override public void onPeerConnected(Peer peer, int peerCount) {
                if (peerCount >= numPeers) {
                    future.set(PeerGroup.this);
                    removeEventListener(this);
                }
            }
        });
        return future;
    }

    /**
     * Returns the number of connections that are required before transactions will be broadcast. If there aren't
     * enough, {@link PeerGroup#broadcastTransaction(Transaction)} will wait until the minimum number is reached so
     * propagation across the network can be observed. If no value has been set using
     * {@link PeerGroup#setMinBroadcastConnections(int)} a default of half of whatever
     * {@link com.google.bitcoin.core.PeerGroup#getMaxConnections()} returns is used.
     * @return
     */
    public int getMinBroadcastConnections() {
        lock.lock();
        try {
            if (minBroadcastConnections == 0) {
                int max = getMaxConnections();
                if (max <= 1)
                    return max;
                else
                    return (int) Math.round(getMaxConnections() / 2.0);
            }
            return minBroadcastConnections;
        } finally {
            lock.unlock();
        }
    }

    /**
     * See {@link com.google.bitcoin.core.PeerGroup#getMinBroadcastConnections()}.
     */
    public void setMinBroadcastConnections(int value) {
        lock.lock();
        try {
            minBroadcastConnections = value;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Calls {@link PeerGroup#broadcastTransaction(Transaction,int)} with getMinBroadcastConnections() as the number
     * of connections to wait for before commencing broadcast.
     */
    public ListenableFuture<Transaction> broadcastTransaction(final Transaction tx) {
        return broadcastTransaction(tx, getMinBroadcastConnections());
    }

    /**
     * <p>Given a transaction, sends it un-announced to one peer and then waits for it to be received back from other
     * peers. Once all connected peers have announced the transaction, the future will be completed. If anything goes
     * wrong the exception will be thrown when get() is called, or you can receive it via a callback on the
     * {@link ListenableFuture}. This method returns immediately, so if you want it to block just call get() on the
     * result.</p>
     *
     * <p>Note that if the PeerGroup is limited to only one connection (discovery is not activated) then the future
     * will complete as soon as the transaction was successfully written to that peer.</p>
     *
     * <p>Other than for sending your own transactions, this method is useful if you have received a transaction from
     * someone and want to know that it's valid. It's a bit of a weird hack because the current version of the Bitcoin
     * protocol does not inform you if you send an invalid transaction. Because sending bad transactions counts towards
     * your DoS limit, be careful with relaying lots of unknown transactions. Otherwise you might get kicked off the
     * network.</p>
     *
     * <p>The transaction won't be sent until there are at least minConnections active connections available.
     * A good choice for proportion would be between 0.5 and 0.8 but if you want faster transmission during initial
     * bringup of the peer group you can lower it.</p>
     */
    public ListenableFuture<Transaction> broadcastTransaction(final Transaction tx, final int minConnections) {
        final SettableFuture<Transaction> future = SettableFuture.create();
        log.info("Waiting for {} peers required for broadcast ...", minConnections);
        ListenableFuture<PeerGroup> peerAvailabilityFuture = waitForPeers(minConnections);
        peerAvailabilityFuture.addListener(new Runnable() {
            public void run() {
                // We now have enough connected peers to send the transaction.
                // This can be called immediately if we already have enough. Otherwise it'll be called from a peer
                // thread.

                // Pick a peer to be the lucky recipient of our tx. This can race if the peer we pick dies immediately.
                final Peer somePeer;
                lock.lock();
                try {
                    somePeer = peers.get(0);
                } finally {
                    lock.unlock();
                }
                log.info("broadcastTransaction: Enough peers, adding {} to the memory pool and sending to {}",
                        tx.getHashAsString(), somePeer);
                final Transaction pinnedTx = memoryPool.seen(tx, somePeer.getAddress());
                // Prepare to send the transaction by adding a listener that'll be called when confidence changes.
                // Only bother with this if we might actually hear back:
                if (minConnections > 1) tx.getConfidence().addEventListener(new TransactionConfidence.Listener() {
                    public void onConfidenceChanged(Transaction tx) {
                        // The number of peers that announced this tx has gone up.
                        // Thread safe - this can run in parallel.
                        final TransactionConfidence conf = tx.getConfidence();
                        int numSeenPeers = conf.numBroadcastPeers();
                        boolean mined = tx.getAppearsInHashes() != null;
                        log.info("broadcastTransaction: TX {} seen by {} peers{}",
                                 new Object[]{pinnedTx.getHashAsString(), numSeenPeers, mined ? " and mined" : ""});
                        if (!(numSeenPeers >= minConnections || mined))
                            return;
                        // We've seen the min required number of peers announce the transaction, or it was included
                        // in a block. Normally we'd expect to see it fully propagate before it gets mined, but
                        // it can be that a block is solved very soon after broadcast, and it's also possible that
                        // due to version skew and changes in the relay rules our transaction is not going to
                        // fully propagate yet can get mined anyway.
                        //
                        // Note that we can't wait for the current number of connected peers right now because we
                        // could have added more peers after the broadcast took place, which means they won't
                        // have seen the transaction. In future when peers sync up their memory pools after they
                        // connect we could come back and change this.
                        //
                        // OK, now tell the wallet about the transaction. If the wallet created the transaction then
                        // it already knows and will ignore this. If it's a transaction we received from
                        // somebody else via a side channel and are now broadcasting, this will put it into the
                        // wallet now we know it's valid.
                        for (Wallet wallet : wallets) {
                            try {
                                // Assumption here is there are no dependencies of the created transaction.
                                //
                                // We may end up with two threads trying to do this in parallel - the wallet will
                                // ignore whichever one loses the race.
                                wallet.receivePending(pinnedTx, null);
                            } catch (Throwable t) {
                                future.setException(t);  // RE-ENTRANCY POINT
                                return;
                            }
                        }
                        // We're done! It's important that the PeerGroup lock is not held (by this thread) at this
                        // point to avoid triggering inversions when the Future completes.
                        log.info("broadcastTransaction: {} complete", pinnedTx.getHashAsString());
                        tx.getConfidence().removeEventListener(this);
                        future.set(pinnedTx);  // RE-ENTRANCY POINT
                    }
                });

                // Satoshis code sends an inv in this case and then lets the peer request the tx data. We just
                // blast out the TX here for a couple of reasons. Firstly it's simpler: in the case where we have
                // just a single connection we don't have to wait for getdata to be received and handled before
                // completing the future in the code immediately below. Secondly, it's faster. The reason the
                // Satoshi client sends an inv is privacy - it means you can't tell if the peer originated the
                // transaction or not. However, we are not a fully validating node and this is advertised in
                // our version message, as SPV nodes cannot relay it doesn't give away any additional information
                // to skip the inv here - we wouldn't send invs anyway.
                //
                // TODO: The peer we picked might be dead by now. If we can't write the message, pick again and retry.
                ChannelFuture sendComplete = somePeer.sendMessage(pinnedTx);
                // If we've been limited to talk to only one peer, we can't wait to hear back because the
                // remote peer won't tell us about transactions we just announced to it for obvious reasons.
                // So we just have to assume we're done, at that point. This happens when we're not given
                // any peer discovery source and the user just calls connectTo() once.
                if (minConnections == 1) {
                    sendComplete.addListener(new ChannelFutureListener() {
                        public void operationComplete(ChannelFuture _) throws Exception {
                            for (Wallet wallet : wallets) {
                                try {
                                    // Assumption here is there are no dependencies of the created transaction.
                                    wallet.receivePending(pinnedTx, null);
                                } catch (Throwable t) {
                                    future.setException(t);
                                    return;
                                }
                            }
                            future.set(pinnedTx);
                        }
                    });
                }
            }
        }, MoreExecutors.sameThreadExecutor());
        return future;
    }

    /**
     * Returns the period between pings for an individual peer. Setting this lower means more accurate and timely ping
     * times are available via {@link com.google.bitcoin.core.Peer#getLastPingTime()} but it increases load on the
     * remote node. It defaults to 5000.
     */
    public long getPingIntervalMsec() {
        lock.lock();
        try {
            return pingIntervalMsec;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets the period between pings for an individual peer. Setting this lower means more accurate and timely ping
     * times are available via {@link com.google.bitcoin.core.Peer#getLastPingTime()} but it increases load on the
     * remote node. It defaults to {@link PeerGroup#DEFAULT_PING_INTERVAL_MSEC}.
     * Setting the value to be <= 0 disables pinging entirely, although you can still request one yourself
     * using {@link com.google.bitcoin.core.Peer#ping()}.
     */
    public void setPingIntervalMsec(long pingIntervalMsec) {
        lock.lock();
        try {
            this.pingIntervalMsec = pingIntervalMsec;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns our peers most commonly reported chain height. If multiple heights are tied, the highest is returned.
     * If no peers are connected, returns zero.
     */
    public int getMostCommonChainHeight() {
        lock.lock();
        try {
            return getMostCommonChainHeight(this.peers);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns most commonly reported chain height from the given list of {@link Peer}s.
     * If multiple heights are tied, the highest is returned. If no peers are connected, returns zero.
     */
    public static int getMostCommonChainHeight(final List<Peer> peers) {
        int s = peers.size();
        int[] heights = new int[s];
        int[] counts = new int[s];
        int maxCount = 0;
        // Calculate the frequencies of each reported height.
        for (Peer peer : peers) {
            int h = (int) peer.getBestHeight();
            // Find the index of the peers height in the heights array.
            for (int cursor = 0; cursor < s; cursor++) {
                if (heights[cursor] == h) {
                    maxCount = Math.max(++counts[cursor], maxCount);
                    break;
                } else if (heights[cursor] == 0) {
                    // A new height we didn't see before.
                    checkState(counts[cursor] == 0);
                    heights[cursor] = h;
                    counts[cursor] = 1;
                    maxCount = Math.max(maxCount, 1);
                    break;
                }
            }
        }
        // Find the heights that have the highest frequencies.
        int[] freqHeights = new int[s];
        int cursor = 0;
        for (int i = 0; i < s; i++) {
            if (counts[i] == maxCount) {
                freqHeights[cursor++] = heights[i];
            }
        }
        // Return the highest of the most common heights.
        Arrays.sort(freqHeights);
        return freqHeights[s - 1];
    }

    private static class PeerAndPing {
        Peer peer;
        long pingTime;
    }

    /**
     * Given a list of Peers, return a Peer to be used as the download peer. If you don't want PeerGroup to manage
     * download peer statuses for you, just override this and always return null.
     */
    protected Peer selectDownloadPeer(List<Peer> peers) {
        // Characteristics to select for in order of importance:
        //  - Chain height is reasonable (majority of nodes)
        //  - High enough protocol version for the features we want (but we'll settle for less)
        //  - Ping time.
        if (peers.isEmpty())
            return null;
        // Make sure we don't select a peer that is behind/synchronizing itself.
        int mostCommonChainHeight = getMostCommonChainHeight(peers);
        List<Peer> candidates = new ArrayList<Peer>();
        for (Peer peer : peers) {
            if (peer.getBestHeight() == mostCommonChainHeight) candidates.add(peer);
        }
        // Of the candidates, find the peers that meet the minimum protocol version we want to target. We could select
        // the highest version we've seen on the assumption that newer versions are always better but we don't want to
        // zap peers if they upgrade early. If we can't find any peers that have our preferred protocol version or
        // better then we'll settle for the highest we found instead.
        int highestVersion = 0, preferredVersion = 0;
        final int PREFERRED_VERSION = FilteredBlock.MIN_PROTOCOL_VERSION;
        for (Peer peer : candidates) {
            highestVersion = Math.max(peer.getPeerVersionMessage().clientVersion, highestVersion);
            preferredVersion = Math.min(highestVersion, PREFERRED_VERSION);
        }
        List<PeerAndPing> candidates2 = new ArrayList<PeerAndPing>();
        for (Peer peer : candidates) {
            if (peer.getPeerVersionMessage().clientVersion >= preferredVersion) {
                PeerAndPing pap = new PeerAndPing();
                pap.peer = peer;
                pap.pingTime = peer.getPingTime();
                candidates2.add(pap);
            }
        }
        // Sort by ping time.
        Collections.sort(candidates2, new Comparator<PeerAndPing>() {
            public int compare(PeerAndPing peerAndPing, PeerAndPing peerAndPing2) {
                if (peerAndPing.pingTime < peerAndPing2.pingTime)
                    return -1;
                else if (peerAndPing.pingTime == peerAndPing2.pingTime)
                    return 0;
                else
                    return 1;

            }
        });
        return candidates2.get(0).peer;
    }

    private static class PeerGroupThreadFactory implements ThreadFactory {
        static final AtomicInteger poolNumber = new AtomicInteger(1);
        final ThreadGroup group;
        final AtomicInteger threadNumber = new AtomicInteger(1);
        final String namePrefix;

        PeerGroupThreadFactory() {
            group = Thread.currentThread().getThreadGroup();
            namePrefix = "PeerGroup-" + poolNumber.getAndIncrement() + "-thread-";
        }

        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            // Lower the priority of the peer threads. This is to avoid competing with UI threads created by the API
            // user when doing lots of work, like downloading the block chain. We select a priority level one lower
            // than the parent thread, or the minimum.
            t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.currentThread().getPriority() - 1));
            t.setDaemon(true);
            return t;
        }
    }

    /**
     * Returns the currently selected download peer. Bear in mind that it may have changed as soon as this method
     * returns. Can return null if no peer was selected.
     */
    public Peer getDownloadPeer() {
        lock.lock();
        try {
            return downloadPeer;
        } finally {
            lock.unlock();
        }
    }
}
