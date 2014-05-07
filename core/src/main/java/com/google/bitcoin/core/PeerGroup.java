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

import com.google.bitcoin.net.ClientConnectionManager;
import com.google.bitcoin.net.FilterMerger;
import com.google.bitcoin.net.NioClientManager;
import com.google.bitcoin.net.discovery.PeerDiscovery;
import com.google.bitcoin.net.discovery.PeerDiscoveryException;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.utils.ExponentialBackoff;
import com.google.bitcoin.utils.ListenerRegistration;
import com.google.bitcoin.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.*;
import net.jcip.annotations.GuardedBy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
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
public class PeerGroup extends AbstractExecutionThreadService implements TransactionBroadcaster {
    private static final int DEFAULT_CONNECTIONS = 4;

    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    protected final ReentrantLock lock = Threading.lock("peergroup");

    // Addresses to try to connect to, excluding active peers.
    @GuardedBy("lock") private final PriorityQueue<PeerAddress> inactives;
    @GuardedBy("lock") private final Map<PeerAddress, ExponentialBackoff> backoffMap;

    // Currently active peers. This is an ordered list rather than a set to make unit tests predictable.
    private final CopyOnWriteArrayList<Peer> peers;
    // Currently connecting peers.
    private final CopyOnWriteArrayList<Peer> pendingPeers;
    private final ClientConnectionManager channels;

    // The peer that has been selected for the purposes of downloading announced data.
    @GuardedBy("lock") private Peer downloadPeer;
    // Callback for events related to chain download
    @Nullable @GuardedBy("lock") private PeerEventListener downloadListener;
    // Callbacks for events related to peer connection/disconnection
    private final CopyOnWriteArrayList<ListenerRegistration<PeerEventListener>> peerEventListeners;
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private final CopyOnWriteArraySet<PeerDiscovery> peerDiscoverers;
    // The version message to use for new connections.
    @GuardedBy("lock") private VersionMessage versionMessage;
    // A class that tracks recent transactions that have been broadcast across the network, counts how many
    // peers announced them and updates the transaction confidence data. It is passed to each Peer.
    private final MemoryPool memoryPool;
    // How many connections we want to have open at the current time. If we lose connections, we'll try opening more
    // until we reach this count.
    @GuardedBy("lock") private int maxConnections;
    // Minimum protocol version we will allow ourselves to connect to: require Bloom filtering.
    private volatile int vMinRequiredProtocolVersion = FilteredBlock.MIN_PROTOCOL_VERSION;

    // Runs a background thread that we use for scheduling pings to our peers, so we can measure their performance
    // and network latency. We ping peers every pingIntervalMsec milliseconds.
    private volatile Timer vPingTimer;
    /** How many milliseconds to wait after receiving a pong before sending another ping. */
    public static final long DEFAULT_PING_INTERVAL_MSEC = 2000;
    private long pingIntervalMsec = DEFAULT_PING_INTERVAL_MSEC;

    private final NetworkParameters params;
    private final AbstractBlockChain chain;
    @GuardedBy("lock") private long fastCatchupTimeSecs;
    private final CopyOnWriteArrayList<Wallet> wallets;
    private final CopyOnWriteArrayList<PeerFilterProvider> peerFilterProviders;

    // This event listener is added to every peer. It's here so when we announce transactions via an "inv", every
    // peer can fetch them.
    private final AbstractPeerEventListener peerListener = new AbstractPeerEventListener() {
        @Override
        public List<Message> getData(Peer peer, GetDataMessage m) {
            return handleGetData(m);
        }

        @Override
        public void onBlocksDownloaded(Peer peer, Block block, int blocksLeft) {
            double rate = checkNotNull(chain).getFalsePositiveRate();
            if (rate > bloomFilterMerger.getBloomFilterFPRate() * MAX_FP_RATE_INCREASE) {
                log.info("Force update Bloom filter due to high false positive rate");
                recalculateFastCatchupAndFilter(FilterRecalculateMode.FORCE_SEND);
            }
        }
    };

    private int minBroadcastConnections = 0;
    private Runnable bloomSendIfChanged = new Runnable() {
        @Override public void run() {
            recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
        }
    };
    private Runnable bloomDontSend = new Runnable() {
        @Override public void run() {
            recalculateFastCatchupAndFilter(FilterRecalculateMode.DONT_SEND);
        }
    };
    private AbstractWalletEventListener walletEventListener = new AbstractWalletEventListener() {
        private void queueRecalc(boolean andTransmit) {
            if (andTransmit) {
                log.info("Queuing recalc of the Bloom filter due to new keys or scripts becoming available");
                Uninterruptibles.putUninterruptibly(jobQueue, bloomSendIfChanged);
            } else {
                log.info("Queuing recalc of the Bloom filter due to observing a pay to pubkey output on a relevant tx");
                Uninterruptibles.putUninterruptibly(jobQueue, bloomDontSend);
            }
        }

        @Override public void onScriptsAdded(Wallet wallet, List<Script> scripts) {
            queueRecalc(true);
        }

        @Override public void onKeysAdded(Wallet wallet, List<ECKey> keys) {
            queueRecalc(true);
        }

        @Override
        public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
            // We received a relevant transaction. We MAY need to recalculate and resend the Bloom filter, but only
            // if we have received a transaction that includes a relevant pay-to-pubkey output.
            //
            // The reason is that pay-to-pubkey outputs, when spent, will not repeat any data we can predict in their
            // inputs. So a remote peer will update the Bloom filter for us when such an output is seen matching the
            // existing filter, so that it includes the tx hash in which the pay-to-pubkey output was observed. Thus
            // the spending transaction will always match (due to the outpoint structure).
            //
            // Unfortunately, whilst this is required for correct sync of the chain in blocks, there are two edge cases.
            //
            // (1) If a wallet receives a relevant, confirmed p2pubkey output that was not broadcast across the network,
            // for example in a coinbase transaction, then the node that's serving us the chain will update its filter
            // but the rest will not. If another transaction then spends it, the other nodes won't match/relay it.
            //
            // (2) If we receive a p2pubkey output broadcast across the network, all currently connected nodes will see
            // it and update their filter themselves, but any newly connected nodes will receive the last filter we
            // calculated, which would not include this transaction.
            //
            // For this reason we check if the transaction contained any relevant pay to pubkeys and force a recalc
            // and possibly retransmit if so. The recalculation process will end up including the tx hash into the
            // filter. In case (1), we need to retransmit the filter to the connected peers. In case (2), we don't
            // and shouldn't, we should just recalculate and cache the new filter for next time.
            for (TransactionOutput output : tx.getOutputs()) {
                if (output.getScriptPubKey().isSentToRawPubKey() && output.isMine(wallet)) {
                    if (tx.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.BUILDING)
                        queueRecalc(true);
                    else
                        queueRecalc(false);
                    return;
                }
            }
        }
    };

    // Exponential backoff for peers starts at 1 second and maxes at 10 minutes.
    private ExponentialBackoff.Params peerBackoffParams = new ExponentialBackoff.Params(1000, 1.5f, 10 * 60 * 1000);
    // Tracks failures globally in case of a network failure.
    private ExponentialBackoff groupBackoff = new ExponentialBackoff(new ExponentialBackoff.Params(1000, 1.5f, 10 * 1000));

    // Things for the dedicated PeerGroup management thread to do.
    private LinkedBlockingQueue<Runnable> jobQueue = new LinkedBlockingQueue<Runnable>();

    // This is a synchronized set, so it locks on itself. We use it to prevent TransactionBroadcast objects from
    // being garbage collected if nothing in the apps code holds on to them transitively. See the discussion
    // in broadcastTransaction.
    private final Set<TransactionBroadcast> runningBroadcasts;

    private class PeerStartupListener extends AbstractPeerEventListener {
        @Override
        public void onPeerConnected(Peer peer, int peerCount) {
            handleNewPeer(peer);
        }

        @Override
        public void onPeerDisconnected(Peer peer, int peerCount) {
            // The channel will be automatically removed from channels.
            handlePeerDeath(peer);
        }
    }

    // Visible for testing
    PeerEventListener startupListener = new PeerStartupListener();

    /**
     * <p>A reasonable default for the bloom filter false positive rate on mainnet. FP rates are values between 0.0 and 1.0
     * where 1.0 is "all transactions" i.e. 100%.</p>
     *
     * <p>Users for which low data usage is of utmost concern, 0.0001 may be better, for users
     * to whom anonymity is of utmost concern, 0.001 (0.1%) should provide very good privacy.</p>
     */
    public static final double DEFAULT_BLOOM_FILTER_FP_RATE = 0.0005;
    /** Maximum increase in FP rate before forced refresh of the bloom filter */
    public static final double MAX_FP_RATE_INCREASE = 2.0f;
    // An object that calculates bloom filters given a list of filter providers, whilst tracking some state useful
    // for privacy purposes.
    private FilterMerger bloomFilterMerger;

    /** The default timeout between when a connection attempt begins and version message exchange completes */
    public static final int DEFAULT_CONNECT_TIMEOUT_MILLIS = 5000;
    private volatile int vConnectTimeoutMillis = DEFAULT_CONNECT_TIMEOUT_MILLIS;

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
    public PeerGroup(NetworkParameters params, @Nullable AbstractBlockChain chain) {
        this(params, chain, new NioClientManager());
    }

    /**
     * Creates a new PeerGroup allowing you to specify the {@link ClientConnectionManager} which is used to create new
     * connections and keep track of existing ones.
     */
    public PeerGroup(NetworkParameters params, @Nullable AbstractBlockChain chain, ClientConnectionManager connectionManager) {
        this.params = checkNotNull(params);
        this.chain = chain;
        this.fastCatchupTimeSecs = params.getGenesisBlock().getTimeSeconds();
        this.wallets = new CopyOnWriteArrayList<Wallet>();
        this.peerFilterProviders = new CopyOnWriteArrayList<PeerFilterProvider>();

        // This default sentinel value will be overridden by one of two actions:
        //   - adding a peer discovery source sets it to the default
        //   - using connectTo() will increment it by one
        this.maxConnections = 0;

        int height = chain == null ? 0 : chain.getBestChainHeight();
        // We never request that the remote node wait for a bloom filter yet, as we have no wallets
        this.versionMessage = new VersionMessage(params, height, true);

        memoryPool = new MemoryPool();

        inactives = new PriorityQueue<PeerAddress>(1, new Comparator<PeerAddress>() {
            @Override
            public int compare(PeerAddress a, PeerAddress b) {
                int result = backoffMap.get(a).compareTo(backoffMap.get(b));
                // Sort by port if otherwise equals - for testing
                if (result == 0)
                    result = Integer.valueOf(a.getPort()).compareTo(b.getPort());
                return result;
            }
        });
        backoffMap = new HashMap<PeerAddress, ExponentialBackoff>();
        peers = new CopyOnWriteArrayList<Peer>();
        pendingPeers = new CopyOnWriteArrayList<Peer>();
        channels = connectionManager;
        peerDiscoverers = new CopyOnWriteArraySet<PeerDiscovery>();
        peerEventListeners = new CopyOnWriteArrayList<ListenerRegistration<PeerEventListener>>();
        runningBroadcasts = Collections.synchronizedSet(new HashSet<TransactionBroadcast>());
        bloomFilterMerger = new FilterMerger(DEFAULT_BLOOM_FILTER_FP_RATE);
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
        adjustment = maxConnections - channels.getConnectedClientCount();
        if (adjustment > 0)
            triggerConnections();

        if (adjustment < 0)
            channels.closeConnections(-adjustment);
    }


    private Runnable triggerConnectionsJob = new Runnable() {
        @Override
        public void run() {
            // We have to test the condition at the end, because during startup we need to run this at least once
            // when isRunning() can return false.
            do {
                try {
                    connectToAnyPeer();
                } catch (PeerDiscoveryException e) {
                    groupBackoff.trackFailure();
                }
            } while (isRunning() && countConnectedAndPendingPeers() < getMaxConnections());
        }
    };

    private void triggerConnections() {
        // Run on a background thread due to the need to potentially retry and back off in the background.
        Uninterruptibles.putUninterruptibly(jobQueue, triggerConnectionsJob);
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
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki">BIP 14</a>.
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
     */
    public void setUserAgent(String name, String version, @Nullable String comments) {
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
            boolean spvMode = chain != null && !chain.shouldVerifyTransactions();
            boolean willSendFilter = spvMode && peerFilterProviders.size() > 0;
            ver.relayTxesBeforeFilter = !willSendFilter;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets information that identifies this software to remote nodes. This is a convenience wrapper for creating
     * a new {@link VersionMessage}, calling {@link VersionMessage#appendToSubVer(String, String, String)} on it,
     * and then calling {@link PeerGroup#setVersionMessage(VersionMessage)} on the result of that. See the docs for
     * {@link VersionMessage#appendToSubVer(String, String, String)} for information on what the fields should contain.
     */
    public void setUserAgent(String name, String version) {
        setUserAgent(name, version, null);
    }


    /**
     * <p>Adds a listener that will be notified on the given executor when:</p>
     * <ol>
     *     <li>New peers are connected to.</li>
     *     <li>Peers are disconnected from.</li>
     *     <li>A message is received by the download peer (there is always one peer which is elected as a peer which
     *     will be used to retrieve data).
     *     <li>Blocks are downloaded by the download peer.</li>
     *     </li>
     * </ol>
     */
    public void addEventListener(PeerEventListener listener, Executor executor) {
        peerEventListeners.add(new ListenerRegistration<PeerEventListener>(checkNotNull(listener), executor));
    }

    /**
     * Same as {@link PeerGroup#addEventListener(PeerEventListener, java.util.concurrent.Executor)} but defaults
     * to running on the user thread.
     */
    public void addEventListener(PeerEventListener listener) {
        addEventListener(listener, Threading.USER_THREAD);
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeEventListener(PeerEventListener listener) {
        return ListenerRegistration.removeFromList(listener, peerEventListeners);
    }

    /**
     * Removes all event listeners simultaneously. Note that this includes listeners added internally by the framework
     * so it's generally not advised to use this - it exists for special purposes only.
     */
    public void clearEventListeners() {
        peerEventListeners.clear();
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
            addInactive(peerAddress);
            newMax = getMaxConnections() + 1;
        } finally {
            lock.unlock();
        }
        setMaxConnections(newMax);
    }

    private void addInactive(PeerAddress peerAddress) {
        // Deduplicate
        if (backoffMap.containsKey(peerAddress))
            return;
        backoffMap.put(peerAddress, new ExponentialBackoff(peerBackoffParams));
        inactives.offer(peerAddress);
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
        if (peerDiscoverers.isEmpty())
            throw new PeerDiscoveryException("No peer discoverers registered");
        long start = System.currentTimeMillis();
        Set<PeerAddress> addressSet = Sets.newHashSet();
        for (PeerDiscovery peerDiscovery : peerDiscoverers) {
            InetSocketAddress[] addresses;
            addresses = peerDiscovery.getPeers(5, TimeUnit.SECONDS);
            for (InetSocketAddress address : addresses) addressSet.add(new PeerAddress(address));
            if (addressSet.size() > 0) break;
        }
        lock.lock();
        try {
            for (PeerAddress address : addressSet) {
                addInactive(address);
            }
        } finally {
            lock.unlock();
        }
        log.info("Peer discovery took {}msec and returned {} items",
                System.currentTimeMillis() - start, addressSet.size());
    }

    @Override
    protected void run() throws Exception {
        // Runs in a background thread dedicated to the PeerGroup. Jobs are for handling peer connections with backoff,
        // and also recalculating filters.
        while (isRunning()) {
            jobQueue.take().run();
        }
    }

    @VisibleForTesting
    void waitForJobQueue() {
        final CountDownLatch latch = new CountDownLatch(1);
        Uninterruptibles.putUninterruptibly(jobQueue, new Runnable() {
            @Override
            public void run() {
                latch.countDown();
            }
        });
        Uninterruptibles.awaitUninterruptibly(latch);
    }

    private int countConnectedAndPendingPeers() {
        lock.lock();
        try {
            return peers.size() + pendingPeers.size();
        } finally {
            lock.unlock();
        }
    }

    /** Picks a peer from discovery and connects to it. If connection fails, picks another and tries again. */
    protected void connectToAnyPeer() throws PeerDiscoveryException {
        final State state = state();
        if (!(state == State.STARTING || state == State.RUNNING)) return;

        PeerAddress addr = null;

        long nowMillis = Utils.currentTimeMillis();
        long retryTime = 0;
        lock.lock();
        try {
            if (!haveReadyInactivePeer(nowMillis)) {
                discoverPeers();
                groupBackoff.trackSuccess();
                nowMillis = Utils.currentTimeMillis();
            }
            if (inactives.size() == 0) {
                log.debug("Peer discovery didn't provide us any more peers, not trying to build new connection.");
                return;
            }
            addr = inactives.poll();
            retryTime = backoffMap.get(addr).getRetryTime();
        } finally {
            // discoverPeers might throw an exception if something goes wrong: we then hit this path with addr == null.
            retryTime = Math.max(retryTime, groupBackoff.getRetryTime());
            lock.unlock();
            if (retryTime > nowMillis) {
                // Sleep until retry time
                final long millis = retryTime - nowMillis;
                log.info("Waiting {} msec before next connect attempt {}", millis, addr == null ? "" : " to " + addr);
                Utils.sleep(millis);
            }
        }

        // This method constructs a Peer and puts it into pendingPeers.
        checkNotNull(addr);   // Help static analysis which can't see that addr is always set if we didn't throw above.
        connectTo(addr, false);
    }

    private boolean haveReadyInactivePeer(long nowMillis) {
        // No inactive peers to try?
        if (inactives.size() == 0)
            return false;
        // All peers have not reached backoff retry time?
        if (backoffMap.get(inactives.peek()).getRetryTime() > nowMillis)
            return false;
        return true;
    }

    @Override
    protected void startUp() throws Exception {
        // This is run in a background thread by the Service implementation.
        vPingTimer = new Timer("Peer pinging thread", true);
        channels.startAndWait();
        triggerConnections();
    }

    @Override
    protected void shutDown() throws Exception {
        // This is run on a separate thread by the Service implementation.
        vPingTimer.cancel();
        // Blocking close of all sockets.
        channels.stopAndWait();
        for (PeerDiscovery peerDiscovery : peerDiscoverers) {
            peerDiscovery.shutdown();
        }
    }

    @Override
    protected void triggerShutdown() {
        // Force the thread to wake up.
        Uninterruptibles.putUninterruptibly(jobQueue, new Runnable() {
            public void run() {
            }
        });
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
            checkNotNull(wallet);
            checkState(!wallets.contains(wallet));
            wallets.add(wallet);
            wallet.setTransactionBroadcaster(this);
            wallet.addEventListener(walletEventListener, Threading.SAME_THREAD);
            addPeerFilterProvider(wallet);
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Link the given PeerFilterProvider to this PeerGroup. DO NOT use this for Wallets, use
     * {@link PeerGroup#addWallet(Wallet)} instead.</p>
     *
     * <p>Note that this should be done before chain download commences because if you add a listener with keys earlier
     * than the current chain head, the relevant parts of the chain won't be redownloaded for you.</p>
     */
    public void addPeerFilterProvider(PeerFilterProvider provider) {
        lock.lock();
        try {
            checkNotNull(provider);
            checkState(!peerFilterProviders.contains(provider));
            peerFilterProviders.add(provider);

            // Don't bother downloading block bodies before the oldest keys in all our wallets. Make sure we recalculate
            // if a key is added. Of course, by then we may have downloaded the chain already. Ideally adding keys would
            // automatically rewind the block chain and redownload the blocks to find transactions relevant to those keys,
            // all transparently and in the background. But we are a long way from that yet.
            recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
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
        peerFilterProviders.remove(wallet);
        wallet.removeEventListener(walletEventListener);
        wallet.setTransactionBroadcaster(null);
    }

    public static enum FilterRecalculateMode {
        SEND_IF_CHANGED,
        FORCE_SEND,
        DONT_SEND,
    }

    /**
     * Recalculates the bloom filter given to peers as well as the timestamp after which full blocks are downloaded
     * (instead of only headers).
     *
     * @param mode In what situations to send the filter to connected peers.
     */
    public void recalculateFastCatchupAndFilter(FilterRecalculateMode mode) {
        lock.lock();
        try {
            // Fully verifying mode doesn't use this optimization (it can't as it needs to see all transactions).
            if (chain != null && chain.shouldVerifyTransactions())
                return;
            log.info("Recalculating filter in mode {}", mode);
            FilterMerger.Result result = bloomFilterMerger.calculate(ImmutableList.copyOf(peerFilterProviders));
            boolean send;
            switch (mode) {
                case SEND_IF_CHANGED: send = result.changed; break;
                case DONT_SEND: send = false; break;
                case FORCE_SEND: send = true; break;
                default: throw new UnsupportedOperationException();
            }
            if (send) {
                for (Peer peer : peers)
                    peer.setBloomFilter(result.filter);
                // Reset the false positive estimate so that we don't send a flood of filter updates
                // if the estimate temporarily overshoots our threshold.
                if (chain != null)
                    chain.resetFalsePositiveEstimate();
            }
            // Do this last so that bloomFilter is already set when it gets called.
            setFastCatchupTimeSecs(result.earliestKeyTimeSecs);
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * <p>Sets the false positive rate of bloom filters given to peers. The default is {@link #DEFAULT_BLOOM_FILTER_FP_RATE}.</p>
     *
     * <p>Be careful regenerating the bloom filter too often, as it decreases anonymity because remote nodes can
     * compare transactions against both the new and old filters to significantly decrease the false positive rate.</p>
     * 
     * <p>See the docs for {@link BloomFilter#BloomFilter(int, double, long, BloomFilter.BloomUpdate)} for a brief
     * explanation of anonymity when using bloom filters.</p>
     */
    public void setBloomFilterFalsePositiveRate(double bloomFilterFPRate) {
        lock.lock();
        try {
            bloomFilterMerger.setBloomFilterFPRate(bloomFilterFPRate);
            recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
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
     * Connect to a peer by creating a channel to the destination address.  This should not be
     * used normally - let the PeerGroup manage connections through {@link #start()}
     * 
     * @param address destination IP and port.
     * @return The newly created Peer object or null if the peer could not be connected.
     *         Use {@link com.google.bitcoin.core.Peer#getConnectionOpenFuture()} if you
     *         want a future which completes when the connection is open.
     */
    @Nullable
    public Peer connectTo(InetSocketAddress address) {
        PeerAddress peerAddress = new PeerAddress(address);
        backoffMap.put(peerAddress, new ExponentialBackoff(peerBackoffParams));
        return connectTo(peerAddress, true);
    }

    // Internal version.
    @Nullable
    protected Peer connectTo(PeerAddress address, boolean incrementMaxConnections) {
        VersionMessage ver = getVersionMessage().duplicate();
        ver.bestHeight = chain == null ? 0 : chain.getBestChainHeight();
        ver.time = Utils.currentTimeMillis() / 1000;

        Peer peer = new Peer(params, ver, address, chain, memoryPool);
        peer.addEventListener(startupListener, Threading.SAME_THREAD);
        peer.setMinProtocolVersion(vMinRequiredProtocolVersion);
        pendingPeers.add(peer);

        try {
            channels.openConnection(address.toSocketAddress(), peer);
        } catch (Exception e) {
            log.warn("Failed to connect to " + address + ": " + e.getMessage());
            handlePeerDeath(peer);
            return null;
        }
        peer.setSocketTimeout(vConnectTimeoutMillis);
        // When the channel has connected and version negotiated successfully, handleNewPeer will end up being called on
        // a worker thread.

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
        return peer;
    }

    /**
     * Sets the timeout between when a connection attempt to a peer begins and when the version message exchange
     * completes. This does not apply to currently pending peers.
     */
    public void setConnectTimeoutMillis(int connectTimeoutMillis) {
        this.vConnectTimeoutMillis = connectTimeoutMillis;
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
            if (downloadPeer != null && this.downloadListener != null)
                downloadPeer.removeEventListener(this.downloadListener);
            this.downloadListener = listener;
            // TODO: be more nuanced about which peer to download from.  We can also try
            // downloading from multiple peers and handle the case when a new peer comes along
            // with a longer chain after we thought we were done.
            if (!peers.isEmpty()) {
                startBlockChainDownloadFromPeer(peers.iterator().next()); // Will add the new download listener
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
            groupBackoff.trackSuccess();
            backoffMap.get(peer.getAddress()).trackSuccess();

            // Sets up the newly connected peer so it can do everything it needs to.
            log.info("{}: New peer", peer);
            pendingPeers.remove(peer);
            peers.add(peer);
            newSize = peers.size();
            // Give the peer a filter that can be used to probabilistically drop transactions that
            // aren't relevant to our wallet. We may still receive some false positives, which is
            // OK because it helps improve wallet privacy. Old nodes will just ignore the message.
            if (bloomFilterMerger.getLastFilter() != null) peer.setBloomFilter(bloomFilterMerger.getLastFilter());
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
            peer.addEventListener(peerListener, Threading.SAME_THREAD);
            // And set up event listeners for clients. This will allow them to find out about new transactions and blocks.
            for (ListenerRegistration<PeerEventListener> registration : peerEventListeners) {
                peer.addEventListenerWithoutOnDisconnect(registration.listener, registration.executor);
            }
            setupPingingForNewPeer(peer);
        } finally {
            lock.unlock();
        }

        final int fNewSize = newSize;
        for (final ListenerRegistration<PeerEventListener> registration : peerEventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onPeerConnected(peer, fNewSize);
                }
            });
        }
    }

    private void setupPingingForNewPeer(final Peer peer) {
        checkState(lock.isHeldByCurrentThread());
        if (peer.getPeerVersionMessage().clientVersion < Pong.MIN_PROTOCOL_VERSION)
            return;
        if (getPingIntervalMsec() <= 0)
            return;  // Disabled.
        // Start the process of pinging the peer. Do a ping right now and then ensure there's a fixed delay between
        // each ping. If the peer is taken out of the peers list then the cycle will stop.
        //
        // TODO: This should really be done by a timer integrated with the network thread to avoid races.
        final Runnable[] pingRunnable = new Runnable[1];
        pingRunnable[0] = new Runnable() {
            private boolean firstRun = true;
            public void run() {
                // Ensure that the first ping happens immediately and later pings after the requested delay.
                if (firstRun) {
                    firstRun = false;
                    try {
                        peer.ping().addListener(this, Threading.SAME_THREAD);
                    } catch (Exception e) {
                        log.warn("{}: Exception whilst trying to ping peer: {}", peer, e.toString());
                        return;
                    }
                    return;
                }

                final long interval = getPingIntervalMsec();
                if (interval <= 0)
                    return;  // Disabled.
                final TimerTask task = new TimerTask() {
                    @Override
                    public void run() {
                        try {
                            if (!peers.contains(peer) || !PeerGroup.this.isRunning())
                                return;  // Peer was removed/shut down.
                            peer.ping().addListener(pingRunnable[0], Threading.SAME_THREAD);
                        } catch (Exception e) {
                            log.warn("{}: Exception whilst trying to ping peer: {}", peer, e.toString());
                        }
                    }
                };
                try {
                    vPingTimer.schedule(task, interval);
                } catch (IllegalStateException ignored) {
                    // This can happen if there's a shutdown race and this runnable is executing whilst the timer is
                    // simultaneously cancelled.
                }
            }
        };
        pingRunnable[0].run();
    }

    private void setDownloadPeer(@Nullable Peer peer) {
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
                if (downloadListener != null)
                    downloadPeer.removeEventListener(downloadListener);
                downloadPeer.setDownloadData(false);
            }
            downloadPeer = peer;
            if (downloadPeer != null) {
                log.info("Setting download peer: {}", downloadPeer);
                if (downloadListener != null)
                    peer.addEventListener(downloadListener, Threading.SAME_THREAD);
                downloadPeer.setDownloadData(true);
                downloadPeer.setDownloadParameters(fastCatchupTimeSecs, bloomFilterMerger.getLastFilter() != null);
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
                downloadPeer.setDownloadParameters(secondsSinceEpoch, bloomFilterMerger.getLastFilter() != null);
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
        // Peer deaths can occur during startup if a connect attempt after peer discovery aborts immediately.
        final State state = state();
        if (state != State.RUNNING && state != State.STARTING) return;

        int numPeers = 0;
        int numConnectedPeers = 0;
        lock.lock();
        try {
            pendingPeers.remove(peer);
            peers.remove(peer);

            PeerAddress address = peer.getAddress();

            log.info("{}: Peer died", address);
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

            groupBackoff.trackFailure();

            //TODO: if network failure is suspected, do not backoff peer
            backoffMap.get(address).trackFailure();
            // Put back on inactive list
            inactives.offer(address);

            if (numPeers < getMaxConnections()) {
                triggerConnections();
            }
        } finally {
            lock.unlock();
        }

        peer.removeEventListener(peerListener);
        for (Wallet wallet : wallets) {
            peer.removeWallet(wallet);
        }

        final int fNumConnectedPeers = numConnectedPeers;
        for (final ListenerRegistration<PeerEventListener> registration : peerEventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onPeerDisconnected(peer, fNumConnectedPeers);
                }
            });
            peer.removeEventListener(registration.listener);
        }
    }

    private void startBlockChainDownloadFromPeer(Peer peer) {
        lock.lock();
        try {
            setDownloadPeer(peer);
            // startBlockChainDownload will setDownloadData(true) on itself automatically.
            peer.startBlockChainDownload();
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
        return broadcastTransaction(tx, Math.max(1, getMinBroadcastConnections()));
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
        final TransactionBroadcast broadcast = new TransactionBroadcast(this, tx);
        broadcast.setMinConnections(minConnections);
        // Send the TX to the wallet once we have a successful broadcast.
        Futures.addCallback(broadcast.future(), new FutureCallback<Transaction>() {
            @Override
            public void onSuccess(Transaction transaction) {
                runningBroadcasts.remove(broadcast);
                // OK, now tell the wallet about the transaction. If the wallet created the transaction then
                // it already knows and will ignore this. If it's a transaction we received from
                // somebody else via a side channel and are now broadcasting, this will put it into the
                // wallet now we know it's valid.
                for (Wallet wallet : wallets) {
                    // Assumption here is there are no dependencies of the created transaction.
                    //
                    // We may end up with two threads trying to do this in parallel - the wallet will
                    // ignore whichever one loses the race.
                    try {
                        wallet.receivePending(transaction, null);
                    } catch (VerificationException e) {
                        throw new RuntimeException(e);   // Cannot fail to verify a tx we created ourselves.
                    }
                }
            }

            @Override
            public void onFailure(Throwable throwable) {
                // This can't happen with the current code, but just in case one day that changes ...
                runningBroadcasts.remove(broadcast);
                throw new RuntimeException(throwable);
            }
        });
        // Keep a reference to the TransactionBroadcast object. This is important because otherwise, the entire tree
        // of objects we just created would become garbage if the user doens't hold on to the returned future, and
        // eventually be collected. This in turn could result in the transaction not being committed to the wallet
        // at all.
        runningBroadcasts.add(broadcast);
        broadcast.broadcast();
        return broadcast.future();
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
     * If a peer is connected to that claims to speak a protocol version lower than the given version, it will
     * be disconnected and another one will be tried instead.
     */
    public void setMinRequiredProtocolVersion(int minRequiredProtocolVersion) {
        this.vMinRequiredProtocolVersion = minRequiredProtocolVersion;
    }

    /** The minimum protocol version required: defaults to the version required for Bloom filtering. */
    public int getMinRequiredProtocolVersion() {
        return vMinRequiredProtocolVersion;
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
        if (peers.isEmpty())
            return 0;
        List<Integer> heights = new ArrayList<Integer>(peers.size());
        for (Peer peer : peers) heights.add((int) peer.getBestHeight());
        return Utils.maxOfMostFreq(heights);
    }

    private static class PeerAndPing {
        Peer peer;
        long pingTime;
    }

    /**
     * Given a list of Peers, return a Peer to be used as the download peer. If you don't want PeerGroup to manage
     * download peer statuses for you, just override this and always return null.
     */
    @Nullable
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
        // If/when PREFERRED_VERSION is not equal to vMinRequiredProtocolVersion, reenable the last test in PeerGroupTest.downloadPeerSelection
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
