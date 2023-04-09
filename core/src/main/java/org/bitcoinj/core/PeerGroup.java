/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.core;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Throwables;
import com.google.common.collect.Maps;
import com.google.common.collect.Ordering;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.Runnables;
import com.google.common.util.concurrent.Uninterruptibles;
import net.jcip.annotations.GuardedBy;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.internal.PlatformUtils;
import org.bitcoinj.base.internal.Stopwatch;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.listeners.AddressEventListener;
import org.bitcoinj.core.listeners.BlockchainDownloadEventListener;
import org.bitcoinj.core.listeners.BlocksDownloadedEventListener;
import org.bitcoinj.core.listeners.ChainDownloadStartedEventListener;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.core.listeners.GetDataEventListener;
import org.bitcoinj.core.listeners.OnTransactionBroadcastListener;
import org.bitcoinj.core.listeners.PeerConnectedEventListener;
import org.bitcoinj.core.listeners.PeerDisconnectedEventListener;
import org.bitcoinj.core.listeners.PeerDiscoveredEventListener;
import org.bitcoinj.core.listeners.PreMessageReceivedEventListener;
import org.bitcoinj.net.ClientConnectionManager;
import org.bitcoinj.net.FilterMerger;
import org.bitcoinj.net.NioClientManager;
import org.bitcoinj.net.discovery.MultiplexingDiscovery;
import org.bitcoinj.net.discovery.PeerDiscovery;
import org.bitcoinj.net.discovery.PeerDiscoveryException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.utils.ContextPropagatingThreadFactory;
import org.bitcoinj.utils.ExponentialBackoff;
import org.bitcoinj.utils.ListenableCompletableFuture;
import org.bitcoinj.utils.ListenerRegistration;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.KeyChainEventListener;
import org.bitcoinj.wallet.listeners.ScriptsChangeEventListener;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.bitcoinj.wallet.listeners.WalletCoinsSentEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;

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
 * <p>A PeerGroup won't do anything until you call the {@link PeerGroup#start()} method 
 * which will block until peer discovery is completed and some outbound connections 
 * have been initiated (it will return before handshaking is done, however). 
 * You should call {@link PeerGroup#stop()} when finished. Note that not all methods
 * of PeerGroup are safe to call from a UI thread as some may do network IO, 
 * but starting and stopping the service should be fine.</p>
 */
public class PeerGroup implements TransactionBroadcaster {
    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    protected final ReentrantLock lock = Threading.lock(PeerGroup.class);

    // All members in this class should be marked with final, volatile, @GuardedBy or a mix as appropriate to define
    // their thread safety semantics. Volatile requires a Hungarian-style v prefix.

    // By default we don't require any services because any peer will do.
    private long requiredServices = 0;
    /**
     * The default number of connections to the p2p network the library will try to build. This is set to 12 empirically.
     * It used to be 4, but because we divide the connection pool in two for broadcasting transactions, that meant we
     * were only sending transactions to two peers and sometimes this wasn't reliable enough: transactions wouldn't
     * get through.
     */
    public static final int DEFAULT_CONNECTIONS = 12;
    private volatile int vMaxPeersToDiscoverCount = 100;
    private static final Duration DEFAULT_PEER_DISCOVERY_TIMEOUT = Duration.ofSeconds(5);
    private volatile Duration vPeerDiscoveryTimeout = DEFAULT_PEER_DISCOVERY_TIMEOUT;

    protected final NetworkParameters params;
    @Nullable protected final AbstractBlockChain chain;

    // This executor is used to queue up jobs: it's used when we don't want to use locks for mutual exclusion,
    // typically because the job might call in to user provided code that needs/wants the freedom to use the API
    // however it wants, or because a job needs to be ordered relative to other jobs like that.
    protected final ScheduledExecutorService executor;

    // Whether the peer group is currently running. Once shut down it cannot be restarted.
    private volatile boolean vRunning;
    // Whether the peer group has been started or not. An unstarted PG does not try to access the network.
    private volatile boolean vUsedUp;

    // Addresses to try to connect to, excluding active peers.
    @GuardedBy("lock") private final PriorityQueue<PeerAddress> inactives;
    @GuardedBy("lock") private final Map<PeerAddress, ExponentialBackoff> backoffMap;
    @GuardedBy("lock") private final Map<PeerAddress, Integer> priorityMap;

    // Currently active peers. This is an ordered list rather than a set to make unit tests predictable.
    private final CopyOnWriteArrayList<Peer> peers;
    // Currently connecting peers.
    private final CopyOnWriteArrayList<Peer> pendingPeers;
    private final ClientConnectionManager channels;

    // The peer that has been selected for the purposes of downloading announced data.
    @GuardedBy("lock") private Peer downloadPeer;
    // Callback for events related to chain download.
    @Nullable @GuardedBy("lock") private BlockchainDownloadEventListener downloadListener;
    private final CopyOnWriteArrayList<ListenerRegistration<BlocksDownloadedEventListener>> peersBlocksDownloadedEventListeners
        = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<ListenerRegistration<ChainDownloadStartedEventListener>> peersChainDownloadStartedEventListeners
        = new CopyOnWriteArrayList<>();
    /** Callbacks for events related to peers connecting */
    protected final CopyOnWriteArrayList<ListenerRegistration<PeerConnectedEventListener>> peerConnectedEventListeners
        = new CopyOnWriteArrayList<>();
    /** Callbacks for events related to peer connection/disconnection */
    protected final CopyOnWriteArrayList<ListenerRegistration<PeerDiscoveredEventListener>> peerDiscoveredEventListeners
        = new CopyOnWriteArrayList<>();
    /** Callbacks for events related to peers disconnecting */
    protected final CopyOnWriteArrayList<ListenerRegistration<PeerDisconnectedEventListener>> peerDisconnectedEventListeners
        = new CopyOnWriteArrayList<>();
    /** Callbacks for events related to peer data being received */
    private final CopyOnWriteArrayList<ListenerRegistration<GetDataEventListener>> peerGetDataEventListeners
        = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<ListenerRegistration<PreMessageReceivedEventListener>> peersPreMessageReceivedEventListeners
        = new CopyOnWriteArrayList<>();
    protected final CopyOnWriteArrayList<ListenerRegistration<OnTransactionBroadcastListener>> peersTransactionBroadastEventListeners
        = new CopyOnWriteArrayList<>();
    // Discover peers via addr and addrv2 messages?
    private volatile boolean vDiscoverPeersViaP2P = false;
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private final CopyOnWriteArraySet<PeerDiscovery> peerDiscoverers;

    // The version message to use for new connections.
    @GuardedBy("lock") private VersionMessage versionMessage;
    // Maximum depth up to which pending transaction dependencies are downloaded, or 0 for disabled.
    @GuardedBy("lock") private int downloadTxDependencyDepth;
    // How many connections we want to have open at the current time. If we lose connections, we'll try opening more
    // until we reach this count.
    @GuardedBy("lock") private int maxConnections;
    // Minimum protocol version we will allow ourselves to connect to: require Bloom filtering.
    private volatile int vMinRequiredProtocolVersion;

    /** How many milliseconds to wait after receiving a pong before sending another ping. */
    public static final long DEFAULT_PING_INTERVAL_MSEC = 2000;
    @GuardedBy("lock") private long pingIntervalMsec = DEFAULT_PING_INTERVAL_MSEC;

    @GuardedBy("lock") private boolean useLocalhostPeerWhenPossible = true;
    @GuardedBy("lock") private boolean ipv6Unreachable = false;

    @GuardedBy("lock") private Instant fastCatchupTime;
    private final CopyOnWriteArrayList<Wallet> wallets;
    private final CopyOnWriteArrayList<PeerFilterProvider> peerFilterProviders;

    // This event listener is added to every peer. It's here so when we announce transactions via an "inv", every
    // peer can fetch them.
    private final PeerListener peerListener = new PeerListener();

    private int minBroadcastConnections = 0;
    private final ScriptsChangeEventListener walletScriptsEventListener = (wallet, scripts, isAddingScripts) -> recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);

    private final KeyChainEventListener walletKeyEventListener = keys -> recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);

    private final WalletCoinsReceivedEventListener walletCoinsReceivedEventListener = (wallet, tx, prevBalance, newBalance) -> onCoinsReceivedOrSent(wallet, tx);

    private final WalletCoinsSentEventListener walletCoinsSentEventListener = (wallet, tx, prevBalance, newBalance) -> onCoinsReceivedOrSent(wallet, tx);

    public static final int MAX_ADDRESSES_PER_ADDR_MESSAGE = 16;

    private void onCoinsReceivedOrSent(Wallet wallet, Transaction tx) {
        // We received a relevant transaction. We MAY need to recalculate and resend the Bloom filter, but only
        // if we have received a transaction that includes a relevant P2PK or P2WPKH output.
        //
        // The reason is that P2PK and P2WPKH outputs, when spent, will not repeat any data we can predict in their
        // inputs. So a remote peer will update the Bloom filter for us when such an output is seen matching the
        // existing filter, so that it includes the tx hash in which the P2PK/P2WPKH output was observed. Thus
        // the spending transaction will always match (due to the outpoint structure).
        //
        // Unfortunately, whilst this is required for correct sync of the chain in blocks, there are two edge cases.
        //
        // (1) If a wallet receives a relevant, confirmed P2PK/P2WPKH output that was not broadcast across the network,
        // for example in a coinbase transaction, then the node that's serving us the chain will update its filter
        // but the rest will not. If another transaction then spends it, the other nodes won't match/relay it.
        //
        // (2) If we receive a P2PK/P2WPKH output broadcast across the network, all currently connected nodes will see
        // it and update their filter themselves, but any newly connected nodes will receive the last filter we
        // calculated, which would not include this transaction.
        //
        // For this reason we check if the transaction contained any relevant P2PKs or P2WPKHs and force a recalc
        // and possibly retransmit if so. The recalculation process will end up including the tx hash into the
        // filter. In case (1), we need to retransmit the filter to the connected peers. In case (2), we don't
        // and shouldn't, we should just recalculate and cache the new filter for next time.
        for (TransactionOutput output : tx.getOutputs()) {
            Script scriptPubKey = output.getScriptPubKey();
            if (ScriptPattern.isP2PK(scriptPubKey) || ScriptPattern.isP2WPKH(scriptPubKey)) {
                if (output.isMine(wallet)) {
                    if (tx.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.BUILDING)
                        recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
                    else
                        recalculateFastCatchupAndFilter(FilterRecalculateMode.DONT_SEND);
                    return;
                }
            }
        }
    }

    // Exponential backoff for peers starts at 1 second and maxes at 10 minutes.
    private final ExponentialBackoff.Params peerBackoffParams = new ExponentialBackoff.Params(Duration.ofSeconds(1),
            1.5f, Duration.ofMinutes(10));
    // Tracks failures globally in case of a network failure.
    @GuardedBy("lock") private ExponentialBackoff groupBackoff = new ExponentialBackoff(new ExponentialBackoff.Params(Duration.ofSeconds(1), 1.5f, Duration.ofSeconds(10)));

    // This is a synchronized set, so it locks on itself. We use it to prevent TransactionBroadcast objects from
    // being garbage collected if nothing in the apps code holds on to them transitively. See the discussion
    // in broadcastTransaction.
    private final Set<TransactionBroadcast> runningBroadcasts;

    private class PeerListener implements GetDataEventListener, BlocksDownloadedEventListener, AddressEventListener {

        public PeerListener() {
        }

        @Override
        public List<Message> getData(Peer peer, GetDataMessage m) {
            return handleGetData(m);
        }

        @Override
        public void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft) {
            if (chain == null) return;
            final double rate = chain.getFalsePositiveRate();
            final double target = bloomFilterMerger.getBloomFilterFPRate() * MAX_FP_RATE_INCREASE;
            if (rate > target) {
                // TODO: Avoid hitting this path if the remote peer didn't acknowledge applying a new filter yet.
                log.info("Force update Bloom filter due to high false positive rate ({} vs {})", rate, target);
                recalculateFastCatchupAndFilter(FilterRecalculateMode.FORCE_SEND_FOR_REFRESH);
            }
        }

        /**
         * Called when a peer receives an {@code addr} or {@code addrv2} message, usually in response to a
         * {@code getaddr} message.
         *
         * @param peer    the peer that received the addr or addrv2 message
         * @param message the addr or addrv2 message that was received
         */
        @Override
        public void onAddr(Peer peer, AddressMessage message) {
            if (!vDiscoverPeersViaP2P)
                return;
            List<PeerAddress> addresses = new LinkedList<>(message.getAddresses());
            // Make sure we pick random addresses.
            Collections.shuffle(addresses);
            int numAdded = 0;
            for (PeerAddress address : addresses) {
                // Add to inactive pool.
                boolean added = addInactive(address, 0);
                if (added)
                    numAdded++;
                // Limit addresses picked per message.
                if (numAdded >= MAX_ADDRESSES_PER_ADDR_MESSAGE)
                    break;
            }
            log.info("{} gossiped {} addresses, added {} of them to the inactive pool", peer.getAddress(),
                    addresses.size(), numAdded);
        }
    }

    private class PeerStartupListener implements PeerConnectedEventListener, PeerDisconnectedEventListener {
        @Override
        public void onPeerConnected(Peer peer, int peerCount) {
            handleNewPeer(peer);
        }

        @Override
        public void onPeerDisconnected(Peer peer, int peerCount) {
            // The channel will be automatically removed from channels.
            handlePeerDeath(peer, null);
        }
    }

    private final PeerStartupListener startupListener = new PeerStartupListener();

    /**
     * The default Bloom filter false positive rate, which is selected to be extremely low such that you hardly ever
     * download false positives. This provides maximum performance. Although this default can be overridden to push
     * the FP rate higher, due to <a href="https://groups.google.com/forum/#!msg/bitcoinj/Ys13qkTwcNg/9qxnhwnkeoIJ">
     * various complexities</a> there are still ways a remote peer can deanonymize the users wallet. This is why the
     * FP rate is chosen for performance rather than privacy. If a future version of bitcoinj fixes the known
     * de-anonymization attacks this FP rate may rise again (or more likely, become expressed as a bandwidth allowance).
     */
    public static final double DEFAULT_BLOOM_FILTER_FP_RATE = 0.00001;
    /** Maximum increase in FP rate before forced refresh of the bloom filter */
    public static final double MAX_FP_RATE_INCREASE = 10.0f;
    // An object that calculates bloom filters given a list of filter providers, whilst tracking some state useful
    // for privacy purposes.
    private final FilterMerger bloomFilterMerger;

    /** The default timeout between when a connection attempt begins and version message exchange completes */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private volatile Duration vConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    /** Whether bloom filter support is enabled when using a non FullPrunedBlockchain*/
    private volatile boolean vBloomFilteringEnabled = true;

    /**
     * Creates a PeerGroup for the given network. No chain is provided so this node will report its chain height
     * as zero to other peers. This constructor is useful if you just want to explore the network but aren't interested
     * in downloading block data.
     * @param network the P2P network to connect to
     */
    public PeerGroup(Network network) {
        this(network, null);
    }

    /**
     * Creates a PeerGroup with the given network. No chain is provided so this node will report its chain height
     * as zero to other peers. This constructor is useful if you just want to explore the network but aren't interested
     * in downloading block data.
     * @deprecated Use {@link #PeerGroup(Network)}
     */
    @Deprecated
    public PeerGroup(NetworkParameters params) {
        this(params.network());
    }

    /**
     * Creates a PeerGroup for the given network and chain. Blocks will be passed to the chain as they are broadcast
     * and downloaded. This is probably the constructor you want to use.
     * @param network the P2P network to connect to
     * @param chain used to process blocks
     */
    public PeerGroup(Network network, @Nullable AbstractBlockChain chain) {
        this(network, chain, new NioClientManager());
    }

    /**
     * Creates a PeerGroup for the given network and chain. Blocks will be passed to the chain as they are broadcast
     * and downloaded.
     * @deprecated Use {@link PeerGroup#PeerGroup(Network, AbstractBlockChain)}
     */
    @Deprecated
    public PeerGroup(NetworkParameters params, @Nullable AbstractBlockChain chain) {
        this(params.network(), chain);
    }

    /**
     * Create a PeerGroup for the given network, chain and connection manager.
     * @param network the P2P network to connect to
     * @param chain used to process blocks
     * @param connectionManager used to create new connections and keep track of existing ones.
     */
    protected PeerGroup(Network network, @Nullable AbstractBlockChain chain, ClientConnectionManager connectionManager) {
        this(NetworkParameters.of(Objects.requireNonNull(network)), chain, connectionManager);
    }

    /**
     * Create a PeerGroup for the given network, chain and connection manager.
     * @param params the P2P network to connect to
     * @param chain used to process blocks
     * @param connectionManager used to create new connections and keep track of existing ones.
     */
    @VisibleForTesting
    protected PeerGroup(NetworkParameters params, @Nullable AbstractBlockChain chain, ClientConnectionManager connectionManager) {
        Objects.requireNonNull(params);
        Context.getOrCreate(); // create a context for convenience
        this.params = params;
        this.chain = chain;
        fastCatchupTime = params.getGenesisBlock().time();
        wallets = new CopyOnWriteArrayList<>();
        peerFilterProviders = new CopyOnWriteArrayList<>();

        executor = createPrivateExecutor();

        // This default sentinel value will be overridden by one of two actions:
        //   - adding a peer discovery source sets it to the default
        //   - using connectTo() will increment it by one
        maxConnections = 0;

        int height = chain == null ? 0 : chain.getBestChainHeight();
        versionMessage = new VersionMessage(params, height);
        // We never request that the remote node wait for a bloom filter yet, as we have no wallets
        versionMessage.relayTxesBeforeFilter = true;

        downloadTxDependencyDepth = Integer.MAX_VALUE;

        inactives = new PriorityQueue<>(1, new Comparator<PeerAddress>() {
            @SuppressWarnings("FieldAccessNotGuarded")   // only called when inactives is accessed, and lock is held then.
            @Override
            public int compare(PeerAddress a, PeerAddress b) {
                checkState(lock.isHeldByCurrentThread());
                int result = backoffMap.get(a).compareTo(backoffMap.get(b));
                if (result != 0)
                    return result;
                result = Integer.compare(getPriority(a), getPriority(b));
                if (result != 0)
                    return result;
                // Sort by port if otherwise equals - for testing
                result = Integer.compare(a.getPort(), b.getPort());
                return result;
            }
        });
        backoffMap = new HashMap<>();
        priorityMap = new ConcurrentHashMap<>();
        peers = new CopyOnWriteArrayList<>();
        pendingPeers = new CopyOnWriteArrayList<>();
        channels = connectionManager;
        peerDiscoverers = new CopyOnWriteArraySet<>();
        runningBroadcasts = Collections.synchronizedSet(new HashSet<TransactionBroadcast>());
        bloomFilterMerger = new FilterMerger(DEFAULT_BLOOM_FILTER_FP_RATE);
        vMinRequiredProtocolVersion = ProtocolVersion.BLOOM_FILTER.intValue();
    }

    private CountDownLatch executorStartupLatch = new CountDownLatch(1);

    protected ScheduledExecutorService createPrivateExecutor() {
        ScheduledExecutorService result =
                new ScheduledThreadPoolExecutor(1, new ContextPropagatingThreadFactory("PeerGroup Thread"));
        // Hack: jam the executor so jobs just queue up until the user calls start() on us. For example, adding a wallet
        // results in a bloom filter recalc being queued, but we don't want to do that until we're actually started.
        result.execute(() -> Uninterruptibles.awaitUninterruptibly(executorStartupLatch));
        return result;
    }

    /**
     * This is how long we wait for peer discoveries to return their results.
     */
    public void setPeerDiscoveryTimeout(Duration peerDiscoveryTimeout) {
        this.vPeerDiscoveryTimeout = peerDiscoveryTimeout;
    }

    /**
     * This is how many milliseconds we wait for peer discoveries to return their results.
     * @deprecated use {@link #setPeerDiscoveryTimeout(Duration)}
     */
    @Deprecated
    public void setPeerDiscoveryTimeoutMillis(long peerDiscoveryTimeoutMillis) {
        setPeerDiscoveryTimeout(Duration.ofMillis(peerDiscoveryTimeoutMillis));
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

    /**
     * Configure download of pending transaction dependencies. A change of values only takes effect for newly connected
     * peers.
     */
    public void setDownloadTxDependencies(int depth) {
        lock.lock();
        try {
            this.downloadTxDependencyDepth = depth;
        } finally {
            lock.unlock();
        }
    }

    private Runnable triggerConnectionsJob = new Runnable() {
        private boolean firstRun = true;
        private final Duration MIN_PEER_DISCOVERY_INTERVAL = Duration.ofSeconds(1);

        @Override
        public void run() {
            try {
                go();
            } catch (Throwable e) {
                log.error("Exception when trying to build connections", e);  // The executor swallows exceptions :(
            }
        }

        public void go() {
            if (!vRunning) return;

            boolean doDiscovery = false;
            Instant now = TimeUtils.currentTime();
            lock.lock();
            try {
                // First run: try and use a local node if there is one, for the additional security it can provide.
                // But, not on Android as there are none for this platform: it could only be a malicious app trying
                // to hijack our traffic.
                if (!PlatformUtils.isAndroidRuntime() && useLocalhostPeerWhenPossible && maybeCheckForLocalhostPeer() && firstRun) {
                    log.info("Localhost peer detected, trying to use it instead of P2P discovery");
                    maxConnections = 0;
                    connectToLocalHost();
                    return;
                }

                boolean havePeerWeCanTry = !inactives.isEmpty() && backoffMap.get(inactives.peek()).retryTime().isBefore(now);
                doDiscovery = !havePeerWeCanTry;
            } finally {
                firstRun = false;
                lock.unlock();
            }

            // Don't hold the lock across discovery as this process can be very slow.
            boolean discoverySuccess = false;
            if (doDiscovery) {
                discoverySuccess = discoverPeers() > 0;
            }

            lock.lock();
            try {
                if (doDiscovery) {
                    // Require that we have enough connections, to consider this
                    // a success, or we just constantly test for new peers
                    if (discoverySuccess && countConnectedAndPendingPeers() >= getMaxConnections()) {
                        groupBackoff.trackSuccess();
                    } else {
                        groupBackoff.trackFailure();
                    }
                }
                // Inactives is sorted by backoffMap time.
                if (inactives.isEmpty()) {
                    if (countConnectedAndPendingPeers() < getMaxConnections()) {
                        Duration interval = TimeUtils.longest(Duration.between(now, groupBackoff.retryTime()), MIN_PEER_DISCOVERY_INTERVAL);
                        log.info("Peer discovery didn't provide us any more peers, will try again in "
                            + interval.toMillis() + " ms.");
                        executor.schedule(this, interval.toMillis(), TimeUnit.MILLISECONDS);
                    } else {
                        // We have enough peers and discovery provided no more, so just settle down. Most likely we
                        // were given a fixed set of addresses in some test scenario.
                    }
                    return;
                }
                PeerAddress addrToTry;
                do {
                    addrToTry = inactives.poll();
                } while (ipv6Unreachable && addrToTry.getAddr() instanceof Inet6Address);
                if (addrToTry == null) {
                    // We have exhausted the queue of reachable peers, so just settle down.
                    // Most likely we were given a fixed set of addresses in some test scenario.
                    return;
                }
                Instant retryTime = backoffMap.get(addrToTry).retryTime();
                retryTime = TimeUtils.later(retryTime, groupBackoff.retryTime());
                if (retryTime.isAfter(now)) {
                    Duration delay = Duration.between(now, retryTime);
                    log.info("Waiting {} ms before next connect attempt to {}", delay.toMillis(), addrToTry);
                    inactives.add(addrToTry);
                    executor.schedule(this, delay.toMillis(), TimeUnit.MILLISECONDS);
                    return;
                }
                connectTo(addrToTry, false, vConnectTimeout);
            } finally {
                lock.unlock();
            }
            if (countConnectedAndPendingPeers() < getMaxConnections()) {
                executor.execute(this);   // Try next peer immediately.
            }
        }
    };

    private void triggerConnections() {
        // Run on a background thread due to the need to potentially retry and back off in the background.
        if (!executor.isShutdown())
            executor.execute(triggerConnectionsJob);
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
            LinkedList<Message> transactions = new LinkedList<>();
            LinkedList<InventoryItem> items = new LinkedList<>(m.getItems());
            Iterator<InventoryItem> it = items.iterator();
            while (it.hasNext()) {
                InventoryItem item = it.next();
                // Check the wallets.
                for (Wallet w : wallets) {
                    Transaction tx = w.getTransaction(item.hash);
                    if (tx == null) continue;
                    transactions.add(tx);
                    it.remove();
                    break;
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
        VersionMessage ver = new VersionMessage(params, height);
        ver.relayTxesBeforeFilter = false;
        updateVersionMessageRelayTxesBeforeFilter(ver);
        ver.appendToSubVer(name, version, comments);
        setVersionMessage(ver);
    }
    
    // Updates the relayTxesBeforeFilter flag of ver
    private void updateVersionMessageRelayTxesBeforeFilter(VersionMessage ver) {
        // We will provide the remote node with a bloom filter (ie they shouldn't relay yet)
        // if chain == null || !chain.shouldVerifyTransactions() and a wallet is added and bloom filters are enabled
        // Note that the default here means that no tx invs will be received if no wallet is ever added
        lock.lock();
        try {
            boolean spvMode = chain != null && !chain.shouldVerifyTransactions();
            boolean willSendFilter = spvMode && peerFilterProviders.size() > 0 && vBloomFilteringEnabled;
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

    /** See {@link Peer#addBlocksDownloadedEventListener(BlocksDownloadedEventListener)} */
    public void addBlocksDownloadedEventListener(BlocksDownloadedEventListener listener) {
        addBlocksDownloadedEventListener(Threading.USER_THREAD, listener);
    }

    /**
     * <p>Adds a listener that will be notified on the given executor when
     * blocks are downloaded by the download peer.</p>
     * @see Peer#addBlocksDownloadedEventListener(Executor, BlocksDownloadedEventListener)
     */
    public void addBlocksDownloadedEventListener(Executor executor, BlocksDownloadedEventListener listener) {
        peersBlocksDownloadedEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
        for (Peer peer : getConnectedPeers())
            peer.addBlocksDownloadedEventListener(executor, listener);
        for (Peer peer : getPendingPeers())
            peer.addBlocksDownloadedEventListener(executor, listener);
    }

    /** See {@link Peer#addBlocksDownloadedEventListener(BlocksDownloadedEventListener)} */
    public void addChainDownloadStartedEventListener(ChainDownloadStartedEventListener listener) {
        addChainDownloadStartedEventListener(Threading.USER_THREAD, listener);
    }

    /**
     * <p>Adds a listener that will be notified on the given executor when
     * chain download starts.</p>
     */
    public void addChainDownloadStartedEventListener(Executor executor, ChainDownloadStartedEventListener listener) {
        peersChainDownloadStartedEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
        for (Peer peer : getConnectedPeers())
            peer.addChainDownloadStartedEventListener(executor, listener);
        for (Peer peer : getPendingPeers())
            peer.addChainDownloadStartedEventListener(executor, listener);
    }

    /** See {@link Peer#addConnectedEventListener(PeerConnectedEventListener)} */
    public void addConnectedEventListener(PeerConnectedEventListener listener) {
        addConnectedEventListener(Threading.USER_THREAD, listener);
    }

    /**
     * <p>Adds a listener that will be notified on the given executor when
     * new peers are connected to.</p>
     */
    public void addConnectedEventListener(Executor executor, PeerConnectedEventListener listener) {
        peerConnectedEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
        for (Peer peer : getConnectedPeers())
            peer.addConnectedEventListener(executor, listener);
        for (Peer peer : getPendingPeers())
            peer.addConnectedEventListener(executor, listener);
    }

    /** See {@link Peer#addDisconnectedEventListener(PeerDisconnectedEventListener)} */
    public void addDisconnectedEventListener(PeerDisconnectedEventListener listener) {
        addDisconnectedEventListener(Threading.USER_THREAD, listener);
    }

    /**
     * <p>Adds a listener that will be notified on the given executor when
     * peers are disconnected from.</p>
     */
    public void addDisconnectedEventListener(Executor executor, PeerDisconnectedEventListener listener) {
        peerDisconnectedEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
        for (Peer peer : getConnectedPeers())
            peer.addDisconnectedEventListener(executor, listener);
        for (Peer peer : getPendingPeers())
            peer.addDisconnectedEventListener(executor, listener);
    }

    /** See {@link PeerGroup#addDiscoveredEventListener(Executor, PeerDiscoveredEventListener)} */
    public void addDiscoveredEventListener(PeerDiscoveredEventListener listener) {
        addDiscoveredEventListener(Threading.USER_THREAD, listener);
    }

    /**
     * <p>Adds a listener that will be notified on the given executor when new
     * peers are discovered.</p>
     */
    public void addDiscoveredEventListener(Executor executor, PeerDiscoveredEventListener listener) {
        peerDiscoveredEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
    }

    /** See {@link Peer#addGetDataEventListener(GetDataEventListener)} */
    public void addGetDataEventListener(GetDataEventListener listener) {
        addGetDataEventListener(Threading.USER_THREAD, listener);
    }

    /** See {@link Peer#addGetDataEventListener(Executor, GetDataEventListener)} */
    public void addGetDataEventListener(final Executor executor, final GetDataEventListener listener) {
        peerGetDataEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
        for (Peer peer : getConnectedPeers())
            peer.addGetDataEventListener(executor, listener);
        for (Peer peer : getPendingPeers())
            peer.addGetDataEventListener(executor, listener);
    }

    /** See {@link Peer#addOnTransactionBroadcastListener(OnTransactionBroadcastListener)} */
    public void addOnTransactionBroadcastListener(OnTransactionBroadcastListener listener) {
        addOnTransactionBroadcastListener(Threading.USER_THREAD, listener);
    }

    /** See {@link Peer#addOnTransactionBroadcastListener(OnTransactionBroadcastListener)} */
    public void addOnTransactionBroadcastListener(Executor executor, OnTransactionBroadcastListener listener) {
        peersTransactionBroadastEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
        for (Peer peer : getConnectedPeers())
            peer.addOnTransactionBroadcastListener(executor, listener);
        for (Peer peer : getPendingPeers())
            peer.addOnTransactionBroadcastListener(executor, listener);
    }

    /** See {@link Peer#addPreMessageReceivedEventListener(PreMessageReceivedEventListener)} */
    public void addPreMessageReceivedEventListener(PreMessageReceivedEventListener listener) {
        addPreMessageReceivedEventListener(Threading.USER_THREAD, listener);
    }

    /** See {@link Peer#addPreMessageReceivedEventListener(Executor, PreMessageReceivedEventListener)} */
    public void addPreMessageReceivedEventListener(Executor executor, PreMessageReceivedEventListener listener) {
        peersPreMessageReceivedEventListeners.add(new ListenerRegistration<>(Objects.requireNonNull(listener), executor));
        for (Peer peer : getConnectedPeers())
            peer.addPreMessageReceivedEventListener(executor, listener);
        for (Peer peer : getPendingPeers())
            peer.addPreMessageReceivedEventListener(executor, listener);
    }

    public boolean removeBlocksDownloadedEventListener(BlocksDownloadedEventListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peersBlocksDownloadedEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removeBlocksDownloadedEventListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removeBlocksDownloadedEventListener(listener);
        return result;
    }

    public boolean removeChainDownloadStartedEventListener(ChainDownloadStartedEventListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peersChainDownloadStartedEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removeChainDownloadStartedEventListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removeChainDownloadStartedEventListener(listener);
        return result;
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeConnectedEventListener(PeerConnectedEventListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peerConnectedEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removeConnectedEventListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removeConnectedEventListener(listener);
        return result;
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeDisconnectedEventListener(PeerDisconnectedEventListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peerDisconnectedEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removeDisconnectedEventListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removeDisconnectedEventListener(listener);
        return result;
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeDiscoveredEventListener(PeerDiscoveredEventListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peerDiscoveredEventListeners);
        return result;
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeGetDataEventListener(GetDataEventListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peerGetDataEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removeGetDataEventListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removeGetDataEventListener(listener);
        return result;
    }

    /** The given event listener will no longer be called with events. */
    public boolean removeOnTransactionBroadcastListener(OnTransactionBroadcastListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peersTransactionBroadastEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removeOnTransactionBroadcastListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removeOnTransactionBroadcastListener(listener);
        return result;
    }

    public boolean removePreMessageReceivedEventListener(PreMessageReceivedEventListener listener) {
        boolean result = ListenerRegistration.removeFromList(listener, peersPreMessageReceivedEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removePreMessageReceivedEventListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removePreMessageReceivedEventListener(listener);
        return result;
    }

    /**
     * Returns a newly allocated list containing the currently connected peers. If all you care about is the count,
     * use numConnectedPeers().
     */
    public List<Peer> getConnectedPeers() {
        lock.lock();
        try {
            return new ArrayList<>(peers);
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
            return new ArrayList<>(pendingPeers);
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
        addAddress(peerAddress, 0);
    }

    /**
     * Add an address to the list of potential peers to connect to. It won't necessarily be used unless there's a need
     * to build new connections to reach the max connection count.
     *
     * @param peerAddress IP/port to use.
     * @param priority for connecting and being picked as a download peer
     */
    public void addAddress(PeerAddress peerAddress, int priority) {
        int newMax;
        lock.lock();
        try {
            if (addInactive(peerAddress, priority)) {
                newMax = getMaxConnections() + 1;
                setMaxConnections(newMax);
            }
        } finally {
            lock.unlock();
        }
    }

    // Adds peerAddress to backoffMap map and inactives queue.
    // Returns true if it was added, false if it was already there.
    private boolean addInactive(PeerAddress peerAddress, int priority) {
        lock.lock();
        try {
            // Deduplicate
            if (backoffMap.containsKey(peerAddress))
                return false;
            backoffMap.put(peerAddress, new ExponentialBackoff(peerBackoffParams));
            if (priority != 0)
                priorityMap.put(peerAddress, priority);
            inactives.offer(peerAddress);
            return true;
        } finally {
            lock.unlock();
        }
    }

    private int getPriority(PeerAddress peerAddress) {
        Integer priority = priorityMap.get(peerAddress);
        return priority != null ? priority : 0;
    }

    /**
     * Convenience for connecting only to peers that can serve specific services. It will configure suitable peer
     * discoveries.
     * @param requiredServices Required services as a bitmask, e.g. {@link Services#NODE_NETWORK}.
     */
    public void setRequiredServices(long requiredServices) {
        lock.lock();
        try {
            this.requiredServices = requiredServices;
            peerDiscoverers.clear();
            addPeerDiscovery(MultiplexingDiscovery.forServices(params, requiredServices));
        } finally {
            lock.unlock();
        }
    }

    /** Convenience method for {@link #addAddress(PeerAddress)}. */
    public void addAddress(InetAddress address) {
        addAddress(new PeerAddress(address, params.getPort()));
    }

    /** Convenience method for {@link #addAddress(PeerAddress, int)}. */
    public void addAddress(InetAddress address, int priority) {
        addAddress(new PeerAddress(address, params.getPort()), priority);
    }

    /**
     * Setting this to {@code true} will add addresses discovered via P2P {@code addr} and {@code addrv2} messages to
     * the list of potential peers to connect to. This will automatically be set to true if at least one peer discovery
     * is added via {@link #addPeerDiscovery(PeerDiscovery)}.
     *
     * @param discoverPeersViaP2P true if peers should be discovered from the P2P network
     */
    public void setDiscoverPeersViaP2P(boolean discoverPeersViaP2P) {
        vDiscoverPeersViaP2P = discoverPeersViaP2P;
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
        setDiscoverPeersViaP2P(true);
    }

    /** Returns number of discovered peers. */
    protected int discoverPeers() {
        // Don't hold the lock whilst doing peer discovery: it can take a long time and cause high API latency.
        checkState(!lock.isHeldByCurrentThread());
        int maxPeersToDiscoverCount = this.vMaxPeersToDiscoverCount;
        Duration peerDiscoveryTimeout = this.vPeerDiscoveryTimeout;
        Stopwatch watch = Stopwatch.start();
        final List<PeerAddress> addressList = new LinkedList<>();
        for (PeerDiscovery peerDiscovery : peerDiscoverers /* COW */) {
            List<InetSocketAddress> addresses;
            try {
                addresses = peerDiscovery.getPeers(requiredServices, peerDiscoveryTimeout);
            } catch (PeerDiscoveryException e) {
                log.warn(e.getMessage());
                continue;
            }
            for (InetSocketAddress address : addresses) addressList.add(new PeerAddress(address));
            if (addressList.size() >= maxPeersToDiscoverCount) break;
        }
        if (!addressList.isEmpty()) {
            for (PeerAddress address : addressList) {
                addInactive(address, 0);
            }
            final Set<PeerAddress> peersDiscoveredSet = Collections.unmodifiableSet(new HashSet<>(addressList));
            for (final ListenerRegistration<PeerDiscoveredEventListener> registration : peerDiscoveredEventListeners /* COW */) {
                registration.executor.execute(() -> registration.listener.onPeersDiscovered(peersDiscoveredSet));
            }
        }
        log.info("Peer discovery took {} and returned {} items from {} discoverers",
                watch, addressList.size(), peerDiscoverers.size());
        return addressList.size();
    }

    @VisibleForTesting
    void waitForJobQueue() {
        Futures.getUnchecked(executor.submit(Runnables.doNothing()));
    }

    private int countConnectedAndPendingPeers() {
        lock.lock();
        try {
            return peers.size() + pendingPeers.size();
        } finally {
            lock.unlock();
        }
    }

    private enum LocalhostCheckState {
        NOT_TRIED,
        FOUND,
        FOUND_AND_CONNECTED,
        NOT_THERE
    }
    private LocalhostCheckState localhostCheckState = LocalhostCheckState.NOT_TRIED;

    private boolean maybeCheckForLocalhostPeer() {
        checkState(lock.isHeldByCurrentThread());
        if (localhostCheckState == LocalhostCheckState.NOT_TRIED) {
            // Do a fast blocking connect to see if anything is listening.
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), params.getPort()),
                        Math.toIntExact(vConnectTimeout.toMillis()));
                localhostCheckState = LocalhostCheckState.FOUND;
                return true;
            } catch (IOException e) {
                log.info("Localhost peer not detected.");
                localhostCheckState = LocalhostCheckState.NOT_THERE;
            }
        }
        return false;
    }

    /**
     * Starts the PeerGroup and begins network activity.
     * @return A future that completes when first connection activity has been triggered (note: not first connection made).
     */
    public ListenableCompletableFuture<Void> startAsync() {
        // This is run in a background thread by the Service implementation.
        if (chain == null) {
            // Just try to help catch what might be a programming error.
            log.warn("Starting up with no attached block chain. Did you forget to pass one to the constructor?");
        }
        checkState(!vUsedUp, () ->
                "cannot start a peer group twice");
        vRunning = true;
        vUsedUp = true;
        executorStartupLatch.countDown();
        // We do blocking waits during startup, so run on the executor thread.
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                log.info("Starting ...");
                channels.startAsync();
                channels.awaitRunning();
                triggerConnections();
                setupPinging();
            } catch (Throwable e) {
                log.error("Exception when starting up", e);  // The executor swallows exceptions :(
            }
        }, executor);
        return ListenableCompletableFuture.of(future);
    }

    /** Does a blocking startup. */
    public void start() {
        startAsync().join();
    }

    public ListenableCompletableFuture<Void>  stopAsync() {
        checkState(vRunning);
        vRunning = false;
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                log.info("Stopping ...");
                Stopwatch watch = Stopwatch.start();
                // The log output this creates can be useful.
                setDownloadPeer(null);
                // Blocking close of all sockets.
                channels.stopAsync();
                channels.awaitTerminated();
                for (PeerDiscovery peerDiscovery : peerDiscoverers) {
                    peerDiscovery.shutdown();
                }
                vRunning = false;
                log.info("Stopped, took {}.", watch);
            } catch (Throwable e) {
                log.error("Exception when shutting down", e);  // The executor swallows exceptions :(
            }
        }, executor);
        executor.shutdown();
        return ListenableCompletableFuture.of(future);
    }

    /** Does a blocking stop */
    public void stop() {
        try {
            Stopwatch watch = Stopwatch.start();
            stopAsync();
            log.info("Awaiting PeerGroup shutdown ...");
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS);
            log.info("... took {}", watch);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Gracefully drops all connected peers.
     */
    public void dropAllPeers() {
        lock.lock();
        try {
            for (Peer peer : peers)
                peer.close();
        } finally {
            lock.unlock();
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
            Objects.requireNonNull(wallet);
            checkState(!wallets.contains(wallet));
            wallets.add(wallet);
            wallet.setTransactionBroadcaster(this);
            wallet.addCoinsReceivedEventListener(Threading.SAME_THREAD, walletCoinsReceivedEventListener);
            wallet.addCoinsSentEventListener(Threading.SAME_THREAD, walletCoinsSentEventListener);
            wallet.addKeyChainEventListener(Threading.SAME_THREAD, walletKeyEventListener);
            wallet.addScriptsChangeEventListener(Threading.SAME_THREAD, walletScriptsEventListener);
            addPeerFilterProvider(wallet);
            for (Peer peer : peers) {
                peer.addWallet(wallet);
            }
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
     *
     * <p>This method invokes {@link PeerGroup#recalculateFastCatchupAndFilter(FilterRecalculateMode)}.
     * The return value of this method is the {@code ListenableCompletableFuture} returned by that invocation.</p>
     *
     * @return a future that completes once each {@code Peer} in this group has had its
     *         {@code BloomFilter} (re)set.
     */
    public ListenableCompletableFuture<BloomFilter> addPeerFilterProvider(PeerFilterProvider provider) {
        lock.lock();
        try {
            Objects.requireNonNull(provider);
            checkState(!peerFilterProviders.contains(provider));
            // Insert provider at the start. This avoids various concurrency problems that could occur because we need
            // all providers to be in a consistent, unchanging state whilst the filter is built. Providers can give
            // this guarantee by taking a lock in their begin method, but if we add to the end of the list here, it
            // means we establish a lock ordering a > b > c if that's the order the providers were added in. Given that
            // the main wallet will usually be first, this establishes an ordering wallet > other-provider, which means
            // other-provider can then not call into the wallet itself. Other providers installed by the API user should
            // come first so the expected ordering is preserved. This can also manifest itself in providers that use
            // synchronous RPCs into an actor instead of locking, but the same issue applies.
            peerFilterProviders.add(0, provider);

            // Don't bother downloading block bodies before the oldest keys in all our wallets. Make sure we recalculate
            // if a key is added. Of course, by then we may have downloaded the chain already. Ideally adding keys would
            // automatically rewind the block chain and redownload the blocks to find transactions relevant to those keys,
            // all transparently and in the background. But we are a long way from that yet.
            ListenableCompletableFuture<BloomFilter> future = recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
            updateVersionMessageRelayTxesBeforeFilter(getVersionMessage());
            return future;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Opposite of {@link #addPeerFilterProvider(PeerFilterProvider)}. Again, don't use this for wallets. Does not
     * trigger recalculation of the filter.
     */
    public void removePeerFilterProvider(PeerFilterProvider provider) {
        lock.lock();
        try {
            Objects.requireNonNull(provider);
            checkArgument(peerFilterProviders.remove(provider));
        } finally {
            lock.unlock();
        }
    }

    /**
     * Unlinks the given wallet so it no longer receives broadcast transactions or has its transactions announced.
     */
    public void removeWallet(Wallet wallet) {
        wallets.remove(Objects.requireNonNull(wallet));
        peerFilterProviders.remove(wallet);
        wallet.removeCoinsReceivedEventListener(walletCoinsReceivedEventListener);
        wallet.removeCoinsSentEventListener(walletCoinsSentEventListener);
        wallet.removeKeyChainEventListener(walletKeyEventListener);
        wallet.removeScriptsChangeEventListener(walletScriptsEventListener);
        wallet.setTransactionBroadcaster(null);
        for (Peer peer : peers) {
            peer.removeWallet(wallet);
        }        
    }

    public enum FilterRecalculateMode {
        SEND_IF_CHANGED,
        FORCE_SEND_FOR_REFRESH,
        DONT_SEND,
    }

    private final Map<FilterRecalculateMode, ListenableCompletableFuture<BloomFilter>> inFlightRecalculations = Maps.newHashMap();

    /**
     * Recalculates the bloom filter given to peers as well as the timestamp after which full blocks are downloaded
     * (instead of only headers). Note that calls made one after another may return the same future, if the request
     * wasn't processed yet (i.e. calls are deduplicated).
     *
     * @param mode In what situations to send the filter to connected peers.
     * @return a future that completes once the filter has been calculated (note: this does not mean acknowledged by remote peers).
     */
    public ListenableCompletableFuture<BloomFilter> recalculateFastCatchupAndFilter(final FilterRecalculateMode mode) {
        final ListenableCompletableFuture<BloomFilter> future = new ListenableCompletableFuture<>();
        synchronized (inFlightRecalculations) {
            if (inFlightRecalculations.get(mode) != null)
                return inFlightRecalculations.get(mode);
            inFlightRecalculations.put(mode, future);
        }
        Runnable command = new Runnable() {
            @Override
            public void run() {
                try {
                    go();
                } catch (Throwable e) {
                    log.error("Exception when trying to recalculate Bloom filter", e);  // The executor swallows exceptions :(
                }
            }

            public void go() {
                checkState(!lock.isHeldByCurrentThread());
                // Fully verifying mode doesn't use this optimization (it can't as it needs to see all transactions).
                if ((chain != null && chain.shouldVerifyTransactions()) || !vBloomFilteringEnabled)
                    return;
                // We only ever call bloomFilterMerger.calculate on jobQueue, so we cannot be calculating two filters at once.
                FilterMerger.Result result = bloomFilterMerger.calculate(Collections.unmodifiableList(peerFilterProviders /* COW */));
                boolean send;
                switch (mode) {
                    case SEND_IF_CHANGED:
                        send = result.changed;
                        break;
                    case DONT_SEND:
                        send = false;
                        break;
                    case FORCE_SEND_FOR_REFRESH:
                        send = true;
                        break;
                    default:
                        throw new UnsupportedOperationException();
                }
                if (send) {
                    for (Peer peer : peers /* COW */) {
                        // Only query the mempool if this recalculation request is not in order to lower the observed FP
                        // rate. There's no point querying the mempool when doing this because the FP rate can only go
                        // down, and we will have seen all the relevant txns before: it's pointless to ask for them again.
                        peer.setBloomFilter(result.filter, mode != FilterRecalculateMode.FORCE_SEND_FOR_REFRESH);
                    }
                    // Reset the false positive estimate so that we don't send a flood of filter updates
                    // if the estimate temporarily overshoots our threshold.
                    if (chain != null)
                        chain.resetFalsePositiveEstimate();
                }
                // Do this last so that bloomFilter is already set when it gets called.
                setFastCatchupTime(result.earliestKeyTime);
                synchronized (inFlightRecalculations) {
                    inFlightRecalculations.put(mode, null);
                }
                future.complete(result.filter);
            }
        };
        try {
            executor.execute(command);
        } catch (RejectedExecutionException e) {
            // Can happen during shutdown.
        }
        return future;
    }
    
    /**
     * <p>Sets the false positive rate of bloom filters given to peers. The default is {@link #DEFAULT_BLOOM_FILTER_FP_RATE}.</p>
     *
     * <p>Be careful regenerating the bloom filter too often, as it decreases anonymity because remote nodes can
     * compare transactions against both the new and old filters to significantly decrease the false positive rate.</p>
     * 
     * <p>See the docs for {@link BloomFilter#BloomFilter(int, double, int, BloomFilter.BloomUpdate)} for a brief
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
     * Returns the number of currently connected peers. To be informed when this count changes, use
     * {@link PeerConnectedEventListener#onPeerConnected} and {@link PeerDisconnectedEventListener#onPeerDisconnected}.
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
     *         Use {@link Peer#getConnectionOpenFuture()} if you
     *         want a future which completes when the connection is open.
     */
    @Nullable
    public Peer connectTo(InetSocketAddress address) {
        lock.lock();
        try {
            PeerAddress peerAddress = new PeerAddress(address);
            backoffMap.put(peerAddress, new ExponentialBackoff(peerBackoffParams));
            return connectTo(peerAddress, true, vConnectTimeout);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Helper for forcing a connection to localhost. Useful when using regtest mode. Returns the peer object.
     */
    @Nullable
    public Peer connectToLocalHost() {
        lock.lock();
        try {
            final PeerAddress localhost = PeerAddress.localhost(params);
            backoffMap.put(localhost, new ExponentialBackoff(peerBackoffParams));
            return connectTo(localhost, true, vConnectTimeout);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Creates a version message to send, constructs a Peer object and attempts to connect it. Returns the peer on
     * success or null on failure.
     * @param address Remote network address
     * @param incrementMaxConnections Whether to consider this connection an attempt to fill our quota, or something
     *                                explicitly requested.
     * @param connectTimeout timeout for establishing the connection to peers
     * @return Peer or null.
     */
    @Nullable @GuardedBy("lock")
    protected Peer connectTo(PeerAddress address, boolean incrementMaxConnections, Duration connectTimeout) {
        checkState(lock.isHeldByCurrentThread());
        VersionMessage ver = getVersionMessage().duplicate();
        ver.bestHeight = chain == null ? 0 : chain.getBestChainHeight();
        ver.time = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS);
        ver.receivingAddr = address;

        Peer peer = createPeer(address, ver);
        peer.addConnectedEventListener(Threading.SAME_THREAD, startupListener);
        peer.addDisconnectedEventListener(Threading.SAME_THREAD, startupListener);
        peer.setMinProtocolVersion(vMinRequiredProtocolVersion);
        pendingPeers.add(peer);

        try {
            log.info("Attempting connection to {}     ({} connected, {} pending, {} max)", address,
                    peers.size(), pendingPeers.size(), maxConnections);
            CompletableFuture<SocketAddress> future = channels.openConnection(address.toSocketAddress(), peer);
            if (future.isDone())
                Uninterruptibles.getUninterruptibly(future);
        } catch (ExecutionException e) {
            Throwable cause = Throwables.getRootCause(e);
            log.warn("Failed to connect to " + address + ": " + cause.getMessage());
            handlePeerDeath(peer, cause);
            return null;
        }
        peer.setSocketTimeout(connectTimeout);
        // When the channel has connected and version negotiated successfully, handleNewPeer will end up being called on
        // a worker thread.
        if (incrementMaxConnections) {
            // We don't use setMaxConnections here as that would trigger a recursive attempt to establish a new
            // outbound connection.
            maxConnections++;
        }
        return peer;
    }

    /** You can override this to customise the creation of {@link Peer} objects. */
    @GuardedBy("lock")
    protected Peer createPeer(PeerAddress address, VersionMessage ver) {
        return new Peer(params, ver, address, chain, requiredServices, downloadTxDependencyDepth);
    }

    /**
     * Sets the timeout between when a connection attempt to a peer begins and when the version message exchange
     * completes. This does not apply to currently pending peers.
     * @param connectTimeout timeout for estiablishing the connection to peers
     */
    public void setConnectTimeout(Duration connectTimeout) {
        this.vConnectTimeout = connectTimeout;
    }

    /** @deprecated use {@link #setConnectTimeout(Duration)} */
    @Deprecated
    public void setConnectTimeoutMillis(int connectTimeoutMillis) {
        setConnectTimeout(Duration.ofMillis(connectTimeoutMillis));
    }

    /**
     * <p>Start downloading the blockchain.</p>
     *
     * <p>If no peers are currently connected, the download will be started once a peer starts.  If the peer dies,
     * the download will resume with another peer.</p>
     *
     * @param listener a listener for chain download events, may not be null
     */
    public void startBlockChainDownload(BlockchainDownloadEventListener listener) {
        lock.lock();
        try {
            if (downloadPeer != null) {
                if (this.downloadListener != null) {
                    removeDataEventListenerFromPeer(downloadPeer, this.downloadListener);
                }
                if (listener != null) {
                    addDataEventListenerToPeer(Threading.USER_THREAD, downloadPeer, listener);
                }
            }
            this.downloadListener = listener;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Register a data event listener against a single peer (i.e. for blockchain
     * download). Handling registration/deregistration on peer death/add is
     * outside the scope of these methods.
     */
    private static void addDataEventListenerToPeer(Executor executor, Peer peer, BlockchainDownloadEventListener downloadListener) {
        peer.addBlocksDownloadedEventListener(executor, downloadListener);
        peer.addChainDownloadStartedEventListener(executor, downloadListener);
    }

    /**
     * Remove a registered data event listener against a single peer (i.e. for
     * blockchain download). Handling registration/deregistration on peer death/add is
     * outside the scope of these methods.
     */
    private static void removeDataEventListenerFromPeer(Peer peer, BlockchainDownloadEventListener listener) {
        peer.removeBlocksDownloadedEventListener(listener);
        peer.removeChainDownloadStartedEventListener(listener);
    }

    /**
     * Download the blockchain from peers. Convenience that uses a {@link DownloadProgressTracker} for you.<p>
     * 
     * This method waits until the download is complete.  "Complete" is defined as downloading
     * from at least one peer all the blocks that are in that peer's inventory.
     */
    public void downloadBlockChain() {
        DownloadProgressTracker listener = new DownloadProgressTracker();
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
            pendingPeers.remove(peer);
            peers.add(peer);
            newSize = peers.size();
            log.info("{}: New peer      ({} connected, {} pending, {} max)", peer, newSize, pendingPeers.size(), maxConnections);
            // Give the peer a filter that can be used to probabilistically drop transactions that
            // aren't relevant to our wallet. We may still receive some false positives, which is
            // OK because it helps improve wallet privacy. Old nodes will just ignore the message.
            if (bloomFilterMerger.getLastFilter() != null) peer.setBloomFilter(bloomFilterMerger.getLastFilter());
            peer.setDownloadData(false);
            // TODO: The peer should calculate the fast catchup time from the added wallets here.
            for (Wallet wallet : wallets)
                peer.addWallet(wallet);
            if (downloadPeer == null && newSize > maxConnections / 2) {
                Peer newDownloadPeer = selectDownloadPeer(peers);
                if (newDownloadPeer != null) {
                    setDownloadPeer(newDownloadPeer);
                    // Kick off chain download if we aren't already doing it.
                    boolean shouldDownloadChain = downloadListener != null && chain != null;
                    if (shouldDownloadChain) {
                        startBlockChainDownloadFromPeer(downloadPeer);
                    }
                } else {
                    log.info("Not yet setting download peer because there is no clear candidate.");
                }
            }
            // Make sure the peer knows how to upload transactions that are requested from us.
            peer.addBlocksDownloadedEventListener(Threading.SAME_THREAD, peerListener);
            peer.addGetDataEventListener(Threading.SAME_THREAD, peerListener);
            // Discover other peers.
            peer.addAddressEventListener(Threading.SAME_THREAD, peerListener);

            // And set up event listeners for clients. This will allow them to find out about new transactions and blocks.
            for (ListenerRegistration<BlocksDownloadedEventListener> registration : peersBlocksDownloadedEventListeners)
                peer.addBlocksDownloadedEventListener(registration.executor, registration.listener);
            for (ListenerRegistration<ChainDownloadStartedEventListener> registration : peersChainDownloadStartedEventListeners)
                peer.addChainDownloadStartedEventListener(registration.executor, registration.listener);
            for (ListenerRegistration<PeerConnectedEventListener> registration : peerConnectedEventListeners)
                peer.addConnectedEventListener(registration.executor, registration.listener);
            // We intentionally do not add disconnect listeners to peers
            for (ListenerRegistration<GetDataEventListener> registration : peerGetDataEventListeners)
                peer.addGetDataEventListener(registration.executor, registration.listener);
            for (ListenerRegistration<OnTransactionBroadcastListener> registration : peersTransactionBroadastEventListeners)
                peer.addOnTransactionBroadcastListener(registration.executor, registration.listener);
            for (ListenerRegistration<PreMessageReceivedEventListener> registration : peersPreMessageReceivedEventListeners)
                peer.addPreMessageReceivedEventListener(registration.executor, registration.listener);
        } finally {
            lock.unlock();
        }

        final int fNewSize = newSize;
        for (final ListenerRegistration<PeerConnectedEventListener> registration : peerConnectedEventListeners) {
            registration.executor.execute(() -> registration.listener.onPeerConnected(peer, fNewSize));
        }

        // Discovery more peers.
        if (vDiscoverPeersViaP2P)
            peer.sendMessage(new GetAddrMessage());
    }

    @Nullable private volatile ScheduledFuture<?> vPingTask;

    @SuppressWarnings("NonAtomicOperationOnVolatileField")
    private void setupPinging() {
        if (getPingIntervalMsec() <= 0)
            return;  // Disabled.

        vPingTask = executor.scheduleAtFixedRate(() -> {
            try {
                if (getPingIntervalMsec() <= 0) {
                    ScheduledFuture<?> task = vPingTask;
                    if (task != null) {
                        task.cancel(false);
                        vPingTask = null;
                    }
                    return;  // Disabled.
                }
                for (Peer peer : getConnectedPeers()) {
                    peer.sendPing();
                }
            } catch (Throwable e) {
                log.error("Exception in ping loop", e);  // The executor swallows exceptions :(
            }
        }, getPingIntervalMsec(), getPingIntervalMsec(), TimeUnit.MILLISECONDS);
    }

    private void setDownloadPeer(@Nullable Peer peer) {
        lock.lock();
        try {
            if (downloadPeer == peer)
                return;
            if (downloadPeer != null) {
                log.info("Unsetting download peer: {}", downloadPeer);
                if (downloadListener != null) {
                    removeDataEventListenerFromPeer(downloadPeer, downloadListener);
                }
                downloadPeer.setDownloadData(false);
            }
            downloadPeer = peer;
            if (downloadPeer != null) {
                log.info("Setting download peer: {}", downloadPeer);
                if (downloadListener != null) {
                    addDataEventListenerToPeer(Threading.SAME_THREAD, peer, downloadListener);
                }
                downloadPeer.setDownloadData(true);
                if (chain != null)
                    downloadPeer.setFastDownloadParameters(bloomFilterMerger.getLastFilter() != null, fastCatchupTime);
            }
        } finally {
            lock.unlock();
        }
    }

    /** Use "Context.get().getConfidenceTable()" instead */
    @Deprecated @Nullable
    public TxConfidenceTable getMemoryPool() {
        return Context.get().getConfidenceTable();
    }

    /**
     * Tells the {@link PeerGroup} to download only block headers before a certain time and bodies after that. Call this
     * before starting block chain download.
     * Do not use a {@code time > NOW - 1} block, as it will break some block download logic.
     */
    public void setFastCatchupTime(Instant fastCatchupTime) {
        lock.lock();
        try {
            checkState(chain == null || !chain.shouldVerifyTransactions(), () ->
                    "fast catchup is incompatible with fully verifying");
            this.fastCatchupTime = fastCatchupTime;
            if (downloadPeer != null) {
                downloadPeer.setFastDownloadParameters(bloomFilterMerger.getLastFilter() != null, fastCatchupTime);
            }
        } finally {
            lock.unlock();
        }
    }

    /** @deprecated use {@link #setFastCatchupTime(Instant)} */
    @Deprecated
    public void setFastCatchupTimeSecs(long fastCatchupTimeSecs) {
        setFastCatchupTime(Instant.ofEpochSecond(fastCatchupTimeSecs));
    }

    /**
     * Returns the current fast catchup time. The contents of blocks before this time won't be downloaded as they
     * cannot contain any interesting transactions. If you use {@link PeerGroup#addWallet(Wallet)} this just returns
     * the min of the wallets earliest key times.
     * @return a time in seconds since the epoch
     */
    public Instant fastCatchupTime() {
        lock.lock();
        try {
            return fastCatchupTime;
        } finally {
            lock.unlock();
        }
    }

    /** @deprecated use {@link #fastCatchupTime()} */
    @Deprecated
    public long getFastCatchupTimeSecs() {
        return fastCatchupTime().getEpochSecond();
    }

    protected void handlePeerDeath(final Peer peer, @Nullable Throwable exception) {
        // Peer deaths can occur during startup if a connect attempt after peer discovery aborts immediately.
        if (!isRunning()) return;

        int numPeers;
        int numConnectedPeers = 0;
        lock.lock();
        try {
            pendingPeers.remove(peer);
            peers.remove(peer);

            PeerAddress address = peer.getAddress();

            log.info("{}: Peer died      ({} connected, {} pending, {} max)", address, peers.size(), pendingPeers.size(), maxConnections);
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

            if (exception instanceof NoRouteToHostException) {
                if (address.getAddr() instanceof Inet6Address && !ipv6Unreachable) {
                    ipv6Unreachable = true;
                    log.warn("IPv6 peer connect failed due to routing failure, ignoring IPv6 addresses from now on");
                }
            } else {
                backoffMap.get(address).trackFailure();
                // Put back on inactive list
                inactives.offer(address);
            }

            if (numPeers < getMaxConnections()) {
                triggerConnections();
            }
        } finally {
            lock.unlock();
        }

        peer.removeAddressEventListener(peerListener);
        peer.removeBlocksDownloadedEventListener(peerListener);
        peer.removeGetDataEventListener(peerListener);
        for (Wallet wallet : wallets) {
            peer.removeWallet(wallet);
        }

        final int fNumConnectedPeers = numConnectedPeers;

        for (ListenerRegistration<BlocksDownloadedEventListener> registration: peersBlocksDownloadedEventListeners)
            peer.removeBlocksDownloadedEventListener(registration.listener);
        for (ListenerRegistration<ChainDownloadStartedEventListener> registration: peersChainDownloadStartedEventListeners)
            peer.removeChainDownloadStartedEventListener(registration.listener);
        for (ListenerRegistration<GetDataEventListener> registration: peerGetDataEventListeners)
            peer.removeGetDataEventListener(registration.listener);
        for (ListenerRegistration<PreMessageReceivedEventListener> registration: peersPreMessageReceivedEventListeners)
            peer.removePreMessageReceivedEventListener(registration.listener);
        for (ListenerRegistration<OnTransactionBroadcastListener> registration : peersTransactionBroadastEventListeners)
            peer.removeOnTransactionBroadcastListener(registration.listener);
        for (final ListenerRegistration<PeerDisconnectedEventListener> registration : peerDisconnectedEventListeners) {
            registration.executor.execute(() -> registration.listener.onPeerDisconnected(peer, fNumConnectedPeers));
            peer.removeDisconnectedEventListener(registration.listener);
        }
    }

    @GuardedBy("lock") private int stallPeriodSeconds = 10;
    @GuardedBy("lock") private int stallMinSpeedBytesSec = Block.HEADER_SIZE * 10;

    /**
     * Configures the stall speed: the speed at which a peer is considered to be serving us the block chain
     * unacceptably slowly. Once a peer has served us data slower than the given data rate for the given
     * number of seconds, it is considered stalled and will be disconnected, forcing the chain download to continue
     * from a different peer. The defaults are chosen conservatively, but if you are running on a platform that is
     * CPU constrained or on a very slow network e.g. EDGE, the default settings may need adjustment to
     * avoid false stalls.
     *
     * @param periodSecs How many seconds the download speed must be below blocksPerSec, defaults to 10.
     * @param bytesPerSecond Download speed (only blocks/txns count) must be consistently below this for a stall, defaults to the bandwidth required for 10 block headers per second.
     */
    public void setStallThreshold(int periodSecs, int bytesPerSecond) {
        lock.lock();
        try {
            stallPeriodSeconds = periodSecs;
            stallMinSpeedBytesSec = bytesPerSecond;
        } finally {
            lock.unlock();
        }
    }

    private class ChainDownloadSpeedCalculator implements BlocksDownloadedEventListener, Runnable {
        private int blocksInLastSecond, txnsInLastSecond, origTxnsInLastSecond;
        private long bytesInLastSecond;

        // If we take more stalls than this, we assume we're on some kind of terminally slow network and the
        // stall threshold just isn't set properly. We give up on stall disconnects after that.
        private int maxStalls = 3;

        // How many seconds the peer has until we start measuring its speed.
        private int warmupSeconds = -1;

        // Used to calculate a moving average.
        private long[] samples;
        private int cursor;

        private boolean syncDone;

        private final Logger log = LoggerFactory.getLogger(ChainDownloadSpeedCalculator.class);

        @Override
        public synchronized void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft) {
            blocksInLastSecond++;
            bytesInLastSecond += Block.HEADER_SIZE;
            List<Transaction> blockTransactions = block.getTransactions();
            // This whole area of the type hierarchy is a mess.
            int txCount = (blockTransactions != null ? countAndMeasureSize(blockTransactions) : 0) +
                          (filteredBlock != null ? countAndMeasureSize(filteredBlock.getAssociatedTransactions().values()) : 0);
            txnsInLastSecond = txnsInLastSecond + txCount;
            if (filteredBlock != null)
                origTxnsInLastSecond += filteredBlock.getTransactionCount();
        }

        private int countAndMeasureSize(Collection<Transaction> transactions) {
            for (Transaction transaction : transactions)
                bytesInLastSecond += transaction.getMessageSize();
            return transactions.size();
        }

        @Override
        public void run() {
            try {
                calculate();
            } catch (Throwable e) {
                log.error("Error in speed calculator", e);
            }
        }

        private void calculate() {
            int minSpeedBytesPerSec;
            int period;

            lock.lock();
            try {
                minSpeedBytesPerSec = stallMinSpeedBytesSec;
                period = stallPeriodSeconds;
            } finally {
                lock.unlock();
            }

            synchronized (this) {
                if (samples == null || samples.length != period) {
                    samples = new long[period];
                    // *2 because otherwise a single low sample could cause an immediate disconnect which is too harsh.
                    Arrays.fill(samples, minSpeedBytesPerSec * 2);
                    warmupSeconds = 15;
                }

                int chainHeight = chain != null ? chain.getBestChainHeight() : -1;
                int mostCommonChainHeight = getMostCommonChainHeight();
                if (!syncDone && mostCommonChainHeight > 0 && chainHeight >= mostCommonChainHeight) {
                    log.info("End of sync detected at height {}.", chainHeight);
                    syncDone = true;
                }

                if (!syncDone) {
                    // Calculate the moving average.
                    samples[cursor++] = bytesInLastSecond;
                    if (cursor == samples.length) cursor = 0;
                    long sampleSum = 0;
                    for (long sample : samples) sampleSum += sample;
                    final float average = (float) sampleSum / samples.length;

                    String statsString = String.format(Locale.US,
                            "%d blocks/sec, %d tx/sec, %d pre-filtered tx/sec, avg/last %.2f/%.2f kilobytes per sec, chain/common height %d/%d",
                            blocksInLastSecond, txnsInLastSecond, origTxnsInLastSecond, average / 1024.0,
                            bytesInLastSecond / 1024.0, chainHeight, mostCommonChainHeight);
                    String thresholdString = String.format(Locale.US, "(threshold <%.2f KB/sec for %d seconds)",
                            minSpeedBytesPerSec / 1024.0, samples.length);
                    if (maxStalls <= 0) {
                        log.info(statsString + ", stall disabled " + thresholdString);
                    } else if (warmupSeconds > 0) {
                        warmupSeconds--;
                        if (bytesInLastSecond > 0)
                            log.info(statsString
                                    + String.format(Locale.US, " (warming up %d more seconds)", warmupSeconds));
                    } else if (average < minSpeedBytesPerSec) {
                        log.info(statsString + ", STALLED " + thresholdString);
                        maxStalls--;
                        if (maxStalls == 0) {
                            // We could consider starting to drop the Bloom filtering FP rate at this point, because
                            // we tried a bunch of peers and no matter what we don't seem to be able to go any faster.
                            // This implies we're bandwidth bottlenecked and might want to start using bandwidth
                            // more effectively. Of course if there's a MITM that is deliberately throttling us,
                            // this is a good way to make us take away all the FPs from our Bloom filters ... but
                            // as they don't give us a whole lot of privacy either way that's not inherently a big
                            // deal.
                            log.warn("This network seems to be slower than the requested stall threshold - won't do stall disconnects any more.");
                        } else {
                            Peer peer = getDownloadPeer();
                            log.warn(String.format(Locale.US,
                                    "Chain download stalled: received %.2f KB/sec for %d seconds, require average of %.2f KB/sec, disconnecting %s, %d stalls left",
                                    average / 1024.0, samples.length, minSpeedBytesPerSec / 1024.0, peer, maxStalls));
                            peer.close();
                            // Reset the sample buffer and give the next peer time to get going.
                            samples = null;
                            warmupSeconds = period;
                        }
                    } else {
                        log.info(statsString + ", not stalled " + thresholdString);
                    }
                }
                blocksInLastSecond = 0;
                txnsInLastSecond = 0;
                origTxnsInLastSecond = 0;
                bytesInLastSecond = 0;
            }
        }
    }
    @Nullable private ChainDownloadSpeedCalculator chainDownloadSpeedCalculator;

    @VisibleForTesting
    void startBlockChainDownloadFromPeer(Peer peer) {
        lock.lock();
        try {
            setDownloadPeer(peer);

            if (chainDownloadSpeedCalculator == null) {
                // Every second, run the calculator which will log how fast we are downloading the chain.
                chainDownloadSpeedCalculator = new ChainDownloadSpeedCalculator();
                executor.scheduleAtFixedRate(chainDownloadSpeedCalculator, 1, 1, TimeUnit.SECONDS);
            }
            peer.addBlocksDownloadedEventListener(Threading.SAME_THREAD, chainDownloadSpeedCalculator);

            // startBlockChainDownload will setDownloadData(true) on itself automatically.
            peer.startBlockChainDownload();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a future that is triggered when the number of connected peers is equal to the given number of
     * peers. By using this with {@link PeerGroup#getMaxConnections()} you can wait until the
     * network is fully online. To block immediately, just call get() on the result. Just calls
     * {@link #waitForPeersOfVersion(int, long)} with zero as the protocol version.
     *
     * @param numPeers How many peers to wait for.
     * @return a future that will be triggered when the number of connected peers is greater than or equals numPeers
     */
    public ListenableCompletableFuture<List<Peer>> waitForPeers(final int numPeers) {
        return waitForPeersOfVersion(numPeers, 0);
    }

    /**
     * Returns a future that is triggered when there are at least the requested number of connected peers that support
     * the given protocol version or higher. To block immediately, just call get() on the result.
     *
     * @param numPeers How many peers to wait for.
     * @param protocolVersion The protocol version the awaited peers must implement (or better).
     * @return a future that will be triggered when the number of connected peers implementing protocolVersion or higher is greater than or equals numPeers
     */
    public ListenableCompletableFuture<List<Peer>> waitForPeersOfVersion(final int numPeers, final long protocolVersion) {
        List<Peer> foundPeers = findPeersOfAtLeastVersion(protocolVersion);
        if (foundPeers.size() >= numPeers) {
            ListenableCompletableFuture<List<Peer>> f = new ListenableCompletableFuture<>();
            f.complete(foundPeers);
            return f;
        }
        final ListenableCompletableFuture<List<Peer>> future = new ListenableCompletableFuture<List<Peer>>();
        addConnectedEventListener(new PeerConnectedEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                final List<Peer> peers = findPeersOfAtLeastVersion(protocolVersion);
                if (peers.size() >= numPeers) {
                    future.complete(peers);
                    removeConnectedEventListener(this);
                }
            }
        });
        return future;
    }

    /**
     * Returns an array list of peers that implement the given protocol version or better.
     */
    public List<Peer> findPeersOfAtLeastVersion(long protocolVersion) {
        lock.lock();
        try {
            ArrayList<Peer> results = new ArrayList<>(peers.size());
            for (Peer peer : peers)
                if (peer.getPeerVersionMessage().clientVersion >= protocolVersion)
                    results.add(peer);
            return results;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a future that is triggered when there are at least the requested number of connected peers that support
     * the given protocol version or higher. To block immediately, just call get() on the result.
     *
     * @param numPeers How many peers to wait for.
     * @param mask An integer representing a bit mask that will be ANDed with the peers advertised service masks.
     * @return a future that will be triggered when the number of connected peers implementing protocolVersion or higher is greater than or equals numPeers
     */
    public ListenableCompletableFuture<List<Peer>> waitForPeersWithServiceMask(final int numPeers, final int mask) {
        lock.lock();
        try {
            List<Peer> foundPeers = findPeersWithServiceMask(mask);
            if (foundPeers.size() >= numPeers) {
                ListenableCompletableFuture<List<Peer>> f = new ListenableCompletableFuture<>();
                f.complete(foundPeers);
                return f;
            }
            final ListenableCompletableFuture<List<Peer>> future = new ListenableCompletableFuture<>();
            addConnectedEventListener(new PeerConnectedEventListener() {
                @Override
                public void onPeerConnected(Peer peer, int peerCount) {
                    final List<Peer> peers = findPeersWithServiceMask(mask);
                    if (peers.size() >= numPeers) {
                        future.complete(peers);
                        removeConnectedEventListener(this);
                    }
                }
            });
            return future;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns an array list of peers that match the requested service bit mask.
     */
    public List<Peer> findPeersWithServiceMask(int mask) {
        lock.lock();
        try {
            ArrayList<Peer> results = new ArrayList<>(peers.size());
            for (Peer peer : peers)
                if (peer.getPeerVersionMessage().localServices.has(mask))
                    results.add(peer);
            return results;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the number of connections that are required before transactions will be broadcast. If there aren't
     * enough, {@link PeerGroup#broadcastTransaction(Transaction)} will wait until the minimum number is reached so
     * propagation across the network can be observed. If no value has been set using
     * {@link PeerGroup#setMinBroadcastConnections(int)} a default of 80% of whatever
     * {@link PeerGroup#getMaxConnections()} returns is used.
     */
    public int getMinBroadcastConnections() {
        lock.lock();
        try {
            if (minBroadcastConnections == 0) {
                int max = getMaxConnections();
                if (max <= 1)
                    return max;
                else
                    return (int) Math.round(getMaxConnections() * 0.8);
            }
            return minBroadcastConnections;
        } finally {
            lock.unlock();
        }
    }

    /**
     * See {@link PeerGroup#getMinBroadcastConnections()}.
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
     * Calls {@link PeerGroup#broadcastTransaction(Transaction, int, boolean)} with getMinBroadcastConnections() as
     * the number of connections to wait for before commencing broadcast. Also, if the transaction has no broadcast
     * confirmations yet the peers will be dropped after the transaction has been sent.
     */
    @Override
    public TransactionBroadcast broadcastTransaction(final Transaction tx) {
        return broadcastTransaction(tx, Math.max(1, getMinBroadcastConnections()), true);
    }

    /**
     * <p>Given a transaction, sends it un-announced to one peer and then waits for it to be received back from other
     * peers. Once all connected peers have announced the transaction, the future available via the
     * {@link TransactionBroadcast#awaitRelayed()} ()} method will be completed. If anything goes
     * wrong the exception will be thrown when get() is called, or you can receive it via a callback on the
     * {@link ListenableCompletableFuture}. This method returns immediately, so if you want it to block just call get() on the
     * result.</p>
     *
     * <p>Optionally, peers will be dropped after they have been used for broadcasting the transaction and they have
     * no broadcast confirmations yet.</p>
     *
     * <p>Note that if the PeerGroup is limited to only one connection (discovery is not activated) then the future
     * will complete as soon as the transaction was successfully written to that peer.</p>
     *
     * <p>The transaction won't be sent until there are at least minConnections active connections available.
     * A good choice for proportion would be between 0.5 and 0.8 but if you want faster transmission during initial
     * bringup of the peer group you can lower it.</p>
     *
     * <p>The returned {@link TransactionBroadcast} object can be used to get progress feedback,
     * which is calculated by watching the transaction propagate across the network and be announced by peers.</p>
     */
    public TransactionBroadcast broadcastTransaction(final Transaction tx, final int minConnections,
                                                     final boolean dropPeersAfterBroadcast) {
        // If we don't have a record of where this tx came from already, set it to be ourselves so Peer doesn't end up
        // redownloading it from the network redundantly.
        if (tx.getConfidence().getSource().equals(TransactionConfidence.Source.UNKNOWN)) {
            log.info("Transaction source unknown, setting to SELF: {}", tx.getTxId());
            tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        }
        final TransactionBroadcast broadcast = new TransactionBroadcast(this, tx);
        broadcast.setMinConnections(minConnections);
        broadcast.setDropPeersAfterBroadcast(dropPeersAfterBroadcast && tx.getConfidence().numBroadcastPeers() == 0);
        // Send the TX to the wallet once we have a successful broadcast.
        broadcast.awaitRelayed().whenComplete((bcast, throwable) -> {
            if (bcast != null) {
                runningBroadcasts.remove(bcast);
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
                        wallet.receivePending(bcast.transaction(), null);
                    } catch (VerificationException e) {
                        throw new RuntimeException(e);   // Cannot fail to verify a tx we created ourselves.
                    }
                }
            } else {
                // This can happen if we get a reject message from a peer.
                runningBroadcasts.remove(bcast);
            }
        });
        // Keep a reference to the TransactionBroadcast object. This is important because otherwise, the entire tree
        // of objects we just created would become garbage if the user doesn't hold on to the returned future, and
        // eventually be collected. This in turn could result in the transaction not being committed to the wallet
        // at all.
        runningBroadcasts.add(broadcast);
        broadcast.broadcastOnly();
        return broadcast;
    }

    /**
     * Returns the period between pings for an individual peer. Setting this lower means more accurate and timely ping
     * times are available via {@link Peer#lastPingInterval()} but it increases load on the
     * remote node. It defaults to {@link PeerGroup#DEFAULT_PING_INTERVAL_MSEC}.
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
     * times are available via {@link Peer#lastPingInterval()} but it increases load on the
     * remote node. It defaults to {@link PeerGroup#DEFAULT_PING_INTERVAL_MSEC}.
     * Setting the value to be smaller or equals 0 disables pinging entirely, although you can still request one yourself
     * using {@link Peer#sendPing()}.
     */
    public void setPingIntervalMsec(long pingIntervalMsec) {
        lock.lock();
        try {
            this.pingIntervalMsec = pingIntervalMsec;
            ScheduledFuture<?> task = vPingTask;
            if (task != null)
                task.cancel(false);
            setupPinging();
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
     * Returns our peers most commonly reported chain height.
     * If the most common heights are tied, or no peers are connected, returns {@code 0}.
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
     * If the most common heights are tied, or no peers are connected, returns {@code 0}.
     */
    public static int getMostCommonChainHeight(final List<Peer> peers) {
        if (peers.isEmpty())
            return 0;
        List<Integer> heights = new ArrayList<>(peers.size());
        for (Peer peer : peers) heights.add((int) peer.getBestHeight());
        return maxOfMostFreq(heights);
    }

    private static class Pair implements Comparable<Pair> {
        final int item;
        int count = 0;
        public Pair(int item) { this.item = item; }
        // note that in this implementation compareTo() is not consistent with equals()
        @Override public int compareTo(Pair o) { return -Integer.compare(count, o.count); }
    }

    static int maxOfMostFreq(List<Integer> items) {
        if (items.isEmpty())
            return 0;
        // This would be much easier in a functional language (or in Java 8).
        items = Ordering.natural().reverse().sortedCopy(items);
        LinkedList<Pair> pairs = new LinkedList<>();
        pairs.add(new Pair(items.get(0)));
        for (int item : items) {
            Pair pair = pairs.getLast();
            if (pair.item != item)
                pairs.add((pair = new Pair(item)));
            pair.count++;
        }
        // pairs now contains a uniquified list of the sorted inputs, with counts for how often that item appeared.
        // Now sort by how frequently they occur, and pick the most frequent. If the first place is tied between two,
        // don't pick any.
        Collections.sort(pairs);
        final Pair firstPair = pairs.get(0);
        if (pairs.size() == 1)
            return firstPair.item;
        final Pair secondPair = pairs.get(1);
        if (firstPair.count > secondPair.count)
            return firstPair.item;
        checkState(firstPair.count == secondPair.count);
        return 0;
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
        //  - Randomly, to try and spread the load.
        if (peers.isEmpty())
            return null;

        int mostCommonChainHeight = getMostCommonChainHeight(peers);
        // Make sure we don't select a peer if there is no consensus about block height.
        if (mostCommonChainHeight == 0)
            return null;

        // Only select peers that announce the minimum protocol and services and that we think is fully synchronized.
        List<Peer> candidates = new LinkedList<>();
        int highestPriority = Integer.MIN_VALUE;
        final int MINIMUM_VERSION = ProtocolVersion.WITNESS_VERSION.intValue();
        for (Peer peer : peers) {
            final VersionMessage versionMessage = peer.getPeerVersionMessage();
            if (versionMessage.clientVersion < MINIMUM_VERSION)
                continue;
            if (!versionMessage.services().has(Services.NODE_NETWORK))
                continue;
            if (!versionMessage.services().has(Services.NODE_WITNESS))
                continue;
            final long peerHeight = peer.getBestHeight();
            if (peerHeight < mostCommonChainHeight || peerHeight > mostCommonChainHeight + 1)
                continue;
            candidates.add(peer);
            highestPriority = Math.max(highestPriority, getPriority(peer.peerAddress));
        }
        if (candidates.isEmpty())
            return null;

        // If there is a difference in priority, consider only the highest.
        for (Iterator<Peer> i = candidates.iterator(); i.hasNext(); ) {
            Peer peer = i.next();
            if (getPriority(peer.peerAddress) < highestPriority)
                i.remove();
        }

        // Random poll.
        int index = (int) (Math.random() * candidates.size());
        return candidates.get(index);
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

    /**
     * Returns the maximum number of {@link Peer}s to discover. This maximum is checked after
     * each {@link PeerDiscovery} so this max number can be surpassed.
     * @return the maximum number of peers to discover
     */
    public int getMaxPeersToDiscoverCount() {
        return vMaxPeersToDiscoverCount;
    }

    /**
     * Sets the maximum number of {@link Peer}s to discover. This maximum is checked after
     * each {@link PeerDiscovery} so this max number can be surpassed.
     * @param maxPeersToDiscoverCount the maximum number of peers to discover
     */
    public void setMaxPeersToDiscoverCount(int maxPeersToDiscoverCount) {
        this.vMaxPeersToDiscoverCount = maxPeersToDiscoverCount;
    }

    /** See {@link #setUseLocalhostPeerWhenPossible(boolean)} */
    public boolean getUseLocalhostPeerWhenPossible() {
        lock.lock();
        try {
            return useLocalhostPeerWhenPossible;
        } finally {
            lock.unlock();
        }
    }

    /**
     * When true (the default), PeerGroup will attempt to connect to a Bitcoin node running on localhost before
     * attempting to use the P2P network. If successful, only localhost will be used. This makes for a simple
     * and easy way for a user to upgrade a bitcoinj based app running in SPV mode to fully validating security.
     */
    public void setUseLocalhostPeerWhenPossible(boolean useLocalhostPeerWhenPossible) {
        lock.lock();
        try {
            this.useLocalhostPeerWhenPossible = useLocalhostPeerWhenPossible;
        } finally {
            lock.unlock();
        }
    }

    public boolean isRunning() {
        return vRunning;
    }

    /**
     * Can be used to disable Bloom filtering entirely, even in SPV mode. You are very unlikely to need this, it is
     * an optimisation for rare cases when full validation is not required but it's still more efficient to download
     * full blocks than filtered blocks.
     */
    public void setBloomFilteringEnabled(boolean bloomFilteringEnabled) {
        this.vBloomFilteringEnabled = bloomFilteringEnabled;
    }

    /** Returns whether the Bloom filtering protocol optimisation is in use: defaults to true. */
    public boolean isBloomFilteringEnabled() {
        return vBloomFilteringEnabled;
    }
}
