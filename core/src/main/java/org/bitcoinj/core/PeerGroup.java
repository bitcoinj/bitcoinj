/**
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

import com.google.common.annotations.*;
import com.google.common.base.*;
import com.google.common.collect.*;
import com.google.common.net.*;
import com.google.common.primitives.*;
import com.google.common.util.concurrent.*;
import com.squareup.okhttp.*;
import com.subgraph.orchid.*;
import net.jcip.annotations.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.net.*;
import org.bitcoinj.net.discovery.*;
import org.bitcoinj.script.*;
import org.bitcoinj.utils.*;
import org.bitcoinj.utils.Threading;
import org.slf4j.*;

import javax.annotation.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;

import static com.google.common.base.Preconditions.*;

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

    // All members in this class should be marked with final, volatile, @GuardedBy or a mix as appropriate to define
    // their thread safety semantics. Volatile requires a Hungarian-style v prefix.

    /**
     * The default number of connections to the p2p network the library will try to build. This is set to 12 empirically.
     * It used to be 4, but because we divide the connection pool in two for broadcasting transactions, that meant we
     * were only sending transactions to two peers and sometimes this wasn't reliable enough: transactions wouldn't
     * get through.
     */
    public static final int DEFAULT_CONNECTIONS = 12;
    private static final int TOR_TIMEOUT_SECONDS = 60;
    private volatile int vMaxPeersToDiscoverCount = 100;
    private static final long DEFAULT_PEER_DISCOVERY_TIMEOUT_MILLIS = 5000;
    private volatile long vPeerDiscoveryTimeoutMillis = DEFAULT_PEER_DISCOVERY_TIMEOUT_MILLIS;

    protected final ReentrantLock lock = Threading.lock("peergroup");

    private final NetworkParameters params;
    @Nullable private final AbstractBlockChain chain;

    // This executor is used to queue up jobs: it's used when we don't want to use locks for mutual exclusion,
    // typically because the job might call in to user provided code that needs/wants the freedom to use the API
    // however it wants, or because a job needs to be ordered relative to other jobs like that.
    protected final ListeningScheduledExecutorService executor;

    // Whether the peer group is currently running. Once shut down it cannot be restarted.
    private volatile boolean vRunning;
    // Whether the peer group has been started or not. An unstarted PG does not try to access the network.
    private volatile boolean vUsedUp;

    // Addresses to try to connect to, excluding active peers.
    @GuardedBy("lock") private final PriorityQueue<PeerAddress> inactives;
    @GuardedBy("lock") private final Map<PeerAddress, ExponentialBackoff> backoffMap;

    // Currently active peers. This is an ordered list rather than a set to make unit tests predictable.
    private final CopyOnWriteArrayList<Peer> peers;
    // Currently connecting peers.
    private final CopyOnWriteArrayList<Peer> pendingPeers;
    private final ClientConnectionManager channels;
    @Nullable private final TorClient torClient;

    // The peer that has been selected for the purposes of downloading announced data.
    @GuardedBy("lock") private Peer downloadPeer;
    // Callback for events related to chain download.
    @Nullable @GuardedBy("lock") private PeerEventListener downloadListener;
    // Callbacks for events related to peer connection/disconnection
    private final CopyOnWriteArrayList<ListenerRegistration<PeerEventListener>> peerEventListeners;
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private final CopyOnWriteArraySet<PeerDiscovery> peerDiscoverers;
    // The version message to use for new connections.
    @GuardedBy("lock") private VersionMessage versionMessage;
    // Switch for enabling download of pending transaction dependencies.
    @GuardedBy("lock") private boolean downloadTxDependencies;
    // How many connections we want to have open at the current time. If we lose connections, we'll try opening more
    // until we reach this count.
    @GuardedBy("lock") private int maxConnections;
    // Minimum protocol version we will allow ourselves to connect to: require Bloom filtering.
    private volatile int vMinRequiredProtocolVersion = FilteredBlock.MIN_PROTOCOL_VERSION;

    /** How many milliseconds to wait after receiving a pong before sending another ping. */
    public static final long DEFAULT_PING_INTERVAL_MSEC = 2000;
    @GuardedBy("lock") private long pingIntervalMsec = DEFAULT_PING_INTERVAL_MSEC;

    @GuardedBy("lock") private boolean useLocalhostPeerWhenPossible = true;
    @GuardedBy("lock") private boolean ipv6Unreachable = false;

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
        public void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft) {
            if (chain == null) return;
            final double rate = chain.getFalsePositiveRate();
            final double target = bloomFilterMerger.getBloomFilterFPRate() * MAX_FP_RATE_INCREASE;
            if (rate > target) {
                // TODO: Avoid hitting this path if the remote peer didn't acknowledge applying a new filter yet.
                if (log.isDebugEnabled())
                    log.debug("Force update Bloom filter due to high false positive rate ({} vs {})", rate, target);
                recalculateFastCatchupAndFilter(FilterRecalculateMode.FORCE_SEND_FOR_REFRESH);
            }
        }
    };

    private int minBroadcastConnections = 0;
    private final AbstractWalletEventListener walletEventListener = new AbstractWalletEventListener() {
        @Override public void onScriptsChanged(Wallet wallet, List<Script> scripts, boolean isAddingScripts) {
            recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
        }

        @Override public void onKeysAdded(List<ECKey> keys) {
            recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
        }

        @Override
        public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
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
                        recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
                    else
                        recalculateFastCatchupAndFilter(FilterRecalculateMode.DONT_SEND);
                    return;
                }
            }
        }
    };

    // Exponential backoff for peers starts at 1 second and maxes at 10 minutes.
    private final ExponentialBackoff.Params peerBackoffParams = new ExponentialBackoff.Params(1000, 1.5f, 10 * 60 * 1000);
    // Tracks failures globally in case of a network failure.
    @GuardedBy("lock") private ExponentialBackoff groupBackoff = new ExponentialBackoff(new ExponentialBackoff.Params(1000, 1.5f, 10 * 1000));

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
            handlePeerDeath(peer, null);
        }
    }

    private final PeerEventListener startupListener = new PeerStartupListener();

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
    public static final int DEFAULT_CONNECT_TIMEOUT_MILLIS = 5000;
    private volatile int vConnectTimeoutMillis = DEFAULT_CONNECT_TIMEOUT_MILLIS;
    
    /** Whether bloom filter support is enabled when using a non FullPrunedBlockchain*/
    private volatile boolean vBloomFilteringEnabled = true;

    /** See {@link #PeerGroup(Context)} */
    public PeerGroup(NetworkParameters params) {
        this(params, null);
    }

    /**
     * Creates a PeerGroup with the given context. No chain is provided so this node will report its chain height
     * as zero to other peers. This constructor is useful if you just want to explore the network but aren't interested
     * in downloading block data.
     */
    public PeerGroup(Context context) {
        this(context, null);
    }

    /** See {@link #PeerGroup(Context, AbstractBlockChain)} */
    public PeerGroup(NetworkParameters params, @Nullable AbstractBlockChain chain) {
        this(Context.getOrCreate(params), chain, new NioClientManager());
    }

    /**
     * Creates a PeerGroup for the given context and chain. Blocks will be passed to the chain as they are broadcast
     * and downloaded. This is probably the constructor you want to use.
     */
    public PeerGroup(Context context, @Nullable AbstractBlockChain chain) {
        this(context, chain, new NioClientManager());
    }

    /** See {@link #newWithTor(Context, AbstractBlockChain, TorClient)} */
    public static PeerGroup newWithTor(NetworkParameters params, @Nullable AbstractBlockChain chain, TorClient torClient) throws TimeoutException {
        return newWithTor(Context.getOrCreate(params), chain, torClient);
    }

    /**
     * <p>Creates a PeerGroup that accesses the network via the Tor network. The provided TorClient is used so you can
     * preconfigure it beforehand. It should not have been already started. You can just use "new TorClient()" if
     * you don't have any particular configuration requirements.</p>
     *
     * <p>Peer discovery is automatically configured to use DNS seeds resolved via a random selection of exit nodes.
     * If running on the Oracle JDK the unlimited strength jurisdiction checks will also be overridden,
     * as they no longer apply anyway and can cause startup failures due to the requirement for AES-256.</p>
     *
     * <p>The user does not need any additional software for this: it's all pure Java. As of April 2014 <b>this mode
     * is experimental</b>.</p>
     *
     * @throws TimeoutException if Tor fails to start within 20 seconds.
     */
    public static PeerGroup newWithTor(Context context, @Nullable AbstractBlockChain chain, TorClient torClient) throws TimeoutException {
        return newWithTor(context, chain, torClient, true);
    }

    /**
     * <p>Creates a PeerGroup that accesses the network via the Tor network. The provided TorClient is used so you can
     * preconfigure it beforehand. It should not have been already started. You can just use "new TorClient()" if
     * you don't have any particular configuration requirements.</p>
     *
     * <p>If running on the Oracle JDK the unlimited strength jurisdiction checks will also be overridden,
     * as they no longer apply anyway and can cause startup failures due to the requirement for AES-256.</p>
     *
     * <p>The user does not need any additional software for this: it's all pure Java. As of April 2014 <b>this mode
     * is experimental</b>.</p>
     *
     * @params doDiscovery if true, DNS or HTTP peer discovery will be performed via Tor: this is almost always what you want.
     * @throws java.util.concurrent.TimeoutException if Tor fails to start within 20 seconds.
     */
    public static PeerGroup newWithTor(Context context, @Nullable AbstractBlockChain chain, TorClient torClient, boolean doDiscovery) throws TimeoutException {
        checkNotNull(torClient);
        DRMWorkaround.maybeDisableExportControls();
        BlockingClientManager manager = new BlockingClientManager(torClient.getSocketFactory());
        final int CONNECT_TIMEOUT_MSEC = TOR_TIMEOUT_SECONDS * 1000;
        manager.setConnectTimeoutMillis(CONNECT_TIMEOUT_MSEC);
        PeerGroup result = new PeerGroup(context, chain, manager, torClient);
        result.setConnectTimeoutMillis(CONNECT_TIMEOUT_MSEC);

        if (doDiscovery) {
            NetworkParameters params = context.getParams();
            HttpDiscovery.Details[] httpSeeds = params.getHttpSeeds();
            if (httpSeeds.length > 0) {
                // Use HTTP discovery when Tor is active and there is a Cartographer seed, for a much needed speed boost.
                OkHttpClient httpClient = new OkHttpClient();
                httpClient.setSocketFactory(torClient.getSocketFactory());
                List<PeerDiscovery> discoveries = Lists.newArrayList();
                for (HttpDiscovery.Details httpSeed : httpSeeds)
                    discoveries.add(new HttpDiscovery(params, httpSeed, httpClient));
                result.addPeerDiscovery(new MultiplexingDiscovery(params, discoveries));
            } else {
                result.addPeerDiscovery(new TorDiscovery(params, torClient));
            }
        }
        return result;
    }

    /** See {@link #PeerGroup(Context, AbstractBlockChain, ClientConnectionManager)} */
    public PeerGroup(NetworkParameters params, @Nullable AbstractBlockChain chain, ClientConnectionManager connectionManager) {
        this(Context.getOrCreate(params), chain, connectionManager, null);
    }

    /**
     * Creates a new PeerGroup allowing you to specify the {@link ClientConnectionManager} which is used to create new
     * connections and keep track of existing ones.
     */
    public PeerGroup(Context context, @Nullable AbstractBlockChain chain, ClientConnectionManager connectionManager) {
        this(context, chain, connectionManager, null);
    }

    /**
     * Creates a new PeerGroup allowing you to specify the {@link ClientConnectionManager} which is used to create new
     * connections and keep track of existing ones.
     */
    private PeerGroup(Context context, @Nullable AbstractBlockChain chain, ClientConnectionManager connectionManager, @Nullable TorClient torClient) {
        checkNotNull(context);
        this.params = context.getParams();
        this.chain = chain;
        fastCatchupTimeSecs = params.getGenesisBlock().getTimeSeconds();
        wallets = new CopyOnWriteArrayList<Wallet>();
        peerFilterProviders = new CopyOnWriteArrayList<PeerFilterProvider>();
        this.torClient = torClient;

        executor = createPrivateExecutor();

        // This default sentinel value will be overridden by one of two actions:
        //   - adding a peer discovery source sets it to the default
        //   - using connectTo() will increment it by one
        maxConnections = 0;

        int height = chain == null ? 0 : chain.getBestChainHeight();
        versionMessage = new VersionMessage(params, height);
        // We never request that the remote node wait for a bloom filter yet, as we have no wallets
        versionMessage.relayTxesBeforeFilter = true;

        downloadTxDependencies = true;

        inactives = new PriorityQueue<PeerAddress>(1, new Comparator<PeerAddress>() {
            @SuppressWarnings("FieldAccessNotGuarded")   // only called when inactives is accessed, and lock is held then.
            @Override
            public int compare(PeerAddress a, PeerAddress b) {
                checkState(lock.isHeldByCurrentThread());
                int result = backoffMap.get(a).compareTo(backoffMap.get(b));
                // Sort by port if otherwise equals - for testing
                if (result == 0)
                    result = Ints.compare(a.getPort(), b.getPort());
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

    private CountDownLatch executorStartupLatch = new CountDownLatch(1);

    protected ListeningScheduledExecutorService createPrivateExecutor() {
        ListeningScheduledExecutorService result = MoreExecutors.listeningDecorator(
                new ScheduledThreadPoolExecutor(1, new ContextPropagatingThreadFactory("PeerGroup Thread"))
        );
        // Hack: jam the executor so jobs just queue up until the user calls start() on us. For example, adding a wallet
        // results in a bloom filter recalc being queued, but we don't want to do that until we're actually started.
        result.execute(new Runnable() {
            @Override
            public void run() {
                Uninterruptibles.awaitUninterruptibly(executorStartupLatch);
            }
        });
        return result;
    }

    /**
     * This is how many milliseconds we wait for peer discoveries to return their results.
     */
    public void setPeerDiscoveryTimeoutMillis(long peerDiscoveryTimeoutMillis) {
        this.vPeerDiscoveryTimeoutMillis = peerDiscoveryTimeoutMillis;
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
     * Switch for enabling download of pending transaction dependencies. A change of value only takes effect for newly
     * connected peers.
     */
    public void setDownloadTxDependencies(boolean downloadTxDependencies) {
        lock.lock();
        try {
            this.downloadTxDependencies = downloadTxDependencies;
        } finally {
            lock.unlock();
        }
    }

    private Runnable triggerConnectionsJob = new Runnable() {
        private boolean firstRun = true;

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
            long now = Utils.currentTimeMillis();
            lock.lock();
            try {
                // First run: try and use a local node if there is one, for the additional security it can provide.
                // But, not on Android as there are none for this platform: it could only be a malicious app trying
                // to hijack our traffic.
                if (!Utils.isAndroidRuntime() && useLocalhostPeerWhenPossible && maybeCheckForLocalhostPeer() && firstRun) {
                    log.info("Localhost peer detected, trying to use it instead of P2P discovery");
                    maxConnections = 0;
                    connectToLocalHost();
                    return;
                }

                boolean havePeerWeCanTry = !inactives.isEmpty() && backoffMap.get(inactives.peek()).getRetryTime() <= now;
                doDiscovery = !havePeerWeCanTry;
            } finally {
                firstRun = false;
                lock.unlock();
            }

            // Don't hold the lock across discovery as this process can be very slow.
            boolean discoverySuccess = false;
            if (doDiscovery) {
                try {
                    discoverySuccess = discoverPeers() > 0;
                } catch (PeerDiscoveryException e) {
                    log.error("Peer discovery failure", e);
                }
            }

            long retryTime;
            PeerAddress addrToTry;
            lock.lock();
            try {
                if (doDiscovery) {
                    if (discoverySuccess) {
                        groupBackoff.trackSuccess();
                    } else {
                        groupBackoff.trackFailure();
                    }
                }
                // Inactives is sorted by backoffMap time.
                if (inactives.isEmpty()) {
                    if (countConnectedAndPendingPeers() < getMaxConnections()) {
                        log.info("Peer discovery didn't provide us any more peers, will try again later.");
                        executor.schedule(this, groupBackoff.getRetryTime() - now, TimeUnit.MILLISECONDS);
                    } else {
                        // We have enough peers and discovery provided no more, so just settle down. Most likely we
                        // were given a fixed set of addresses in some test scenario.
                    }
                    return;
                } else {
                    do {
                        addrToTry = inactives.poll();
                    } while (ipv6Unreachable && addrToTry.getAddr() instanceof Inet6Address);
                    retryTime = backoffMap.get(addrToTry).getRetryTime();
                }
                retryTime = Math.max(retryTime, groupBackoff.getRetryTime());
                if (retryTime > now) {
                    long delay = retryTime - now;
                    log.info("Waiting {} msec before next connect attempt {}", delay, addrToTry == null ? "" : "to " + addrToTry);
                    inactives.add(addrToTry);
                    executor.schedule(this, delay, TimeUnit.MILLISECONDS);
                    return;
                }
                connectTo(addrToTry, false, vConnectTimeoutMillis);
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
            LinkedList<Message> transactions = new LinkedList<Message>();
            LinkedList<InventoryItem> items = new LinkedList<InventoryItem>(m.getItems());
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
        for (Peer peer : getConnectedPeers())
            peer.addEventListener(listener, executor);
        for (Peer peer: getPendingPeers())
            peer.addEventListener(listener, executor);
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
        boolean result = ListenerRegistration.removeFromList(listener, peerEventListeners);
        for (Peer peer : getConnectedPeers())
            peer.removeEventListener(listener);
        for (Peer peer : getPendingPeers())
            peer.removeEventListener(listener);
        return result;
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
        lock.lock();
        try {
            // Deduplicate
            if (backoffMap.containsKey(peerAddress))
                return;
            backoffMap.put(peerAddress, new ExponentialBackoff(peerBackoffParams));
            inactives.offer(peerAddress);
        } finally {
            lock.unlock();
        }
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

    /** Returns number of discovered peers. */
    protected int discoverPeers() throws PeerDiscoveryException {
        // Don't hold the lock whilst doing peer discovery: it can take a long time and cause high API latency.
        checkState(!lock.isHeldByCurrentThread());
        int maxPeersToDiscoverCount = this.vMaxPeersToDiscoverCount;
        long peerDiscoveryTimeoutMillis = this.vPeerDiscoveryTimeoutMillis;
        long start = System.currentTimeMillis();
        final List<PeerAddress> addressList = Lists.newLinkedList();
        for (PeerDiscovery peerDiscovery : peerDiscoverers /* COW */) {
            InetSocketAddress[] addresses;
            addresses = peerDiscovery.getPeers(peerDiscoveryTimeoutMillis, TimeUnit.MILLISECONDS);
            for (InetSocketAddress address : addresses) addressList.add(new PeerAddress(address));
            if (addressList.size() >= maxPeersToDiscoverCount) break;
        }
        if (!addressList.isEmpty()) {
            for (PeerAddress address : addressList) {
                addInactive(address);
            }
            final ImmutableSet<PeerAddress> peersDiscoveredSet = ImmutableSet.copyOf(addressList);
            for (final ListenerRegistration<PeerEventListener> registration : peerEventListeners /* COW */) {
                registration.executor.execute(new Runnable() {
                    @Override
                    public void run() {
                        registration.listener.onPeersDiscovered(peersDiscoveredSet);
                    }
                });
            }
        }
        log.info("Peer discovery took {}ms and returned {} items", System.currentTimeMillis() - start,
                addressList.size());
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
            Socket socket = null;
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress(InetAddresses.forString("127.0.0.1"), params.getPort()), vConnectTimeoutMillis);
                localhostCheckState = LocalhostCheckState.FOUND;
                return true;
            } catch (IOException e) {
                log.info("Localhost peer not detected.");
                localhostCheckState = LocalhostCheckState.NOT_THERE;
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        // Ignore.
                    }
                }
            }
        }
        return false;
    }

    /**
     * Starts the PeerGroup and begins network activity.
     * @return A future that completes when first connection activity has been triggered (note: not first connection made).
     */
    public ListenableFuture startAsync() {
        // This is run in a background thread by the Service implementation.
        if (chain == null) {
            // Just try to help catch what might be a programming error.
            log.warn("Starting up with no attached block chain. Did you forget to pass one to the constructor?");
        }
        checkState(!vUsedUp, "Cannot start a peer group twice");
        vRunning = true;
        vUsedUp = true;
        executorStartupLatch.countDown();
        // We do blocking waits during startup, so run on the executor thread.
        return executor.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    log.info("Starting ...");
                    if (torClient != null) {
                        log.info("Starting Tor/Orchid ...");
                        torClient.start();
                        try {
                            torClient.waitUntilReady(TOR_TIMEOUT_SECONDS * 1000);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                        log.info("Tor ready");
                    }
                    channels.startAsync();
                    channels.awaitRunning();
                    triggerConnections();
                    setupPinging();
                } catch (Throwable e) {
                    log.error("Exception when starting up", e);  // The executor swallows exceptions :(
                }
            }
        });
    }

    /** Does a blocking startup. */
    public void start() {
        Futures.getUnchecked(startAsync());
    }

    /** Can just use start() for a blocking start here instead of startAsync/awaitRunning: PeerGroup is no longer a Guava service. */
    @Deprecated
    public void awaitRunning() {
        waitForJobQueue();
    }

    public ListenableFuture stopAsync() {
        checkState(vRunning);
        vRunning = false;
        ListenableFuture future = executor.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    log.info("Stopping ...");
                    // Blocking close of all sockets.
                    channels.stopAsync();
                    channels.awaitTerminated();
                    for (PeerDiscovery peerDiscovery : peerDiscoverers) {
                        peerDiscovery.shutdown();
                    }
                    if (torClient != null) {
                        torClient.stop();
                    }
                    vRunning = false;
                    log.info("Stopped.");
                } catch (Throwable e) {
                    log.error("Exception when shutting down", e);  // The executor swallows exceptions :(
                }
            }
        });
        executor.shutdown();
        return future;
    }

    /** Does a blocking stop */
    public void stop() {
        try {
            stopAsync();
            log.info("Awaiting PeerGroup shutdown ...");
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /** Can just use stop() here instead of stopAsync/awaitTerminated: PeerGroup is no longer a Guava service. */
    @Deprecated
    public void awaitTerminated() {
        try {
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
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
            checkNotNull(wallet);
            checkState(!wallets.contains(wallet));
            wallets.add(wallet);
            wallet.setTransactionBroadcaster(this);
            wallet.addEventListener(walletEventListener, Threading.SAME_THREAD);
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
     * The return value of this method is the <code>ListenableFuture</code> returned by that invocation.</p>
     *
     * @return a future that completes once each <code>Peer</code> in this group has had its
     *         <code>BloomFilter</code> (re)set.
     */
    public ListenableFuture<BloomFilter> addPeerFilterProvider(PeerFilterProvider provider) {
        lock.lock();
        try {
            checkNotNull(provider);
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
            ListenableFuture<BloomFilter> future = recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED);
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
            checkNotNull(provider);
            checkArgument(peerFilterProviders.remove(provider));
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
        for (Peer peer : peers) {
            peer.removeWallet(wallet);
        }        
    }

    public enum FilterRecalculateMode {
        SEND_IF_CHANGED,
        FORCE_SEND_FOR_REFRESH,
        DONT_SEND,
    }

    private final Map<FilterRecalculateMode, SettableFuture<BloomFilter>> inFlightRecalculations = Maps.newHashMap();

    /**
     * Recalculates the bloom filter given to peers as well as the timestamp after which full blocks are downloaded
     * (instead of only headers). Note that calls made one after another may return the same future, if the request
     * wasn't processed yet (i.e. calls are deduplicated).
     *
     * @param mode In what situations to send the filter to connected peers.
     * @return a future that completes once the filter has been calculated (note: this does not mean acknowledged by remote peers).
     */
    public ListenableFuture<BloomFilter> recalculateFastCatchupAndFilter(final FilterRecalculateMode mode) {
        final SettableFuture<BloomFilter> future = SettableFuture.create();
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
                FilterMerger.Result result = bloomFilterMerger.calculate(ImmutableList.copyOf(peerFilterProviders /* COW */));
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
                setFastCatchupTimeSecs(result.earliestKeyTimeSecs);
                synchronized (inFlightRecalculations) {
                    inFlightRecalculations.put(mode, null);
                }
                future.set(result.filter);
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
     *         Use {@link org.bitcoinj.core.Peer#getConnectionOpenFuture()} if you
     *         want a future which completes when the connection is open.
     */
    @Nullable
    public Peer connectTo(InetSocketAddress address) {
        lock.lock();
        try {
            PeerAddress peerAddress = new PeerAddress(address);
            backoffMap.put(peerAddress, new ExponentialBackoff(peerBackoffParams));
            return connectTo(peerAddress, true, vConnectTimeoutMillis);
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
            return connectTo(localhost, true, vConnectTimeoutMillis);
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
     * @return Peer or null.
     */
    @Nullable @GuardedBy("lock")
    protected Peer connectTo(PeerAddress address, boolean incrementMaxConnections, int connectTimeoutMillis) {
        checkState(lock.isHeldByCurrentThread());
        VersionMessage ver = getVersionMessage().duplicate();
        ver.bestHeight = chain == null ? 0 : chain.getBestChainHeight();
        ver.time = Utils.currentTimeSeconds();

        Peer peer = new Peer(params, ver, address, chain, downloadTxDependencies);
        peer.addEventListener(startupListener, Threading.SAME_THREAD);
        peer.setMinProtocolVersion(vMinRequiredProtocolVersion);
        pendingPeers.add(peer);

        try {
            log.info("Attempting connection to {}     ({} connected, {} pending, {} max)", address,
                    peers.size(), pendingPeers.size(), maxConnections);
            ListenableFuture<SocketAddress> future = channels.openConnection(address.toSocketAddress(), peer);
            if (future.isDone())
                Uninterruptibles.getUninterruptibly(future);
        } catch (ExecutionException e) {
            Throwable cause = Throwables.getRootCause(e);
            log.warn("Failed to connect to " + address + ": " + cause.getMessage());
            handlePeerDeath(peer, cause);
            return null;
        }
        peer.setSocketTimeout(connectTimeoutMillis);
        // When the channel has connected and version negotiated successfully, handleNewPeer will end up being called on
        // a worker thread.
        if (incrementMaxConnections) {
            // We don't use setMaxConnections here as that would trigger a recursive attempt to establish a new
            // outbound connection.
            maxConnections++;
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
            if (downloadPeer != null && listener != null)
                downloadPeer.addEventListener(listener);
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
            if (downloadPeer == null) {
                // Kick off chain download if we aren't already doing it.
                setDownloadPeer(selectDownloadPeer(peers));
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

    @Nullable private volatile ListenableScheduledFuture<?> vPingTask;

    @SuppressWarnings("NonAtomicOperationOnVolatileField")
    private void setupPinging() {
        if (getPingIntervalMsec() <= 0)
            return;  // Disabled.

        vPingTask = executor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                try {
                    if (getPingIntervalMsec() <= 0) {
                        ListenableScheduledFuture<?> task = vPingTask;
                        if (task != null) {
                            task.cancel(false);
                            vPingTask = null;
                        }
                        return;  // Disabled.
                    }
                    for (Peer peer : getConnectedPeers()) {
                        if (peer.getPeerVersionMessage().clientVersion < Pong.MIN_PROTOCOL_VERSION)
                            continue;
                        peer.ping();
                    }
                } catch (Throwable e) {
                    log.error("Exception in ping loop", e);  // The executor swallows exceptions :(
                }
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
                if (chain != null)
                    downloadPeer.setDownloadParameters(fastCatchupTimeSecs, bloomFilterMerger.getLastFilter() != null);
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
     * Tells the PeerGroup to download only block headers before a certain time and bodies after that. Call this
     * before starting block chain download.
     * Do not use a time > NOW - 1 block, as it will break some block download logic.
     */
    public void setFastCatchupTimeSecs(long secondsSinceEpoch) {
        lock.lock();
        try {
            checkState(chain == null || !chain.shouldVerifyTransactions(), "Fast catchup is incompatible with fully verifying");
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

    @GuardedBy("lock") private int stallPeriodSeconds = 10;
    @GuardedBy("lock") private int stallMinSpeedBytesSec = Block.HEADER_SIZE * 20;

    /**
     * Configures the stall speed: the speed at which a peer is considered to be serving us the block chain
     * unacceptably slowly. Once a peer has served us data slower than the given data rate for the given
     * number of seconds, it is considered stalled and will be disconnected, forcing the chain download to continue
     * from a different peer. The defaults are chosen conservatively, but if you are running on a platform that is
     * CPU constrained or on a very slow network e.g. EDGE, the default settings may need adjustment to
     * avoid false stalls.
     *
     * @param periodSecs How many seconds the download speed must be below blocksPerSec, defaults to 10.
     * @param bytesPerSecond Download speed (only blocks/txns count) must be consistently below this for a stall, defaults to the bandwidth required for 20 block headers per second.
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

    private class ChainDownloadSpeedCalculator extends AbstractPeerEventListener implements Runnable {
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

        @Override
        public synchronized void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft) {
            blocksInLastSecond++;
            bytesInLastSecond += 80;  // For the header.
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

                boolean behindPeers = chain != null && chain.getBestChainHeight() < getMostCommonChainHeight();
                if (!behindPeers)
                    syncDone = true;
                if (!syncDone) {
                    if (warmupSeconds < 0) {
                        // Calculate the moving average.
                        samples[cursor++] = bytesInLastSecond;
                        if (cursor == samples.length) cursor = 0;
                        long average = 0;
                        for (long sample : samples) average += sample;
                        average /= samples.length;

                        log.info(String.format(Locale.US, "%d blocks/sec, %d tx/sec, %d pre-filtered tx/sec, avg/last %.2f/%.2f kilobytes per sec (stall threshold <%.2f KB/sec for %d seconds)",
                                blocksInLastSecond, txnsInLastSecond, origTxnsInLastSecond, average / 1024.0, bytesInLastSecond / 1024.0,
                                minSpeedBytesPerSec / 1024.0, samples.length));

                        if (average < minSpeedBytesPerSec && maxStalls > 0) {
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
                                log.warn(String.format(Locale.US, "Chain download stalled: received %.2f KB/sec for %d seconds, require average of %.2f KB/sec, disconnecting %s", average / 1024.0, samples.length, minSpeedBytesPerSec / 1024.0, peer));
                                peer.close();
                                // Reset the sample buffer and give the next peer time to get going.
                                samples = null;
                                warmupSeconds = period;
                            }
                        }
                    } else {
                        warmupSeconds--;
                        if (bytesInLastSecond > 0)
                            log.info(String.format(Locale.US, "%d blocks/sec, %d tx/sec, %d pre-filtered tx/sec, last %.2f kilobytes per sec",
                                    blocksInLastSecond, txnsInLastSecond, origTxnsInLastSecond, bytesInLastSecond / 1024.0));
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

    private void startBlockChainDownloadFromPeer(Peer peer) {
        lock.lock();
        try {
            setDownloadPeer(peer);

            if (chainDownloadSpeedCalculator == null) {
                // Every second, run the calculator which will log how fast we are downloading the chain.
                chainDownloadSpeedCalculator = new ChainDownloadSpeedCalculator();
                executor.scheduleAtFixedRate(chainDownloadSpeedCalculator, 1, 1, TimeUnit.SECONDS);
            }
            peer.addEventListener(chainDownloadSpeedCalculator, Threading.SAME_THREAD);

            // startBlockChainDownload will setDownloadData(true) on itself automatically.
            peer.startBlockChainDownload();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a future that is triggered when the number of connected peers is equal to the given number of
     * peers. By using this with {@link org.bitcoinj.core.PeerGroup#getMaxConnections()} you can wait until the
     * network is fully online. To block immediately, just call get() on the result. Just calls
     * {@link #waitForPeersOfVersion(int, long)} with zero as the protocol version.
     *
     * @param numPeers How many peers to wait for.
     * @return a future that will be triggered when the number of connected peers >= numPeers
     */
    public ListenableFuture<List<Peer>> waitForPeers(final int numPeers) {
        return waitForPeersOfVersion(numPeers, 0);
    }

    /**
     * Returns a future that is triggered when there are at least the requested number of connected peers that support
     * the given protocol version or higher. To block immediately, just call get() on the result.
     *
     * @param numPeers How many peers to wait for.
     * @param protocolVersion The protocol version the awaited peers must implement (or better).
     * @return a future that will be triggered when the number of connected peers implementing protocolVersion or higher >= numPeers
     */
    public ListenableFuture<List<Peer>> waitForPeersOfVersion(final int numPeers, final long protocolVersion) {
        List<Peer> foundPeers = findPeersOfAtLeastVersion(protocolVersion);
        if (foundPeers.size() >= numPeers) {
            return Futures.immediateFuture(foundPeers);
        }
        final SettableFuture<List<Peer>> future = SettableFuture.create();
        addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                final List<Peer> peers = findPeersOfAtLeastVersion(protocolVersion);
                if (peers.size() >= numPeers) {
                    future.set(peers);
                    removeEventListener(this);
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
            ArrayList<Peer> results = new ArrayList<Peer>(peers.size());
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
     * @return a future that will be triggered when the number of connected peers implementing protocolVersion or higher >= numPeers
     */
    public ListenableFuture<List<Peer>> waitForPeersWithServiceMask(final int numPeers, final int mask) {
        lock.lock();
        try {
            List<Peer> foundPeers = findPeersWithServiceMask(mask);
            if (foundPeers.size() >= numPeers)
                return Futures.immediateFuture(foundPeers);
            final SettableFuture<List<Peer>> future = SettableFuture.create();
            addEventListener(new AbstractPeerEventListener() {
                @Override
                public void onPeerConnected(Peer peer, int peerCount) {
                    final List<Peer> peers = findPeersWithServiceMask(mask);
                    if (peers.size() >= numPeers) {
                        future.set(peers);
                        removeEventListener(this);
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
            ArrayList<Peer> results = new ArrayList<Peer>(peers.size());
            for (Peer peer : peers)
                if ((peer.getPeerVersionMessage().localServices & mask) == mask)
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
     * {@link org.bitcoinj.core.PeerGroup#getMaxConnections()} returns is used.
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
     * See {@link org.bitcoinj.core.PeerGroup#getMinBroadcastConnections()}.
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
    @Override
    public TransactionBroadcast broadcastTransaction(final Transaction tx) {
        return broadcastTransaction(tx, Math.max(1, getMinBroadcastConnections()));
    }

    /**
     * <p>Given a transaction, sends it un-announced to one peer and then waits for it to be received back from other
     * peers. Once all connected peers have announced the transaction, the future available via the
     * {@link org.bitcoinj.core.TransactionBroadcast#future()} method will be completed. If anything goes
     * wrong the exception will be thrown when get() is called, or you can receive it via a callback on the
     * {@link ListenableFuture}. This method returns immediately, so if you want it to block just call get() on the
     * result.</p>
     *
     * <p>Note that if the PeerGroup is limited to only one connection (discovery is not activated) then the future
     * will complete as soon as the transaction was successfully written to that peer.</p>
     *
     * <p>The transaction won't be sent until there are at least minConnections active connections available.
     * A good choice for proportion would be between 0.5 and 0.8 but if you want faster transmission during initial
     * bringup of the peer group you can lower it.</p>
     *
     * <p>The returned {@link org.bitcoinj.core.TransactionBroadcast} object can be used to get progress feedback,
     * which is calculated by watching the transaction propagate across the network and be announced by peers.</p>
     */
    public TransactionBroadcast broadcastTransaction(final Transaction tx, final int minConnections) {
        // If we don't have a record of where this tx came from already, set it to be ourselves so Peer doesn't end up
        // redownloading it from the network redundantly.
        if (tx.getConfidence().getSource().equals(TransactionConfidence.Source.UNKNOWN)) {
            log.info("Transaction source unknown, setting to SELF: {}", tx.getHashAsString());
            tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        }
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
                // This can happen if we get a reject message from a peer.
                runningBroadcasts.remove(broadcast);
            }
        });
        // Keep a reference to the TransactionBroadcast object. This is important because otherwise, the entire tree
        // of objects we just created would become garbage if the user doesn't hold on to the returned future, and
        // eventually be collected. This in turn could result in the transaction not being committed to the wallet
        // at all.
        runningBroadcasts.add(broadcast);
        broadcast.broadcast();
        return broadcast;
    }

    /**
     * Returns the period between pings for an individual peer. Setting this lower means more accurate and timely ping
     * times are available via {@link org.bitcoinj.core.Peer#getLastPingTime()} but it increases load on the
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
     * times are available via {@link org.bitcoinj.core.Peer#getLastPingTime()} but it increases load on the
     * remote node. It defaults to {@link PeerGroup#DEFAULT_PING_INTERVAL_MSEC}.
     * Setting the value to be <= 0 disables pinging entirely, although you can still request one yourself
     * using {@link org.bitcoinj.core.Peer#ping()}.
     */
    public void setPingIntervalMsec(long pingIntervalMsec) {
        lock.lock();
        try {
            this.pingIntervalMsec = pingIntervalMsec;
            ListenableScheduledFuture<?> task = vPingTask;
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
        ArrayList<Peer> candidates2 = new ArrayList<Peer>(candidates.size());
        for (Peer peer : candidates) {
            if (peer.getPeerVersionMessage().clientVersion >= preferredVersion) {
                candidates2.add(peer);
            }
        }
        int index = (int) (Math.random() * candidates2.size());
        return candidates2.get(index);
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
     * Returns the {@link com.subgraph.orchid.TorClient} object for this peer group, if Tor is in use, null otherwise.
     */
    @Nullable
    public TorClient getTorClient() {
        return torClient;
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
