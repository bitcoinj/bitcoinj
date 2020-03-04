/*
 * Copyright 2014 Mike Hearn
 * Copyright 2015 Andreas Schildbach
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

package org.bitcoinj.net.discovery;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.VersionMessage;
import org.bitcoinj.net.discovery.DnsDiscovery.DnsSeedDiscovery;
import org.bitcoinj.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.*;

import okhttp3.OkHttpClient;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * MultiplexingDiscovery queries multiple PeerDiscovery objects, optionally shuffles their responses and then returns the results,
 * thus selecting randomly between them and reducing the influence of any particular seed. Any that don't respond
 * within the timeout are ignored. Backends are queried in parallel or serially. Backends may block.
 */
public class MultiplexingDiscovery implements PeerDiscovery {
    private static final Logger log = LoggerFactory.getLogger(MultiplexingDiscovery.class);

    protected final List<PeerDiscovery> seeds;
    protected final NetworkParameters netParams;
    private volatile ExecutorService vThreadPool;
    private final boolean parallelQueries;
    private final boolean shufflePeers;

    /**
     * Builds a suitable set of peer discoveries. Will query them in parallel before producing a merged response.
     * If specific services are required, DNS is not used as the protocol can't handle it.
     * @param params Network to use.
     * @param services Required services as a bitmask, e.g. {@link VersionMessage#NODE_NETWORK}.
     */
    public static MultiplexingDiscovery forServices(NetworkParameters params, long services) {
        return forServices(params, services, true, true);
    }

    /**
     * Builds a suitable set of peer discoveries.
     * If specific services are required, DNS is not used as the protocol can't handle it.
     * @param params Network to use.
     * @param services Required services as a bitmask, e.g. {@link VersionMessage#NODE_NETWORK}.
     * @param parallelQueries When true, seeds are queried in parallel
     * @param shufflePeers When true, queried peers are shuffled
     */
    public static MultiplexingDiscovery forServices(NetworkParameters params, long services, boolean parallelQueries,
                                                    boolean shufflePeers) {
        List<PeerDiscovery> discoveries = new ArrayList<>();
        HttpDiscovery.Details[] httpSeeds = params.getHttpSeeds();
        if (httpSeeds != null) {
            OkHttpClient httpClient = new OkHttpClient();
            for (HttpDiscovery.Details httpSeed : httpSeeds)
                discoveries.add(new HttpDiscovery(params, httpSeed, httpClient));
        }
        String[] dnsSeeds = params.getDnsSeeds();
        if (dnsSeeds != null)
            for (String dnsSeed : dnsSeeds)
                discoveries.add(new DnsSeedDiscovery(params, dnsSeed));
        return new MultiplexingDiscovery(params, discoveries, parallelQueries, shufflePeers);
    }

    /**
     * Will query the given seeds in parallel before producing a merged response.
     */
    public MultiplexingDiscovery(NetworkParameters params, List<PeerDiscovery> seeds) {
        this(params, seeds, true, true);
    }

    private MultiplexingDiscovery(NetworkParameters params, List<PeerDiscovery> seeds, boolean parallelQueries,
                                  boolean shufflePeers) {
        checkArgument(!seeds.isEmpty());
        this.netParams = params;
        this.seeds = seeds;
        this.parallelQueries = parallelQueries;
        this.shufflePeers = shufflePeers;
    }

    @Override
    public List<InetSocketAddress> getPeers(final long services, final long timeoutValue, final TimeUnit timeoutUnit) throws PeerDiscoveryException {
        vThreadPool = createExecutor();
        try {
            List<Callable<List<InetSocketAddress>>> tasks = new ArrayList<>();
            if (parallelQueries) {
                for (final PeerDiscovery seed : seeds) {
                    tasks.add(new Callable<List<InetSocketAddress>>() {
                        @Override
                        public List<InetSocketAddress> call() throws Exception {
                            return seed.getPeers(services, timeoutValue, timeoutUnit);
                        }
                    });
                }
            } else {
                tasks.add(new Callable<List<InetSocketAddress>>() {
                    @Override
                    public List<InetSocketAddress> call() throws Exception {
                        List<InetSocketAddress> peers = new LinkedList<>();
                        for (final PeerDiscovery seed : seeds)
                            peers.addAll(seed.getPeers(services, timeoutValue, timeoutUnit));
                        return peers;
                    }
                });
            }
            final List<Future<List<InetSocketAddress>>> futures = vThreadPool.invokeAll(tasks, timeoutValue, timeoutUnit);
            List<InetSocketAddress> addrs = new ArrayList<>();
            for (int i = 0; i < futures.size(); i++) {
                Future<List<InetSocketAddress>> future = futures.get(i);
                if (future.isCancelled()) {
                    log.warn("Seed {}: timed out", parallelQueries ? seeds.get(i) : "any");
                    continue;  // Timed out.
                }
                final List<InetSocketAddress> inetAddresses;
                try {
                    inetAddresses = future.get();
                } catch (ExecutionException e) {
                    log.warn("Seed {}: failed to look up: {}", parallelQueries ? seeds.get(i) : "any", e.getMessage());
                    continue;
                }
                addrs.addAll(inetAddresses);
            }
            if (addrs.size() == 0)
                throw new PeerDiscoveryException("No peer discovery returned any results in "
                        + timeoutUnit.toMillis(timeoutValue) + "ms. Check internet connection?");
            if (shufflePeers)
                Collections.shuffle(addrs);
            vThreadPool.shutdownNow();
            return addrs;
        } catch (InterruptedException e) {
            throw new PeerDiscoveryException(e);
        } finally {
            vThreadPool.shutdown();
        }
    }

    protected ExecutorService createExecutor() {
        return Executors.newFixedThreadPool(seeds.size(), new ContextPropagatingThreadFactory("Multiplexing discovery"));
    }

    @Override
    public void shutdown() {
        ExecutorService tp = vThreadPool;
        if (tp != null)
            tp.shutdown();
    }
}
