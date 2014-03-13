/**
 * Copyright 2011 John Sample
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

package com.google.bitcoin.net.discovery;

import com.google.bitcoin.core.NetworkParameters;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.circuits.path.CircuitPathChooser;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.exitpolicy.ExitTarget;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * <p>Supports peer discovery through Tor.</p>
 *
 * <p>Failure to obtain at least four different peers through different exit nodes will cause
 * a PeerDiscoveryException will be thrown during getPeers().
 * </p>
 *
 * <p>DNS seeds do not attempt to enumerate every peer on the network. If you want more peers
 * to connect to, you need to discover them via other means (like addr broadcasts).</p>
 */
public class TorDiscovery implements PeerDiscovery {
    private static final Logger log = LoggerFactory.getLogger(TorDiscovery.class);
    public static final int MINIMUM_ROUTER_COUNT = 4;
    public static final int MINIMUM_ROUTER_LOOKUP_COUNT = 10;
    public static final int RECEIVE_RETRIES = 5;

    private final String[] hostNames;
    private final NetworkParameters netParams;
    private final CircuitPathChooser pathChooser;
    private final TorClient torClient;

    /**
     * Supports finding peers through Tor. Community run DNS entry points will be used.
     *
     * @param netParams Network parameters to be used for port information.
     */
    public TorDiscovery(NetworkParameters netParams, TorClient torClient) {
        this(netParams.getDnsSeeds(), netParams, torClient);
    }

    /**
     * Supports finding peers through Tor.
     *
     * @param hostNames Host names to be examined for seed addresses.
     * @param netParams Network parameters to be used for port information.
     * @param torClient an already-started Tor client.
     */
    public TorDiscovery(String[] hostNames, NetworkParameters netParams, TorClient torClient) {
        this.hostNames = hostNames;
        this.netParams = netParams;

        this.torClient = torClient;
        this.pathChooser = CircuitPathChooser.create(torClient.getConfig(), torClient.getDirectory());
    }

    static class Lookup {
        final Router router;
        final InetAddress address;

        Lookup(Router router, InetAddress address) {
            this.router = router;
            this.address = address;
        }
    }

    public InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        if (hostNames == null)
            throw new PeerDiscoveryException("Unable to find any peers via DNS");

        Set<Router> routers = Sets.newHashSet();
        ArrayList<ExitTarget> dummyTargets = Lists.newArrayList();

        while (routers.size() < MINIMUM_ROUTER_LOOKUP_COUNT) {
            Router router = pathChooser.chooseExitNodeForTargets(dummyTargets);
            routers.add(router);
        }

        ExecutorService threadPool = Executors.newFixedThreadPool(routers.size());

        try {
            List<Circuit> circuits = getCircuits(timeoutValue, timeoutUnit, routers, threadPool);

            threadPool = Executors.newFixedThreadPool(circuits.size() * hostNames.length);
            Map<HexDigest, InetSocketAddress> lookupMap = lookupAddresses(timeoutValue, timeoutUnit, threadPool, circuits);

            ArrayList<InetSocketAddress> addrs = Lists.newArrayList();
            addrs.addAll(lookupMap.values());
            if (addrs.size() < MINIMUM_ROUTER_COUNT)
                throw new PeerDiscoveryException("Unable to find enough peers via Tor - got " + addrs.size());
            Collections.shuffle(addrs);
            threadPool.shutdownNow();
            return addrs.toArray(new InetSocketAddress[addrs.size()]);
        } catch (InterruptedException e) {
            throw new PeerDiscoveryException(e);
        } finally {
            threadPool.shutdown();
        }
    }

    private List<Circuit> getCircuits(long timeoutValue, TimeUnit timeoutUnit, Set<Router> routers, ExecutorService threadPool) throws InterruptedException {
        List<Circuit> circuits = Lists.newArrayList();

        List<Callable<Circuit>> circuitTasks = Lists.newArrayList();
        for (final Router router : routers) {
            circuitTasks.add(new Callable<Circuit>() {
                public Circuit call() throws Exception {
                    return torClient.getCircuitManager().openInternalCircuitTo(Lists.newArrayList(router));
                }
            });
        }

        final List<Future<Circuit>> circuitFutures =
                threadPool.invokeAll(circuitTasks, timeoutValue, timeoutUnit);
        for (int i = 0; i < circuitFutures.size(); i++) {
            Future<Circuit> future = circuitFutures.get(i);
            if (future.isCancelled()) {
                log.warn("circuit timed out");
                continue;  // Timed out.
            }
            try {
                circuits.add(future.get());
            } catch (ExecutionException e) {
                log.error("Failed to construct circuit - {}", e.getMessage());
                continue;
            }
        }

        threadPool.shutdownNow();
        return circuits;
    }

    private Map<HexDigest, InetSocketAddress> lookupAddresses(long timeoutValue, TimeUnit timeoutUnit, ExecutorService threadPool, List<Circuit> circuits) throws InterruptedException {
        List<Callable<Lookup>> lookupTasks = Lists.newArrayList();
        for (final Circuit circuit : circuits) {
            for (final String seed : hostNames) {
                lookupTasks.add(new Callable<Lookup>() {
                    public Lookup call() throws Exception {
                        return new Lookup(circuit.getFinalCircuitNode().getRouter(), lookup(circuit, seed));
                    }
                });
            }
        }

        final List<Future<Lookup>> lookupFutures =
                threadPool.invokeAll(lookupTasks, timeoutValue, timeoutUnit);
        Map<HexDigest, InetSocketAddress> lookupMap = Maps.newHashMap();
        for (int i = 0; i < lookupFutures.size(); i++) {
            Future<Lookup> future = lookupFutures.get(i);
            if (future.isCancelled()) {
                log.warn("circuit timed out");
                continue;  // Timed out.
            }
            try {
                Lookup lookup = future.get();
                // maximum one entry per exit node
                // TODO randomize result selection better

                InetSocketAddress address = new InetSocketAddress(lookup.address, netParams.getPort());
                lookupMap.put(lookup.router.getIdentityHash(), address);
            } catch (ExecutionException e) {
                log.error("Failed to construct circuit - {}", e.getMessage());
                continue;
            }
        }
        return lookupMap;
    }

    private InetAddress lookup(Circuit circuit, String seed) throws UnknownHostException {
        RelayCell cell = circuit.createRelayCell(RelayCell.RELAY_RESOLVE, 0x1000, circuit.getFinalCircuitNode());
        cell.putString(seed);
        circuit.sendRelayCell(cell);
        for (int i = 0 ; i < RECEIVE_RETRIES; i++) {
            RelayCell res = circuit.receiveRelayCell();
            if (res != null) {
                while (res.cellBytesRemaining() > 0) {
                    int type = res.getByte();
                    int len = res.getByte();
                    byte[] value = new byte[len];
                    res.getByteArray(value);
                    int ttl = res.getInt();
                    if (type == 0 || type >= 0xf0)
                        throw new RuntimeException(new String(value));
                    else if (type == 4 || type == 6) {
                        return InetAddress.getByAddress(value);
                    }
                }
                break;
            }
        }
        throw new RuntimeException("Could not look up " + seed);
    }

    /** We don't have a way to abort a DNS lookup, so this does nothing */
    public void shutdown() {
    }
}
