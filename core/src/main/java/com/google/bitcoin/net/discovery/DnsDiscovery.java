/**
 * Copyright 2011 John Sample
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

package com.google.bitcoin.net.discovery;

import com.google.bitcoin.core.NetworkParameters;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;

/**
 * <p>Supports peer discovery through DNS.</p>
 *
 * <p>Failure to resolve individual host names will not cause an Exception to be thrown.
 * However, if all hosts passed fail to resolve a PeerDiscoveryException will be thrown during getPeers().
 * </p>
 *
 * <p>DNS seeds do not attempt to enumerate every peer on the network. {@link DnsDiscovery#getPeers(long, java.util.concurrent.TimeUnit)}
 * will return up to 30 random peers from the set of those returned within the timeout period. If you want more peers
 * to connect to, you need to discover them via other means (like addr broadcasts).</p>
 */
public class DnsDiscovery implements PeerDiscovery {
    private static final Logger log = LoggerFactory.getLogger(DnsDiscovery.class);

    private final String[] dnsSeeds;
    private final NetworkParameters netParams;

    /**
     * Supports finding peers through DNS A records. Community run DNS entry points will be used.
     *
     * @param netParams Network parameters to be used for port information.
     */
    public DnsDiscovery(NetworkParameters netParams) {
        this(netParams.getDnsSeeds(), netParams);
    }

    /**
     * Supports finding peers through DNS A records.
     *
     * @param dnsSeeds Host names to be examined for seed addresses.
     * @param netParams Network parameters to be used for port information.
     */
    public DnsDiscovery(String[] dnsSeeds, NetworkParameters netParams) {
        this.dnsSeeds = dnsSeeds;
        this.netParams = netParams;
    }

    public InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        if (dnsSeeds == null || dnsSeeds.length == 0)
            throw new PeerDiscoveryException("No DNS seeds configured; unable to find any peers");

        // Java doesn't have an async DNS API so we have to do all lookups in a thread pool, as sometimes seeds go
        // hard down and it takes ages to give up and move on.
        ExecutorService threadPool = Executors.newFixedThreadPool(dnsSeeds.length);
        try {
            List<Callable<InetAddress[]>> tasks = Lists.newArrayList();
            for (final String seed : dnsSeeds) {
                tasks.add(new Callable<InetAddress[]>() {
                    public InetAddress[] call() throws Exception {
                        return InetAddress.getAllByName(seed);
                    }
                });
            }
            final List<Future<InetAddress[]>> futures = threadPool.invokeAll(tasks, timeoutValue, timeoutUnit);
            ArrayList<InetSocketAddress> addrs = Lists.newArrayList();
            for (int i = 0; i < futures.size(); i++) {
                Future<InetAddress[]> future = futures.get(i);
                if (future.isCancelled()) {
                    log.warn("DNS seed {}: timed out", dnsSeeds[i]);
                    continue;  // Timed out.
                }
                final InetAddress[] inetAddresses;
                try {
                    inetAddresses = future.get();
                    log.info("DNS seed {}: got {} peers", dnsSeeds[i], inetAddresses.length);
                } catch (ExecutionException e) {
                    log.error("DNS seed {}: failed to look up: {}", dnsSeeds[i], e.getMessage());
                    continue;
                }
                for (InetAddress addr : inetAddresses) {
                    addrs.add(new InetSocketAddress(addr, netParams.getPort()));
                }
            }
            if (addrs.size() == 0)
                throw new PeerDiscoveryException("Unable to find any peers via DNS");
            Collections.shuffle(addrs);
            threadPool.shutdownNow();
            return addrs.toArray(new InetSocketAddress[addrs.size()]);
        } catch (InterruptedException e) {
            throw new PeerDiscoveryException(e);
        } finally {
            threadPool.shutdown();
        }
    }

    /** We don't have a way to abort a DNS lookup, so this does nothing */
    public void shutdown() {
    }
}
