/*
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

package org.bitcoinj.net.discovery;

import org.bitcoinj.base.Network;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Services;
import org.bitcoinj.core.VersionMessage;
import org.bitcoinj.utils.DaemonThreadFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * <p>Supports peer discovery through DNS.</p>
 *
 * <p>Failure to resolve individual host names will not cause an Exception to be thrown.
 * However, if all hosts passed fail to resolve a PeerDiscoveryException will be thrown during getPeers().
 * </p>
 *
 * <p>DNS seeds do not attempt to enumerate every peer on the network. {@link DnsDiscovery#getPeers(long, Duration)}
 * will return up to 30 random peers from the set of those returned within the timeout period. If you want more peers
 * to connect to, you need to discover them via other means (like addr broadcasts).</p>
 */
public class DnsDiscovery extends MultiplexingDiscovery {
    private static final Logger log = LoggerFactory.getLogger(DnsDiscovery.class);

    /**
     * Supports finding peers through DNS A records. Community run DNS entry points will be used.
     *
     * @param network Network to be used for port information.
     */
    public DnsDiscovery(Network network) {
        this(NetworkParameters.of(network).getDnsSeeds(), network);
    }

    /**
     * Supports finding peers through DNS A records.
     *
     * @param dnsSeeds Host names to be examined for seed addresses.
     * @param network Network to be used for port information.
     */
    public DnsDiscovery(String[] dnsSeeds, Network network) {
        super(network, buildDiscoveries(network, dnsSeeds));
    }

    /**
     * @deprecated Use {@link DnsDiscovery#DnsDiscovery(Network)}
     */
    @Deprecated
    public DnsDiscovery(NetworkParameters netParams) {
        this(netParams.getDnsSeeds(), netParams.network());
    }

    /**
     * @deprecated Use {@link DnsDiscovery#DnsDiscovery(String[], Network)}
     */
    @Deprecated
    public DnsDiscovery(String[] dnsSeeds, NetworkParameters params) {
        this(dnsSeeds, params.network());
    }


    private static List<PeerDiscovery> buildDiscoveries(Network network, String[] seeds) {
        List<PeerDiscovery> discoveries = new ArrayList<>();
        if (seeds != null)
            for (String seed : seeds)
                discoveries.add(new DnsSeedDiscovery(network, seed));
        return discoveries;
    }

    @Override
    protected ExecutorService createExecutor() {
        return Executors.newFixedThreadPool(seeds.size(), new DaemonThreadFactory("DNS seed lookups"));
    }

    /** Implements discovery from a single DNS host. */
    public static class DnsSeedDiscovery implements PeerDiscovery {
        private final String hostname;
        private final NetworkParameters params;

        public DnsSeedDiscovery(Network network, String hostname) {
            this.hostname = hostname;
            this.params = NetworkParameters.of(network);
        }

        /**
         * @deprecated Use {@link DnsSeedDiscovery#DnsSeedDiscovery(Network, String)}
         */
        @Deprecated
        public DnsSeedDiscovery(NetworkParameters params, String hostname) {
            this(params.network(), hostname);
        }

        @Override
        public List<InetSocketAddress> getPeers(long services, Duration timeout) throws PeerDiscoveryException {
            InetAddress[] response = null;
            if (services != 0) {
                String hostnameWithServices = "x" + Long.toHexString(services) + "." + hostname;
                log.info("Requesting {} peers from {}", Services.of(services).toString(),
                        hostnameWithServices);
                try {
                    response = InetAddress.getAllByName(hostnameWithServices);
                    log.info("Got {} peers from {}", response.length, hostnameWithServices);
                } catch (UnknownHostException e) {
                    log.info("Seed {} doesn't appear to support service bit filtering: {}", hostname, e.getMessage());
                }
            }
            if (response == null || response.length == 0) {
                log.info("Requesting all peers from {}", hostname);
                try {
                    response = InetAddress.getAllByName(hostname);
                    log.info("Got {} peers from {}", response.length, hostname);
                } catch (UnknownHostException e) {
                    throw new PeerDiscoveryException(e);
                }
            }

            List<InetSocketAddress> result = new ArrayList<>(response.length);
            for (InetAddress r : response)
                result.add(new InetSocketAddress(r, params.getPort()));
            return result;
        }

        @Override
        public void shutdown() {
        }

        @Override
        public String toString() {
            return hostname;
        }
    }
}
