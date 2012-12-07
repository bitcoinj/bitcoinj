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

package com.google.bitcoin.discovery;

import com.google.bitcoin.core.NetworkParameters;
import com.google.common.collect.Sets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.*;

/**
 * <p>Supports peer discovery through DNS.</p>
 *
 * <p>This class does not support the testnet as currently there are no DNS servers providing testnet hosts.
 * If this class is being used for testnet you must specify the hostnames to use.</p>
 *
 * <p>Failure to resolve individual host names will not cause an Exception to be thrown.
 * However, if all hosts passed fail to resolve a PeerDiscoveryException will be thrown during getPeers().
 * </p>
 *
 * <p>DNS seeds do not attempt to enumerate every peer on the network. {@link DnsDiscovery#getPeers(long, java.util.concurrent.TimeUnit)}
 * will return up to 30 random peers from the set of those returned within the timeout period. If you want more peers
 * to connect to, you need to discover them via other means (like addr broadcasts).
 * </p>
 */
public class DnsDiscovery implements PeerDiscovery {
    private static final Logger log = LoggerFactory.getLogger(DnsDiscovery.class);

    private String[] hostNames;
    private NetworkParameters netParams;

    public static final String[] defaultHosts = new String[]{
            "seed.bitcoin.sipa.be",        // Pieter Wuille
            "dnsseed.bluematt.me",         // Matt Corallo
            "dnsseed.bitcoin.dashjr.org",  // Luke Dashjr
            "bitseed.xf2.org",             // Jeff Garzik
    };

    /**
     * Supports finding peers through DNS A records. Community run DNS entry points will be used.
     *
     * @param netParams Network parameters to be used for port information.
     */
    public DnsDiscovery(NetworkParameters netParams) {
        this(getDefaultHostNames(), netParams);
    }

    /**
     * Supports finding peers through DNS A records.
     *
     * @param hostNames Host names to be examined for seed addresses.
     * @param netParams Network parameters to be used for port information.
     */
    public DnsDiscovery(String[] hostNames, NetworkParameters netParams) {
        this.hostNames = hostNames;
        this.netParams = netParams;
    }

    public InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        final BlockingQueue<InetSocketAddress> queue = new LinkedBlockingQueue<InetSocketAddress>();

        ArrayList<String> seeds = new ArrayList<String>(Arrays.asList(hostNames));
        // Java doesn't have an async DNS API so we have to do all lookups in a thread pool, as sometimes seeds go
        // hard down and it takes ages to give up and move on.
        ExecutorService pool = Executors.newFixedThreadPool(seeds.size());
        for (final String seed : seeds) {
            pool.submit(new Runnable() {
                public void run() {
                    try {
                        InetAddress[] addrs = InetAddress.getAllByName(seed);
                        for (InetAddress addr : addrs) queue.put(new InetSocketAddress(addr, netParams.port));
                    } catch (UnknownHostException e) {
                        log.warn("Unable to resolve {}", seed);
                    } catch (InterruptedException e) {
                        // Silently go away.
                    }
                }
            });
        }
        // The queue will fill up with resolutions. Let's wait until we got at least 30 or we run out of time.
        final long timeout = timeoutUnit.toMillis(timeoutValue);
        long start = System.currentTimeMillis();
        Set<InetSocketAddress> addrs = Sets.newHashSet();
        while (addrs.size() < 30) {
            try {
                long pollTime = timeout - (System.currentTimeMillis() - start);
                if (pollTime < 0) break;
                InetSocketAddress a = queue.poll(pollTime, TimeUnit.MILLISECONDS);
                if (a == null) {
                    break;
                }
                addrs.add(a);
            } catch (InterruptedException e) {
                break;
            }
        }
        if (addrs.size() == 0) {
            throw new PeerDiscoveryException("Unable to find any peers via DNS");
        }
        ArrayList<InetSocketAddress> shuffledAddrs = new ArrayList<InetSocketAddress>(addrs);
        Collections.shuffle(shuffledAddrs);
        pool.shutdown();
        return shuffledAddrs.toArray(new InetSocketAddress[]{});
    }

    /**
     * Returns the well known discovery host names on the production network.
     */
    public static String[] getDefaultHostNames() {
        return defaultHosts;
    }

    /** We don't have a way to abort a DNS lookup, so this does nothing */
    public void shutdown() {
    }
}
