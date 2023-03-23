/*
 * Copyright by the original author or authors.
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

import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.NetworkParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * SeedPeers stores a pre-determined list of Bitcoin node addresses. These nodes are selected based on being
 * active on the network for a long period of time. The intention is to be a last resort way of finding a connection
 * to the network, in case IRC and DNS fail. The list comes from the Bitcoin C++ source code.
 */
public class SeedPeers implements PeerDiscovery {
    private final List<InetSocketAddress> seedAddrs;
    private int pnseedIndex;

    private static final Logger log = LoggerFactory.getLogger(SeedPeers.class);

    /**
     * Supports finding peers by IP addresses/ports
     *
     * @param seedAddrs IP addresses/ports of seeds.
     */
    public SeedPeers(InetSocketAddress[] seedAddrs) {
        this.seedAddrs = Arrays.asList(seedAddrs);
    }

    /**
     * Supports finding peers by IP addresses
     *
     * @param params Network parameters to be used for port information.
     * @deprecated use {@link SeedPeers#SeedPeers(InetSocketAddress[])}
     */
    @Deprecated
    public SeedPeers(NetworkParameters params) {
        this(params.getAddrSeeds(), params);
    }

    /**
     * Supports finding peers by IP addresses
     *
     * @param seedAddrInts IP addresses for seed addresses.
     * @param params    Network parameters to be used for port information.
     * @deprecated use {@link SeedPeers#SeedPeers(InetSocketAddress[])}
     */
    @Deprecated
    public SeedPeers(int[] seedAddrInts, NetworkParameters params) {
        this.seedAddrs = new LinkedList<>();
        if (seedAddrInts == null)
            return;
        for (int seedAddrInt : seedAddrInts) {
            try {
                InetSocketAddress seedAddr = new InetSocketAddress(convertAddress(seedAddrInt), params.getPort());
                this.seedAddrs.add(seedAddr);
            } catch (UnknownHostException x) {
                // swallow
            }
        }
    }

    /**
     * Acts as an iterator, returning the address of each node in the list sequentially.
     * Once all the list has been iterated, null will be returned for each subsequent query.
     *
     * @return InetSocketAddress - The address/port of the next node.
     */
    @Nullable
    public InetSocketAddress getPeer() {
        return nextPeer();
    }

    @Nullable
    private InetSocketAddress nextPeer() {
        if (pnseedIndex >= seedAddrs.size())
            return null;
        return seedAddrs.get(pnseedIndex++);
    }

    /**
     * Returns all the Bitcoin nodes within the list.
     *
     * @param services ignored
     * @param timeout  ignored
     * @return the pre-determined list of peers
     */
    @Override
    public List<InetSocketAddress> getPeers(long services, Duration timeout) {
        if (services != 0)
            log.info("Pre-determined peers cannot be filtered by services: {}", services);
        return Collections.unmodifiableList(seedAddrs);
    }

    @Override
    public void shutdown() {
    }

    private static InetAddress convertAddress(int seed) throws UnknownHostException {
        byte[] v4addr = ByteBuffer.allocate(4).putInt(seed).array(); // Big-Endian
        return InetAddress.getByAddress(v4addr);
    }
}
