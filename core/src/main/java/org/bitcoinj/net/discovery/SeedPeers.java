/*
 * Copyright 2011 Micheal Swiggs
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

import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.NetworkParameters;

import javax.annotation.Nullable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * SeedPeers stores a pre-determined list of Bitcoin node addresses. These nodes are selected based on being
 * active on the network for a long period of time. The intention is to be a last resort way of finding a connection
 * to the network, in case IRC and DNS fail. The list comes from the Bitcoin C++ source code.
 */
public class SeedPeers implements PeerDiscovery {
    private NetworkParameters params;
    private int[] seedAddrs;
    private int pnseedIndex;

    /**
     * Supports finding peers by IP addresses
     *
     * @param params Network parameters to be used for port information.
     */
    public SeedPeers(NetworkParameters params) {
        this(params.getAddrSeeds(), params);
    }

    /**
     * Supports finding peers by IP addresses
     *
     * @param seedAddrs IP addresses for seed addresses.
     * @param params Network parameters to be used for port information.
     */
    public SeedPeers(int[] seedAddrs, NetworkParameters params) {
        this.seedAddrs = seedAddrs;
        this.params = params;
    }

    /**
     * Acts as an iterator, returning the address of each node in the list sequentially.
     * Once all the list has been iterated, null will be returned for each subsequent query.
     *
     * @return InetSocketAddress - The address/port of the next node.
     * @throws PeerDiscoveryException
     */
    @Nullable
    public InetSocketAddress getPeer() throws PeerDiscoveryException {
        try {
            return nextPeer();
        } catch (UnknownHostException e) {
            throw new PeerDiscoveryException(e);
        }
    }

    @Nullable
    private InetSocketAddress nextPeer() throws UnknownHostException, PeerDiscoveryException {
        if (seedAddrs == null || seedAddrs.length == 0)
            throw new PeerDiscoveryException("No IP address seeds configured; unable to find any peers");

        if (pnseedIndex >= seedAddrs.length) return null;
        return new InetSocketAddress(convertAddress(seedAddrs[pnseedIndex++]),
                params.getPort());
    }

    /**
     * Returns all the Bitcoin nodes within the list.
     */
    @Override
    public List<InetSocketAddress> getPeers(long services, long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        if (services != 0)
            throw new PeerDiscoveryException("Pre-determined peers cannot be filtered by services: " + services);
        try {
            return allPeers();
        } catch (UnknownHostException e) {
            throw new PeerDiscoveryException(e);
        }
    }

    private List<InetSocketAddress> allPeers() throws UnknownHostException {
        List<InetSocketAddress> addresses = new ArrayList<>(seedAddrs.length);
        for (int seedAddr : seedAddrs) {
            addresses.add(new InetSocketAddress(convertAddress(seedAddr), params.getPort()));
        }
        return addresses;
    }

    private InetAddress convertAddress(int seed) throws UnknownHostException {
        byte[] v4addr = new byte[4];
        ByteUtils.uint32ToByteArrayLE(seed, v4addr, 0);
        return InetAddress.getByAddress(v4addr);
    }

    @Override
    public void shutdown() {
    }
}
