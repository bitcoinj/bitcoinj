/**
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
package com.google.bitcoin.net.discovery;

import com.google.bitcoin.core.NetworkParameters;
import com.google.common.base.Charsets;

import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

/**
 * SeedPeers contains a pre-determined list of Bitcoin node addresses. These nodes are selected based on being
 * active on the network for a long period of time. The intention is to be a last resort way of finding a connection
 * to the network, in case IRC and DNS fail. The list is stored in the resource file named <code>resourceFileName</code>.
 */
public class SeedPeers implements PeerDiscovery {
    private NetworkParameters params;
    private InetSocketAddress[] allPeers = null;
    private BufferedReader peerFileReader;
    private static final String resourceFileName = "seeds.txt";
    private static final int expectedNumberSeeds = 198552;  // Number of expected seeds in "seeds.txt"

    public SeedPeers(NetworkParameters params) {
        this.params = params;
        InputStream is = this.getClass().getResourceAsStream(resourceFileName);
        InputStreamReader isr = new InputStreamReader(is, Charsets.UTF_8);
        this.peerFileReader = new BufferedReader(isr);
        try {
            this.peerFileReader.readLine(); // Read and discard header line
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Acts as an iterator, returning the address of each node in the list sequentially.
     * Once all the list has been iterated, null will be returned for each subsequent query.
     *
     * @return InetSocketAddress - The address/port of the next node.
     * @deprecated - As far as I know this was only used in the unit test and can be removed.
     * @throws PeerDiscoveryException
     */
    @Nullable
    protected InetSocketAddress getPeer() throws PeerDiscoveryException {
        try {
            return nextPeer();
        } catch (UnknownHostException e) {
            throw new PeerDiscoveryException(e);
        }
    }

    /**
     * When getPeer is removed, this should probably be merged inside the loop in allPeers and eliminated.
     * @return
     * @deprecated
     * @throws UnknownHostException
     */
    @Nullable
    private InetSocketAddress nextPeer() throws UnknownHostException {
        try {
            String line = peerFileReader.readLine();
            if (line != null) {
                String address = line.substring(0,line.indexOf(':'));   // Get IPv4 or IPv6 address, but not port
                return new InetSocketAddress(address, params.getPort());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Returns an array containing all the Bitcoin nodes within the list.
     * This is the only method in the <code>PeerDiscovery</code> interface that returns peer data.
     */
    @Override
    public InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        try {
            return allPeers();
        } catch (UnknownHostException e) {
            throw new PeerDiscoveryException(e);
        }
    }

    private InetSocketAddress[] allPeers() throws UnknownHostException, PeerDiscoveryException {
        if (allPeers == null) {
            ArrayList<InetSocketAddress> addressList = new ArrayList<InetSocketAddress>(expectedNumberSeeds);
            InetSocketAddress peer;
            while ((peer = nextPeer()) != null) {
                addressList.add(peer);
            }
            InetSocketAddress[] addresses = new InetSocketAddress[addressList.size()];
            allPeers = addressList.toArray(addresses);
        }
        return allPeers;
    }

    public void shutdown() {
        allPeers = null;    // Free up some memory
    }
}
