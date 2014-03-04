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

import java.io.*;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

/**
 * SeedPeers contains a pre-determined list of Bitcoin node addresses. These nodes are selected based on being
 * active on the network for a long period of time. The intention is to be a last resort way of finding a connection
 * to the network, in case IRC and DNS fail.
 * <p>
 * In the current implementation, the list is stored in a file with the suffix <code>resourceFileSuffix</code>.
 * The basename of the file is the result of calling <code>getId()</code> for <code<NetworkParameters</code>.
 * This file will be stored in a resource in the same package as this class, except on Android which doesn't allow this.
 * On Android you should set <code>inputStreamOverride</code> with an InputStream from inside the <code>.apk</code> file.
 * <p>
 * The file is a text file containing string-formatted ipv4 and/or ipv6 addresses, one-per-line.
 */
public class SeedPeers implements PeerDiscovery {
    /**
     * To override loading seeds.txt from a resource file, set this InputStream.
     */
    public static InputStream inputStreamOverride = null;
    private static final String resourceFileSuffix = "-seeds.txt";
    private static final int expectedNumberSeeds = 600;  // Number of expected seeds in stream (initial array size)
    private NetworkParameters params;
    private InetSocketAddress[] allPeers = null;
    private BufferedReader peerFileReader;

    /**
     * Private constructor that could be made public if we want to allow using an arbitrary InputStream
     * as a source for Peer IP addresses.
     * @param seedInput
     * @param params
     */
    private SeedPeers(InputStream seedInput, NetworkParameters params) {
        InputStreamReader isr = new InputStreamReader(seedInput, Charsets.UTF_8);
        this.peerFileReader = new BufferedReader(isr);
        this.params = params;
    }

    /**
     * Construct a list of SeedPeers from a resource file based on NetworkParameters id field.
     * static member <code>inputStreamOverride</code> can be used to override behavior and set
     * an input stream explicitly for Android or other platforms that don't support JAR resources.
     * @param params
     * @throws FileNotFoundException
     */
    public SeedPeers(NetworkParameters params) throws FileNotFoundException {
        this((inputStreamOverride == null) ?
                SeedPeers.class.getResourceAsStream(params.getId() + resourceFileSuffix) :
                inputStreamOverride,
                params);
    }

    /**
     * Returns an array containing all the Bitcoin nodes within the list.
     * This is the only method in the <code>PeerDiscovery</code> interface that returns peer data.
     * @param timeoutValue ignored, we're assuming file is small enough that time to read is approx zero
     * @param timeoutUnit also ignored
     * @return array containing IP addresses of all the peers in the seed address file
     * @throws PeerDiscoveryException
     */
    @Override
    public InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        try {
            if (allPeers == null) {
                allPeers = loadAllPeers();
            }
            return allPeers;
        } catch (UnknownHostException e) {
            throw new PeerDiscoveryException(e);
        }
    }

    /**
     * Return an array of InetSocketAddress containing Peer addresses
     * @return
     * @throws UnknownHostException
     * @throws PeerDiscoveryException
     */
    private InetSocketAddress[] loadAllPeers() throws UnknownHostException, PeerDiscoveryException {
        ArrayList<InetSocketAddress> addressList = new ArrayList<InetSocketAddress>(expectedNumberSeeds);

        try {
            String line;
            while ((line = peerFileReader.readLine()) != null) {
                InetSocketAddress sockAddr;
                // Use port from params
                sockAddr = new InetSocketAddress(line, params.getPort());
                // Add address to list
                addressList.add(sockAddr);
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new PeerDiscoveryException(e);
        }

        InetSocketAddress[] addresses = new InetSocketAddress[addressList.size()];
        return addressList.toArray(addresses);
    }

    public void shutdown() {
        allPeers = null;    // Free up some memory
    }
}
