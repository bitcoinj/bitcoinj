/*
 * Copyright 2011 John Sample.
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

package org.bitcoinj.examples;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.VersionMessage;
import org.bitcoinj.net.NioClientManager;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.net.discovery.PeerDiscoveryException;
import org.bitcoinj.utils.BriefLogFormatter;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Prints a list of IP addresses obtained from DNS.
 */
public class PrintPeers {
    private static List<InetSocketAddress> dnsPeers;

    private static void printElapsed(long start) {
        long now = System.currentTimeMillis();
        System.out.println(String.format("Took %.2f seconds", (now - start) / 1000.0));
    }

    private static void printPeers(List<InetSocketAddress> addresses) {
        for (InetSocketAddress address : addresses) {
            String hostAddress = address.getAddress().getHostAddress();
            System.out.println(String.format("%s:%d", hostAddress, address.getPort()));
        }
    }

    private static void printDNS(Network network) throws PeerDiscoveryException {
        long start = System.currentTimeMillis();
        DnsDiscovery dns = new DnsDiscovery(network);
        dnsPeers = dns.getPeers(0, Duration.ofSeconds(10));
        printPeers(dnsPeers);
        printElapsed(start);
    }

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        final Network network = BitcoinNetwork.MAINNET;
        final NetworkParameters params = NetworkParameters.of(network);
        System.out.println("=== DNS ===");
        printDNS(network);
        System.out.println("=== Version/chain heights ===");

        ArrayList<InetAddress> addrs = new ArrayList<>();
        for (InetSocketAddress peer : dnsPeers) addrs.add(peer.getAddress());
        System.out.println("Scanning " + addrs.size() + " peers:");

        final Object lock = new Object();
        final long[] bestHeight = new long[1];

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        NioClientManager clientManager = new NioClientManager();
        for (final InetAddress addr : addrs) {
            InetSocketAddress address = new InetSocketAddress(addr, params.getPort());
            final Peer peer = new Peer(params, new VersionMessage(params, 0),
                    PeerAddress.simple(address), null);
            final CompletableFuture<Void> future = new CompletableFuture<>();
            // Once the connection has completed version handshaking ...
            peer.addConnectedEventListener((p, peerCount) -> {
                // Check the chain height it claims to have.
                VersionMessage ver = peer.getPeerVersionMessage();
                long nodeHeight = ver.bestHeight;
                synchronized (lock) {
                    long diff = bestHeight[0] - nodeHeight;
                    if (diff > 0) {
                        System.out.println("Node is behind by " + diff + " blocks: " + addr);
                    } else if (diff == 0) {
                        System.out.println("Node " + addr + " has " + nodeHeight + " blocks");
                        bestHeight[0] = nodeHeight;
                    } else if (diff < 0) {
                        System.out.println("Node is ahead by " + Math.abs(diff) + " blocks: " + addr);
                        bestHeight[0] = nodeHeight;
                    }
                }
                // Now finish the future and close the connection
                future.complete(null);
                peer.close();
            });
            peer.addDisconnectedEventListener((p, peerCount) -> {
                if (!future.isDone())
                    System.out.println("Failed to talk to " + addr);
                future.complete(null);
            });
            clientManager.openConnection(address, peer);
            futures.add(future);
        }
        // Wait for every tried connection to finish.
        CompletableFuture.allOf(futures.toArray( new CompletableFuture[0])).join();
    }
}
