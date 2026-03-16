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
import org.bitcoinj.core.Context;
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
import java.util.logging.Level;

/**
 * Prints a list of IP addresses obtained from DNS.
 */
public class PrintPeers {
    record PeerDnsResult(List<InetSocketAddress> dnsPeers, Duration duration) {}

    private static void printPeers(PeerDnsResult result) {
        for (InetSocketAddress address : result.dnsPeers()) {
            String hostAddress = address.getAddress().getHostAddress();
            System.out.println(String.format("%s:%d", hostAddress, address.getPort()));
        }
        System.out.println(String.format("DNS query took %.2f seconds", result.duration().toMillis() / 1000.0));
    }

    private static PeerDnsResult getPeers(Network network) throws PeerDiscoveryException {
        long start = System.currentTimeMillis();
        DnsDiscovery dns = new DnsDiscovery(network);
        List<InetSocketAddress> dnsPeers = dns.getPeers(0, Duration.ofSeconds(10));
        var duration = Duration.ofMillis(System.currentTimeMillis() - start);
        return new PeerDnsResult(dnsPeers, duration);
    }

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init(Level.WARNING);
        Context.propagate(new Context());
        final Network network = BitcoinNetwork.MAINNET;
        final NetworkParameters params = NetworkParameters.of(network);
        System.out.println("=== DNS ===");
        PeerDnsResult result = getPeers(network);
        printPeers(result);
        System.out.println("=== Version/chain heights ===");

        ArrayList<InetAddress> addrs = new ArrayList<>();
        for (InetSocketAddress peer : result.dnsPeers()) addrs.add(peer.getAddress());
        System.out.println("Scanning " + addrs.size() + " peers:");

        final Object lock = new Object();
        final long[] bestHeight = new long[1];

        List<CompletableFuture<Boolean>> futures = new ArrayList<>();
        NioClientManager clientManager = new NioClientManager();
        clientManager.start().join();
        for (final InetAddress addr : addrs) {
            InetSocketAddress address = new InetSocketAddress(addr, params.getPort());
            final Peer peer = new Peer(params, new VersionMessage(params, 0),
                    PeerAddress.simple(address), null);
            final CompletableFuture<Boolean> future = new CompletableFuture<>();
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
                future.complete(true);
                peer.close();
            });
            peer.addDisconnectedEventListener((p, peerCount) -> {
                if (!future.isDone()) {
                    System.out.println("Failed to talk to " + addr);
                    future.complete(false);
                }
            });
            clientManager.openConnection(address, peer);
            futures.add(future);
        }
        // Wait for every tried connection to finish.
        CompletableFuture.allOf(futures.toArray( new CompletableFuture[0])).join();
        int successful = futures.stream().mapToInt(f -> f.join() ? 1 : 0).sum();
        int total = futures.size();
        System.out.printf("Successfully talked to %d of %d nodes.\n", successful, total);
    }
}
