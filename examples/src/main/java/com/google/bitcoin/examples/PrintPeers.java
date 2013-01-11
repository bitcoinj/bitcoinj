/**
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

package com.google.bitcoin.examples;

import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.TCPNetworkConnection;
import com.google.bitcoin.core.VersionMessage;
import com.google.bitcoin.discovery.DnsDiscovery;
import com.google.bitcoin.discovery.IrcDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Prints a list of IP addresses connected to the rendezvous point on the LFnet IRC channel.
 */
public class PrintPeers {
    private static InetSocketAddress[] dnsPeers, ircPeers;

    private static void printElapsed(long start) {
        long now = System.currentTimeMillis();
        System.out.println(String.format("Took %.2f seconds", (now - start) / 1000.0));
    }

    private static void printPeers(InetSocketAddress[] addresses) {
        for (InetSocketAddress address : addresses) {
            String hostAddress = address.getAddress().getHostAddress();
            System.out.println(String.format("%s:%d", hostAddress.toString(), address.getPort()));
        }
    }

    private static void printIRC() throws PeerDiscoveryException {
        long start = System.currentTimeMillis();
        IrcDiscovery d = new IrcDiscovery("#bitcoinTEST3") {
            @Override
            protected void onIRCReceive(String message) {
                System.out.println("<- " + message);
            }

            @Override
            protected void onIRCSend(String message) {
                System.out.println("-> " + message);
            }
        };
        ircPeers = d.getPeers(10, TimeUnit.SECONDS);
        printPeers(ircPeers);
        printElapsed(start);
    }

    private static void printDNS() throws PeerDiscoveryException {
        long start = System.currentTimeMillis();
        DnsDiscovery dns = new DnsDiscovery(NetworkParameters.prodNet());
        dnsPeers = dns.getPeers(10, TimeUnit.SECONDS);
        printPeers(dnsPeers);
        printElapsed(start);
    }

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        System.out.println("=== IRC ===");
        printIRC();
        System.out.println("=== DNS ===");
        printDNS();
        System.out.println("=== Version/chain heights ===");

        ArrayList<InetAddress> addrs = new ArrayList<InetAddress>();
        for (InetSocketAddress peer : dnsPeers) addrs.add(peer.getAddress());
        for (InetSocketAddress peer : ircPeers) addrs.add(peer.getAddress());
        System.out.println("Scanning " + addrs.size() + " peers:");

        final NetworkParameters params = NetworkParameters.prodNet();
        final Object lock = new Object();
        final long[] bestHeight = new long[1];

        List<ListenableFuture<TCPNetworkConnection>> futures = Lists.newArrayList();
        for (final InetAddress addr : addrs) {
            final ListenableFuture<TCPNetworkConnection> future =
                    TCPNetworkConnection.connectTo(params, new InetSocketAddress(addr, params.port), 1000 /* timeout */);
            futures.add(future);
            // Once the connection has completed version handshaking ...
            Futures.addCallback(future, new FutureCallback<TCPNetworkConnection>() {
                public void onSuccess(TCPNetworkConnection conn) {
                    // Check the chain height it claims to have.
                    VersionMessage ver = conn.getVersionMessage();
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
                    conn.close();
                }

                public void onFailure(Throwable throwable) {
                    System.out.println("Failed to talk to " + addr + ": " + throwable.getMessage());
                }
            });
        }
        // Wait for every tried connection to finish.
        Futures.successfulAsList(futures).get();
    }
}
