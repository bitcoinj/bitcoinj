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

import com.google.bitcoin.core.NetworkConnection;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.TCPNetworkConnection;
import com.google.bitcoin.discovery.DnsDiscovery;
import com.google.bitcoin.discovery.IrcDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.concurrent.*;

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
        IrcDiscovery d = new IrcDiscovery("#bitcoin") {
            @Override
            protected void onIRCReceive(String message) {
                System.out.println("<- " + message);
            }

            @Override
            protected void onIRCSend(String message) {
                System.out.println("-> " + message);
            }
        };
        ircPeers = d.getPeers();
        printPeers(ircPeers);
        printElapsed(start);
    }

    private static void printDNS() throws PeerDiscoveryException {
        long start = System.currentTimeMillis();
        DnsDiscovery dns = new DnsDiscovery(NetworkParameters.prodNet());
        dnsPeers = dns.getPeers();
        printPeers(dnsPeers);
        printElapsed(start);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== IRC ===");
        printIRC();
        System.out.println("=== DNS ===");
        printDNS();
        System.out.println("=== Version/chain heights ===");

        ExecutorService pool = Executors.newFixedThreadPool(100);
        ArrayList<InetAddress> addrs = new ArrayList<InetAddress>();
        for (InetSocketAddress peer : dnsPeers) addrs.add(peer.getAddress());
        for (InetSocketAddress peer : ircPeers) addrs.add(peer.getAddress());
        System.out.println("Scanning " + addrs.size() + " peers:");

        final Object lock = new Object();
        final long[] bestHeight = new long[1];

        for (final InetAddress addr : addrs) {
            pool.submit(new Runnable() {
                public void run() {
                    try {
                        NetworkConnection conn = new TCPNetworkConnection(addr,
                                NetworkParameters.prodNet(), 0, 1000);
                        synchronized (lock) {
                            long nodeHeight = conn.getVersionMessage().bestHeight;
                            long diff = bestHeight[0] - nodeHeight;
                            if (diff > 0) {
                                System.out.println("Node is behind by " + diff + " blocks: " + addr.toString());
                            } else {
                                bestHeight[0] = nodeHeight;
                            }
                        }
                        conn.shutdown();
                    } catch (Exception e) {
                    }
                }
            });
        }
        pool.awaitTermination(3600 * 24, TimeUnit.SECONDS); // 1 Day
    }
}
