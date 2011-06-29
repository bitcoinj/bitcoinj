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

import java.net.InetSocketAddress;

import com.google.bitcoin.core.*;
import com.google.bitcoin.discovery.DnsDiscovery;
import com.google.bitcoin.discovery.IrcDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;

/**
 * Prints a list of IP addresses connected to the rendezvous point on the LFnet IRC channel.
 */
public class PrintPeers {
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
        printPeers(d.getPeers());
        printElapsed(start);
    }

    private static void printDNS() throws PeerDiscoveryException {
        long start = System.currentTimeMillis();
        DnsDiscovery dns = new DnsDiscovery(NetworkParameters.prodNet());
        printPeers(dns.getPeers());
        printElapsed(start);
    }

    public static void main(String[] args) throws PeerDiscoveryException {
        System.out.println("=== IRC ===");
        printIRC();
        System.out.println("=== DNS ===");
        printDNS();
    }
}
