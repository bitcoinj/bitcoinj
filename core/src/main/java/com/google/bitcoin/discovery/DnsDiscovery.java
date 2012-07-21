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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Set;

/**
 * Supports peer discovery through DNS.<p>
 *
 * This class does not support the testnet as currently there are no DNS servers providing testnet hosts.
 * If this class is being used for testnet you must specify the hostnames to use.<p>
 *
 * Failure to resolve individual host names will not cause an Exception to be thrown.
 * However, if all hosts passed fail to resolve a PeerDiscoveryException will be thrown during getPeers().
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

    public InetSocketAddress[] getPeers() throws PeerDiscoveryException {
        Set<InetSocketAddress> addresses = new HashSet<InetSocketAddress>();

        /*
         * Keep track of how many lookups failed vs. succeeded.
         * We'll throw an exception only if all the lookups fail.
         * We don't want to throw an exception if only one of many lookups fails.
         */
        int failedLookups = 0;

        for (String hostName : hostNames) {
            try {
                InetAddress[] hostAddresses = InetAddress.getAllByName(hostName);

                for (InetAddress inetAddress : hostAddresses) {
                    // DNS isn't going to provide us with the port.
                    // Grab the port from the specified NetworkParameters.
                    InetSocketAddress socketAddress = new InetSocketAddress(inetAddress, netParams.port);

                    // Only add the new address if it's not already in the combined list.
                    if (!addresses.contains(socketAddress)) {
                        addresses.add(socketAddress);
                    }
                }
            } catch (Exception e) {
                failedLookups++;
                log.info("DNS lookup for " + hostName + " failed.");

                if (failedLookups == hostNames.length) {
                    // All the lookups failed.
                    // Throw the discovery exception and include the last inner exception.
                    throw new PeerDiscoveryException("DNS resolution for all hosts failed.", e);
                }
            }
        }
        return addresses.toArray(new InetSocketAddress[]{});
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
