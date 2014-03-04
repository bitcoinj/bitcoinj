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
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.params.TestNet3Params;
import com.google.bitcoin.params.UnitTestParams;
import com.google.common.net.InetAddresses;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

public class SeedPeersTest {
    private static HashMap<String, Integer> numEntries = null;  // Number of entries in address file
    private static ArrayList<NetworkParameters> networkList = null;

    @BeforeClass
    public static void setUpClass() {
        SeedPeersTest.numEntries = new HashMap<String, Integer>(3);
        SeedPeersTest.numEntries.put(NetworkParameters.ID_MAINNET, 600);    // 600 entries in this file
        SeedPeersTest.numEntries.put(NetworkParameters.ID_TESTNET, 25);     // 25 in this one
        SeedPeersTest.numEntries.put(NetworkParameters.ID_UNITTESTNET, 1);  // 1 entry (127.0.0.1, is that right?)
        SeedPeersTest.networkList = new ArrayList<NetworkParameters>(3);
        SeedPeersTest.networkList.add(MainNetParams.get());
        SeedPeersTest.networkList.add(TestNet3Params.get());
        SeedPeersTest.networkList.add(UnitTestParams.get());
    }

    @Before
    public void setUpTest() {
        SeedPeers.inputStreamOverride = null;
    }

    @Test
    public void getPeersCheckArrayInputStream() throws Exception {
        // Simulate Android Configuration
        String seedsSuffix = "-seeds.txt";
        // Test for all networks configured in SeedPeersTest.networkList
        for (NetworkParameters params : SeedPeersTest.networkList) {
            String path = params.getId() + seedsSuffix;
            String seedsFile = SeedPeers.class.getResource(path).getFile();
            SeedPeers.inputStreamOverride = new FileInputStream(seedsFile);
            SeedPeers seedPeers = new SeedPeers(params);
            InetSocketAddress[] addresses = seedPeers.getPeers(0, TimeUnit.SECONDS);
            assertThat(addresses, notNullValue());
            assertThat(addresses.length, equalTo( SeedPeersTest.numEntries.get(params.getId()) ));
            for (InetSocketAddress address : addresses) {
                assertThat("Port should match params", address.getPort(), equalTo(params.getPort()));
                assertThat("Should be IP address not hostname", InetAddresses.isInetAddress(address.getHostString()), equalTo(true));
            }
        }
    }

    /**
     * Test getPeers() - the only method defined in the PeerDiscovery interface that returns peers.
     * Test it for ID_MAINNET, ID_TESTNET, and ID_UNITTESTNET
     * Make sure it returns the expected number of addresses for each case (test needs to be updated if numbers change)
     * @throws Exception
     */
    @Test
    public void getPeersCheckArray() throws Exception {
        // Test for all networks configured in SeedPeersTest.networkList
        for (NetworkParameters params : SeedPeersTest.networkList) {
            SeedPeers seedPeers = new SeedPeers(params);
            InetSocketAddress[] addresses = seedPeers.getPeers(0, TimeUnit.SECONDS);
            assertThat(addresses, notNullValue());
            assertThat(addresses.length, equalTo( SeedPeersTest.numEntries.get(params.getId()) ));
            for (InetSocketAddress address : addresses) {
                assertThat("Port should match params", address.getPort(), equalTo(params.getPort()));
                assertThat("Should be IP address not hostname", InetAddresses.isInetAddress(address.getHostString()), equalTo(true));
            }
        }
    }
}
