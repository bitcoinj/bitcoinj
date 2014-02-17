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

import com.google.bitcoin.params.MainNetParams;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

public class SeedPeersTest {
    private static final int numRecordsInResourceFile = 198552;  // Number of lines (minus header) in "seeds.txt"

    /**
     * Test single invocation of public (but not in the PeerDiscovery interface) getPeer() method.
     * @throws Exception
     */
    @Test
    public void getPeer_one() throws Exception{
        SeedPeers seedPeers = new SeedPeers(MainNetParams.get());
        assertThat(seedPeers.getPeer(), notNullValue());
    }

    /**
     * Call getPeer() once for every line in the resource file with no errors,
     * then call it one more time and make sure we get a null.
     * @throws Exception
     */
    @Test
    public void getPeer_all() throws Exception{
        SeedPeers seedPeers = new SeedPeers(MainNetParams.get());
        for(int i = 0; i < numRecordsInResourceFile; ++i){
            assertThat("Failed on index: "+i, seedPeers.getPeer(), notNullValue());
        }
        assertThat(seedPeers.getPeer(), equalTo(null));
    }

    /**
     * Call getPeers() - the only method defined in the PeerDiscovery interface that returns peers.
     * Make sure it returns the expected number of addresses.
     * @throws Exception
     */
    @Test
    public void getPeers_length() throws Exception{
        SeedPeers seedPeers = new SeedPeers(MainNetParams.get());
        InetSocketAddress[] addresses = seedPeers.getPeers(0, TimeUnit.SECONDS);
        assertThat(addresses.length, equalTo(numRecordsInResourceFile));
    }
}
