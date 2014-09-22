/*
 * Copyright 2013 Matt Corallo
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

import com.google.bitcoin.core.*;
import com.google.bitcoin.params.UnitTestParams;
import org.junit.Test;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Random;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class PeerDBDiscoveryTest {
    NetworkParameters params = UnitTestParams.get();
    PeerEventListener listener;
    @Test
    public void fillAndSerializeTest() throws Exception {
        File tempFile = File.createTempFile("unittest.", ".peerdb");
        tempFile.deleteOnExit();

        PeerGroup peerGroup = new PeerGroup(params) {
            @Override
            public void addEventListener(PeerEventListener newListener) {
                listener = newListener;
            }
        };
        PeerDBDiscovery discovery = new PeerDBDiscovery(params, tempFile, peerGroup);
        Peer[] peers = new Peer[3];
        for (int i = 1; i <= peers.length; i++) {
            peers[i-1] = new Peer(params, new VersionMessage(params, 1), null, new PeerAddress(new InetSocketAddress("142.56.45." + i, 10)));
        }
        Random r = new Random(Utils.now().getTime());
        // Add 4*the maximum number of IPs stored per source from each peer (in the same source group)
        for (Peer peer : peers) {
            for (int i = 0; i < PeerDBDiscovery.SETS_PER_SOURCE * PeerDBDiscovery.MAX_SET_SIZE * 4 / AddressMessage.MAX_ADDRESSES; i++) {
                AddressMessage message = new AddressMessage(params);
                for (int j = 0; j < AddressMessage.MAX_ADDRESSES; j++) {
                    byte[] ip = new byte[16];
                    Utils.uint64ToByteArrayLE(j*i, ip, 0);
                    //Utils.uint64ToByteArrayLE(r.nextLong(), ip, 0);
                    //Utils.uint64ToByteArrayLE(r.nextLong(), ip, 8);
                    message.addAddress(new PeerAddress(new InetSocketAddress(InetAddress.getByAddress(ip), 42)));
                }
                listener.onPreMessageReceived(peer, message);
            }
        }
        int bucketsWithEntries = 0;
        for (PeerDBDiscovery.AddressSet set : discovery.addressBuckets) {
            // p(set.size() > 0 && set.size() < MAX_SET_SIZE) is negligible
            assertTrue(set.size() == 0 || set.size() == PeerDBDiscovery.MAX_SET_SIZE);
            if (set.size() == PeerDBDiscovery.MAX_SET_SIZE)
                bucketsWithEntries++;
        }
        // p(bucketsWithEntries < SETS_PER_SOURCE) == 0.38
        assertTrue(PeerDBDiscovery.SETS_PER_SOURCE >= bucketsWithEntries);

        discovery.shutdown();

        PeerDBDiscovery reloadedDiscovery = new PeerDBDiscovery(params, tempFile, peerGroup);
        assertEquals(PeerDBDiscovery.TOTAL_SETS, discovery.addressBuckets.size());
        assertEquals(PeerDBDiscovery.TOTAL_SETS, reloadedDiscovery.addressBuckets.size());
        for (int i = 0; i < PeerDBDiscovery.TOTAL_SETS; i++) {
            PeerDBDiscovery.AddressSet set = discovery.addressBuckets.get(i);
            PeerDBDiscovery.AddressSet reloadedSet = reloadedDiscovery.addressBuckets.get(i);
            assertEquals(set.size(), reloadedSet.size());
            for (PeerDBDiscovery.PeerData peer : set) {
                PeerDBDiscovery.PeerData reloadedPeer = reloadedDiscovery.addressToSetMap.get(peer.address.getAddr());
                assertEquals(peer, reloadedPeer);
                assertTrue(reloadedSet.contains(reloadedPeer));
                assertEquals(peer.lastConnected, reloadedPeer.lastConnected);
                assertEquals(peer.triedSinceLastConnection, reloadedPeer.triedSinceLastConnection);
                assertEquals(peer.vTimeLastHeard, reloadedPeer.vTimeLastHeard);
            }
        }
    }
}
