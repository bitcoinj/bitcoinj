/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.litecoinj.examples;

import org.litecoinj.core.*;
import org.litecoinj.net.discovery.DnsDiscovery;
import org.litecoinj.params.MainNetParams;
import org.litecoinj.params.TestNet3Params;
import org.litecoinj.store.BlockStore;
import org.litecoinj.store.MemoryBlockStore;
import org.litecoinj.utils.BriefLogFormatter;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.concurrent.Future;

/**
 * Downloads the block given a block hash from the localhost node and prints it out.
 */
public class FetchBlock {
    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        System.out.println("Connecting to node");
        final NetworkParameters netParams = MainNetParams.get();

        BlockStore blockStore = new MemoryBlockStore(netParams);
        BlockChain chain = new BlockChain(netParams, blockStore);
        PeerGroup peerGroup = new PeerGroup(netParams, chain);
        peerGroup.addPeerDiscovery(new DnsDiscovery(netParams));
        peerGroup.setUseLocalhostPeerWhenPossible(false);
        peerGroup.setMaxConnections(300);
        peerGroup.setMaxPeersToDiscoverCount(300);
        peerGroup.setMinBroadcastConnections(20);
        peerGroup.setFastCatchupTimeSecs(System.currentTimeMillis() / 1000);
        peerGroup.setConnectTimeoutMillis(2 * 60 * 1000);
        peerGroup.setStallThreshold(10, Block.HEADER_SIZE * 20);
        peerGroup.setUserAgent("BitRafael", "2.0.0");
        peerGroup.start();

        peerGroup.waitForPeers(1).get();
        Peer peer = peerGroup.getConnectedPeers().get(0);

        Sha256Hash blockHash = Sha256Hash.wrap("000000000000000000f9bd5d6a8e4ad2752df3f9073f0be52e1b068827ff9476");
        Future<Block> future = peer.getBlock(blockHash);
        System.out.println("Waiting for node to send us the requested block: " + blockHash);
        Block block = future.get();
        System.out.println(block);
        peerGroup.stopAsync();
    }
}
