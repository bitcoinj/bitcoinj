/*
 * Copyright 2012 Matt Corallo.
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

package com.google.bitcoin.core;

import com.google.bitcoin.store.BlockStore;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.channel.*;

import java.net.InetSocketAddress;

import static org.junit.Assert.assertTrue;

/**
 * Utility class that makes it easy to work with mock NetworkConnections in PeerGroups.
 */
public class TestWithPeerGroup extends TestWithNetworkConnections {
    protected PeerGroup peerGroup;

    protected VersionMessage remoteVersionMessage;

    public void setUp(BlockStore blockStore) throws Exception {
        super.setUp(blockStore);

        remoteVersionMessage = new VersionMessage(unitTestParams, 1);
        remoteVersionMessage.clientVersion = FilteredBlock.MIN_PROTOCOL_VERSION;
        
        ClientBootstrap bootstrap = new ClientBootstrap(new ChannelFactory() {
            public void releaseExternalResources() {}
            public Channel newChannel(ChannelPipeline pipeline) {
                ChannelSink sink = new FakeChannelSink();
                return new FakeChannel(this, pipeline, sink);
            }
            public void shutdown() {}
        });
        bootstrap.setPipelineFactory(new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                VersionMessage ver = new VersionMessage(unitTestParams, 1);
                ChannelPipeline p = Channels.pipeline();
                
                Peer peer = new Peer(unitTestParams, blockChain, ver, peerGroup.getMemoryPool());
                peer.addLifecycleListener(peerGroup.startupListener);
                p.addLast("peer", peer.getHandler());
                return p;
            }

        });
        peerGroup = new PeerGroup(unitTestParams, blockChain, bootstrap);
        peerGroup.setPingIntervalMsec(0);  // Disable the pings as they just get in the way of most tests.
    }
    
    protected FakeChannel connectPeer(int id) {
        return connectPeer(id, remoteVersionMessage);
    }

    protected FakeChannel connectPeer(int id, VersionMessage versionMessage) {
        InetSocketAddress remoteAddress = new InetSocketAddress("127.0.0.1", 2000 + id);
        FakeChannel p = (FakeChannel) peerGroup.connectTo(remoteAddress).getChannel();
        assertTrue(p.nextEvent() instanceof ChannelStateEvent);
        inbound(p, versionMessage);
        if (versionMessage.isBloomFilteringSupported()) {
            assertTrue(outbound(p) instanceof BloomFilter);
            assertTrue(outbound(p) instanceof MemoryPoolMessage);
        }
        return p;
    }
}
