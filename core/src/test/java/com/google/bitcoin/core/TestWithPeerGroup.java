package com.google.bitcoin.core;

import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;

import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.junit.Before;

import com.google.bitcoin.store.BlockStore;

/**
 * Utility class that makes it easy to work with mock NetworkConnections in PeerGroups.
 */
public class TestWithPeerGroup extends TestWithNetworkConnections {
    protected PeerGroup peerGroup;

    protected VersionMessage remoteVersionMessage;

    public void setUp(BlockStore blockStore) throws Exception {
        super.setUp(blockStore);

        remoteVersionMessage = new VersionMessage(unitTestParams, 1);
        
        ClientBootstrap bootstrap = new ClientBootstrap(new ChannelFactory() {
            public void releaseExternalResources() {}
            public Channel newChannel(ChannelPipeline pipeline) {
                ChannelSink sink = new FakeChannelSink();
                return new FakeChannel(this, pipeline, sink);
            }
        });
        bootstrap.setPipelineFactory(new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                VersionMessage ver = new VersionMessage(unitTestParams, 1);
                ChannelPipeline p = Channels.pipeline();
                
                Peer peer = new Peer(unitTestParams, blockChain, ver);
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
        return p;
    }
}
