/*
 * Copyright 2011 Google Inc.
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

import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.MemoryBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import org.easymock.EasyMock;
import org.easymock.IMocksControl;
import org.jboss.netty.channel.*;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;

import static org.easymock.EasyMock.createStrictControl;
import static org.easymock.EasyMock.expect;

/**
 * Utility class that makes it easy to work with mock NetworkConnections.
 */
public class TestWithNetworkConnections {
    protected IMocksControl control;
    protected NetworkParameters unitTestParams;
    protected BlockStore blockStore;
    protected BlockChain blockChain;
    protected Wallet wallet;
    protected ECKey key;
    protected Address address;
    private static int fakePort;
    protected ChannelHandlerContext ctx;
    protected Channel channel;
    protected SocketAddress socketAddress;
    protected ChannelPipeline pipeline;
    
    public void setUp() throws Exception {
        setUp(new MemoryBlockStore(UnitTestParams.get()));
    }
    
    public void setUp(BlockStore blockStore) throws Exception {
        BriefLogFormatter.init();

        control = createStrictControl();
        control.checkOrder(false);

        unitTestParams = UnitTestParams.get();
        Wallet.SendRequest.DEFAULT_FEE_PER_KB = BigInteger.ZERO;
        this.blockStore = blockStore;
        wallet = new Wallet(unitTestParams);
        key = new ECKey();
        address = key.toAddress(unitTestParams);
        wallet.addKey(key);
        blockChain = new BlockChain(unitTestParams, wallet, blockStore);

        socketAddress = new InetSocketAddress("127.0.0.1", 1111);

        ctx = createChannelHandlerContext();
        channel = createChannel();
        pipeline = createPipeline(channel);
    }

    public void tearDown() throws Exception {
        Wallet.SendRequest.DEFAULT_FEE_PER_KB = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;
    }

    protected ChannelPipeline createPipeline(Channel channel) {
        ChannelPipeline pipeline = control.createMock(ChannelPipeline.class);
        expect(channel.getPipeline()).andStubReturn(pipeline);
        return pipeline;
    }

    protected Channel createChannel() {
        Channel channel = control.createMock(Channel.class);
        expect(channel.getRemoteAddress()).andStubReturn(socketAddress);
        return channel;
    }

    protected ChannelHandlerContext createChannelHandlerContext() {
        ChannelHandlerContext ctx1 = control.createMock(ChannelHandlerContext.class);
        ctx1.sendDownstream(EasyMock.anyObject(ChannelEvent.class));
        EasyMock.expectLastCall().anyTimes();
        ctx1.sendUpstream(EasyMock.anyObject(ChannelEvent.class));
        EasyMock.expectLastCall().anyTimes();
        return ctx1;
    }

    protected MockNetworkConnection createMockNetworkConnection() {
        MockNetworkConnection conn = new MockNetworkConnection();
        try {
            conn.connect(new PeerAddress(InetAddress.getLocalHost(), fakePort++), 0);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e); // Cannot happen
        }
        return conn;
    }

    protected void closePeer(Peer peer) throws Exception {
        peer.getHandler().channelClosed(ctx,
                new UpstreamChannelStateEvent(channel, ChannelState.CONNECTED, null));
    }
    
    protected void inbound(Peer peer, Message message) throws Exception {
        peer.getHandler().messageReceived(ctx,
                new UpstreamMessageEvent(channel, message, socketAddress));
    }

    protected void inbound(FakeChannel peerChannel, Message message) {
        Channels.fireMessageReceived(peerChannel, message);
    }

    protected Object outbound(FakeChannel p1) {
        ChannelEvent channelEvent = p1.nextEvent();
        if (channelEvent != null && !(channelEvent instanceof MessageEvent))
            throw new IllegalStateException("Expected message but got: " + channelEvent);
        MessageEvent nextEvent = (MessageEvent) channelEvent;
        if (nextEvent == null)
            return null;
        return nextEvent.getMessage();
    }

    protected Object waitForOutbound(FakeChannel ch) throws InterruptedException {
        return ((MessageEvent)ch.nextEventBlocking()).getMessage();
    }

    protected Peer peerOf(Channel ch) {
        return PeerGroup.peerFromChannel(ch);
    }
}
