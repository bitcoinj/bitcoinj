package com.google.bitcoin.core;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.BlockingQueue;

import org.jboss.netty.channel.*;
import org.jboss.netty.util.internal.QueueFactory;

public class FakeChannel extends AbstractChannel {
    final BlockingQueue<ChannelEvent> events = QueueFactory.createQueue(ChannelEvent.class);

    private final ChannelConfig config;
    private SocketAddress localAddress;
    private SocketAddress remoteAddress;

    protected FakeChannel(ChannelFactory factory,
            ChannelPipeline pipeline, ChannelSink sink) {
        super(null, factory, pipeline, sink);
        config = new DefaultChannelConfig();
        localAddress = new InetSocketAddress("127.0.0.1", 2000);
    }

    public ChannelConfig getConfig() {
        return config;
    }

    public SocketAddress getLocalAddress() {
        return localAddress;
    }

    public SocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    @Override
    public ChannelFuture connect(SocketAddress remoteAddress) {
        this.remoteAddress = remoteAddress;
        return super.connect(remoteAddress);
    }
    
    public boolean isBound() {
        return true;
    }

    public boolean isConnected() {
        return true;
    }


    public ChannelEvent nextEvent() {
        return events.poll();
    }
}
