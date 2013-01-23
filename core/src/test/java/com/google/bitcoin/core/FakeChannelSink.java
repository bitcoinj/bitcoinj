package com.google.bitcoin.core;

import org.jboss.netty.channel.*;

import static org.jboss.netty.channel.Channels.fireChannelConnected;

public class FakeChannelSink extends AbstractChannelSink {
    
    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent event = (ChannelStateEvent) e;

            FakeChannel channel = (FakeChannel) event.getChannel();
            boolean offered = channel.events.offer(event);
            assert offered;

            ChannelFuture future = event.getFuture();
            ChannelState state = event.getState();
            Object value = event.getValue();
            switch (state) {
            case OPEN:
                if (Boolean.FALSE.equals(value)) {
                    channel.setClosed();
                }
                break;
            case BOUND:
                if (value != null) {
                    // Bind
                } else {
                    // Close
                }
                break;
            case CONNECTED:
                if (value != null) {
                    future.setSuccess();
                    fireChannelConnected(channel, channel.getRemoteAddress());
                } else {
                    // Close
                }
                break;
            case INTEREST_OPS:
                // Unsupported - discard silently.
                future.setSuccess();
                break;
            }
        } else if (e instanceof MessageEvent) {
            MessageEvent event = (MessageEvent) e;
            FakeChannel channel = (FakeChannel) event.getChannel();
            boolean offered = channel.events.offer(event);
            assert offered;
            event.getFuture().setSuccess();
        }
    }
}
