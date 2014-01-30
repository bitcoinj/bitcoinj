package com.google.bitcoin.core;

import com.google.common.util.concurrent.SettableFuture;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * An extension of {@link PeerSocketHandler} that keeps inbound messages in a queue for later processing
 */
public abstract class InboundMessageQueuer extends PeerSocketHandler {
    final BlockingQueue<Message> inboundMessages = new ArrayBlockingQueue<Message>(1000);
    final Map<Long, SettableFuture<Void>> mapPingFutures = new HashMap<Long, SettableFuture<Void>>();

    public Peer peer;
    public BloomFilter lastReceivedFilter;

    protected InboundMessageQueuer(NetworkParameters params) {
        super(params, new InetSocketAddress("127.0.0.1", 2000));
    }

    public Message nextMessage() {
        return inboundMessages.poll();
    }

    public Message nextMessageBlocking() throws InterruptedException {
        return inboundMessages.take();
    }

    @Override
    protected void processMessage(Message m) throws Exception {
        if (m instanceof Ping) {
            SettableFuture<Void> future = mapPingFutures.get(((Ping)m).getNonce());
            if (future != null) {
                future.set(null);
                return;
            }
        }
        if (m instanceof BloomFilter) {
            lastReceivedFilter = (BloomFilter) m;
        }
        inboundMessages.offer(m);
    }
}
