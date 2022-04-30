/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.testing;

import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.Message;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerSocketHandler;
import org.bitcoinj.core.Ping;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;

/**
 * An extension of {@link PeerSocketHandler} that keeps inbound messages in a queue for later processing
 */
public abstract class InboundMessageQueuer extends PeerSocketHandler {
    public final BlockingQueue<Message> inboundMessages = new ArrayBlockingQueue<>(1000);
    public final Map<Long, CompletableFuture<Void>> mapPingFutures = new HashMap<>();

    public Peer peer;
    public BloomFilter lastReceivedFilter;

    protected InboundMessageQueuer(NetworkParameters params) {
        super(params, new InetSocketAddress(InetAddress.getLoopbackAddress(), 2000));
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
            CompletableFuture<Void> future = mapPingFutures.get(((Ping) m).getNonce());
            if (future != null) {
                future.complete(null);
                return;
            }
        }
        if (m instanceof BloomFilter) {
            lastReceivedFilter = (BloomFilter) m;
        }
        inboundMessages.offer(m);
    }
}
