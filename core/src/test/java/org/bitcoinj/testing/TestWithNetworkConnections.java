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

package org.bitcoinj.testing;

import org.bitcoinj.core.listeners.PeerDisconnectedEventListener;
import org.bitcoinj.core.listeners.PreMessageReceivedEventListener;
import org.bitcoinj.core.*;
import org.bitcoinj.net.*;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;

import com.google.common.util.concurrent.SettableFuture;

import javax.annotation.Nullable;
import javax.net.SocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

/**
 * Utility class that makes it easy to work with mock NetworkConnections.
 */
public class TestWithNetworkConnections {
    public static final int PEER_SERVERS = 5;
    protected static final NetworkParameters PARAMS = UnitTestParams.get();
    protected Context context;
    protected BlockStore blockStore;
    protected BlockChain blockChain;
    protected Wallet wallet;
    protected ECKey key;
    protected Address address;
    protected SocketAddress socketAddress;

    private NioServer[] peerServers = new NioServer[PEER_SERVERS];
    private final ClientConnectionManager channels;
    protected final BlockingQueue<InboundMessageQueuer> newPeerWriteTargetQueue = new LinkedBlockingQueue<>();

    public enum ClientType {
        NIO_CLIENT_MANAGER,
        BLOCKING_CLIENT_MANAGER,
        NIO_CLIENT,
        BLOCKING_CLIENT
    }
    private final ClientType clientType;
    public TestWithNetworkConnections(ClientType clientType) {
        this.clientType = clientType;
        if (clientType == ClientType.NIO_CLIENT_MANAGER)
            channels = new NioClientManager();
        else if (clientType == ClientType.BLOCKING_CLIENT_MANAGER)
            channels = new BlockingClientManager();
        else
            channels = null;
    }

    public void setUp() throws Exception {
        setUp(new MemoryBlockStore(UnitTestParams.get()));
    }
    
    public void setUp(BlockStore blockStore) throws Exception {
        BriefLogFormatter.init();
        Context.propagate(new Context(PARAMS, 100, Coin.ZERO, false));
        this.blockStore = blockStore;
        // Allow subclasses to override the wallet object with their own.
        if (wallet == null) {
            wallet = new Wallet(PARAMS);
            key = wallet.freshReceiveKey();
            address = key.toAddress(PARAMS);
        }
        blockChain = new BlockChain(PARAMS, wallet, blockStore);

        startPeerServers();
        if (clientType == ClientType.NIO_CLIENT_MANAGER || clientType == ClientType.BLOCKING_CLIENT_MANAGER) {
            channels.startAsync();
            channels.awaitRunning();
        }

        socketAddress = new InetSocketAddress("127.0.0.1", 1111);
    }

    protected void startPeerServers() throws IOException {
        for (int i = 0 ; i < PEER_SERVERS ; i++) {
            startPeerServer(i);
        }
    }

    protected void startPeerServer(int i) throws IOException {
        peerServers[i] = new NioServer(new StreamConnectionFactory() {
            @Nullable
            @Override
            public StreamConnection getNewConnection(InetAddress inetAddress, int port) {
                return new InboundMessageQueuer(PARAMS) {
                    @Override
                    public void connectionClosed() {
                    }

                    @Override
                    public void connectionOpened() {
                        newPeerWriteTargetQueue.offer(this);
                    }
                };
            }
        }, new InetSocketAddress("127.0.0.1", 2000 + i));
        peerServers[i].startAsync();
        peerServers[i].awaitRunning();
    }

    public void tearDown() throws Exception {
        stopPeerServers();
    }

    protected void stopPeerServers() {
        for (int i = 0 ; i < PEER_SERVERS ; i++)
            stopPeerServer(i);
    }

    protected void stopPeerServer(int i) {
        peerServers[i].stopAsync();
        peerServers[i].awaitTerminated();
    }

    protected InboundMessageQueuer connect(Peer peer, VersionMessage versionMessage) throws Exception {
        checkArgument(versionMessage.hasBlockChain());
        final AtomicBoolean doneConnecting = new AtomicBoolean(false);
        final Thread thisThread = Thread.currentThread();
        peer.addDisconnectedEventListener(new PeerDisconnectedEventListener() {
            @Override
            public void onPeerDisconnected(Peer p, int peerCount) {
                synchronized (doneConnecting) {
                    if (!doneConnecting.get())
                        thisThread.interrupt();
                }
            }
        });
        if (clientType == ClientType.NIO_CLIENT_MANAGER || clientType == ClientType.BLOCKING_CLIENT_MANAGER)
            channels.openConnection(new InetSocketAddress("127.0.0.1", 2000), peer);
        else if (clientType == ClientType.NIO_CLIENT)
            new NioClient(new InetSocketAddress("127.0.0.1", 2000), peer, 100);
        else if (clientType == ClientType.BLOCKING_CLIENT)
            new BlockingClient(new InetSocketAddress("127.0.0.1", 2000), peer, 100, SocketFactory.getDefault(), null);
        else
            throw new RuntimeException();
        // Claim we are connected to a different IP that what we really are, so tx confidence broadcastBy sets work
        InboundMessageQueuer writeTarget = newPeerWriteTargetQueue.take();
        writeTarget.peer = peer;
        // Complete handshake with the peer - send/receive version(ack)s, receive bloom filter
        checkState(!peer.getVersionHandshakeFuture().isDone());
        writeTarget.sendMessage(versionMessage);
        writeTarget.sendMessage(new VersionAck());
        try {
            checkState(writeTarget.nextMessageBlocking() instanceof VersionMessage);
            checkState(writeTarget.nextMessageBlocking() instanceof VersionAck);
            peer.getVersionHandshakeFuture().get();
            synchronized (doneConnecting) {
                doneConnecting.set(true);
            }
            Thread.interrupted(); // Clear interrupted bit in case it was set before we got into the CS
        } catch (InterruptedException e) {
            // We were disconnected before we got back version/verack
        }
        return writeTarget;
    }

    protected void closePeer(Peer peer) throws Exception {
        peer.close();
    }

    protected void inbound(InboundMessageQueuer peerChannel, Message message) {
        peerChannel.sendMessage(message);
    }

    private void outboundPingAndWait(final InboundMessageQueuer p, long nonce) throws Exception {
        // Send a ping and wait for it to get to the other side
        SettableFuture<Void> pingReceivedFuture = SettableFuture.create();
        p.mapPingFutures.put(nonce, pingReceivedFuture);
        p.peer.sendMessage(new Ping(nonce));
        pingReceivedFuture.get();
        p.mapPingFutures.remove(nonce);
    }

    private void inboundPongAndWait(final InboundMessageQueuer p, final long nonce) throws Exception {
        // Receive a ping (that the Peer doesn't see) and wait for it to get through the socket
        final SettableFuture<Void> pongReceivedFuture = SettableFuture.create();
        PreMessageReceivedEventListener listener = new PreMessageReceivedEventListener() {
            @Override
            public Message onPreMessageReceived(Peer p, Message m) {
                if (m instanceof Pong && ((Pong) m).getNonce() == nonce) {
                    pongReceivedFuture.set(null);
                    return null;
                }
                return m;
            }
        };
        p.peer.addPreMessageReceivedEventListener(Threading.SAME_THREAD, listener);
        inbound(p, new Pong(nonce));
        pongReceivedFuture.get();
        p.peer.removePreMessageReceivedEventListener(listener);
    }

    protected void pingAndWait(final InboundMessageQueuer p) throws Exception {
        final long nonce = (long) (Math.random() * Long.MAX_VALUE);
        // Start with an inbound Pong as pingAndWait often happens immediately after an inbound() call, and then wants
        // to wait on an outbound message, so we do it in the same order or we see race conditions
        inboundPongAndWait(p, nonce);
        outboundPingAndWait(p, nonce);
    }

    protected Message outbound(InboundMessageQueuer p1) throws Exception {
        pingAndWait(p1);
        return p1.nextMessage();
    }

    protected Message waitForOutbound(InboundMessageQueuer ch) throws InterruptedException {
        return ch.nextMessageBlocking();
    }

    protected Peer peerOf(InboundMessageQueuer ch) {
        return ch.peer;
    }
}
