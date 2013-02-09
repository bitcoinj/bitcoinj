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

import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferInputStream;
import org.jboss.netty.buffer.ChannelBufferOutputStream;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.*;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
import org.jboss.netty.handler.codec.replay.VoidEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.jboss.netty.channel.Channels.write;

// TODO: Remove this class and refactor the way we build Netty pipelines.

/**
 * <p>A {@code TCPNetworkConnection} is used for connecting to a Bitcoin node over the standard TCP/IP protocol.<p>
 *
 * <p>{@link TCPNetworkConnection#getHandler()} is part of a Netty Pipeline, downstream of other pipeline stages.</p>
 *
 */
public class TCPNetworkConnection implements NetworkConnection {
    private static final Logger log = LoggerFactory.getLogger(TCPNetworkConnection.class);
    
    // The IP address to which we are connecting.
    private InetAddress remoteIp;
    private final NetworkParameters params;
    private VersionMessage versionMessage;

    private BitcoinSerializer serializer = null;

    private VersionMessage myVersionMessage;
    private Channel channel;
    
    private NetworkHandler handler;
    // For ping nonces.
    private Random random = new Random();

    /**
     * Construct a network connection with the given params and version. If you use this constructor you need to set
     * up the Netty pipelines and infrastructure yourself. If all you have is an IP address and port, use the static
     * connectTo method.
     *
     * @param params Defines which network to connect to and details of the protocol.
     * @param ver The VersionMessage to announce to the other side of the connection.
     */
    public TCPNetworkConnection(NetworkParameters params, VersionMessage ver) {
        this.params = params;
        this.myVersionMessage = ver;
        this.serializer = new BitcoinSerializer(this.params);
        this.handler = new NetworkHandler();
    }

    // Some members that are used for convenience APIs. If the app only uses PeerGroup then these won't be used.
    private static NioClientSocketChannelFactory channelFactory;
    private SettableFuture<TCPNetworkConnection> handshakeFuture;

    /**
     * Returns a future for a TCPNetworkConnection that is connected and version negotiated to the given remote address.
     * Behind the scenes this method sets up a thread pool and a Netty pipeline that uses it. The equivalent Netty code
     * is quite complex so use this method if you aren't writing a complex app. The future completes once version
     * handshaking is done, use .get() on the response to wait for it.
     *
     * @param params The network parameters to use (production or testnet)
     * @param address IP address and port to use
     * @param connectTimeoutMsec How long to wait before giving up and setting the future to failure.
     * @return
     */
    public static ListenableFuture<TCPNetworkConnection> connectTo(NetworkParameters params, InetSocketAddress address,
                                                                   int connectTimeoutMsec) {
        synchronized (TCPNetworkConnection.class) {
            if (channelFactory == null) {
                ExecutorService bossExecutor = Executors.newCachedThreadPool();
                ExecutorService workerExecutor = Executors.newCachedThreadPool();
                channelFactory = new NioClientSocketChannelFactory(bossExecutor, workerExecutor);
            }
        }
        // Run the connection in the thread pool and wait for it to complete.
        ClientBootstrap clientBootstrap = new ClientBootstrap(channelFactory);
        ChannelPipeline pipeline = Channels.pipeline();
        final TCPNetworkConnection conn = new TCPNetworkConnection(params, new VersionMessage(params, 0));
        conn.handshakeFuture = SettableFuture.create();
        pipeline.addLast("codec", conn.getHandler());
        clientBootstrap.setPipeline(pipeline);
        clientBootstrap.setOption("connectTimeoutMillis", Integer.valueOf(connectTimeoutMsec));
        ChannelFuture socketFuture = clientBootstrap.connect(address);
        // Once the socket is either connected on the TCP level, or failed ...
        socketFuture.addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture channelFuture) throws Exception {
                // Check if it failed ...
                if (channelFuture.isDone() && !channelFuture.isSuccess()) {
                    // And complete the returned future with an exception.
                    conn.handshakeFuture.setException(channelFuture.getCause());
                }
                // Otherwise the handshakeFuture will be marked as completed once we did ver/verack exchange.
            }
        });
        return conn.handshakeFuture;
    }

    public void writeMessage(Message message) throws IOException {
        write(channel, message);
    }

    private void onVersionMessage(Message m) throws IOException, ProtocolException {
        if (!(m instanceof VersionMessage)) {
            // Bad peers might not follow the protocol. This has been seen in the wild (issue 81).
            log.info("First message received was not a version message but rather " + m);
            return;
        }
        versionMessage = (VersionMessage) m;
        // Switch to the new protocol version.
        int peerVersion = versionMessage.clientVersion;
        log.info("Connected to peer: version={}, subVer='{}', services=0x{}, time={}, blocks={}", new Object[] {
                peerVersion,
                versionMessage.subVer,
                versionMessage.localServices,
                new Date(versionMessage.time * 1000),
                versionMessage.bestHeight
        });
        // Now it's our turn ...
        // Send an ACK message stating we accept the peers protocol version.
        write(channel, new VersionAck());
        // bitcoinj is a client mode implementation. That means there's not much point in us talking to other client
        // mode nodes because we can't download the data from them we need to find/verify transactions. Some bogus
        // implementations claim to have a block chain in their services field but then report a height of zero, filter
        // them out here.
        if (!versionMessage.hasBlockChain() ||
                (!params.allowEmptyPeerChains && versionMessage.bestHeight <= 0)) {
            // Shut down the channel
            throw new ProtocolException("Peer does not have a copy of the block chain.");
        }
        // Handshake is done!
        if (handshakeFuture != null)
            handshakeFuture.set(this);
    }

    public void ping() throws IOException {
        // pong/nonce messages were added to any protocol version greater than 60000
        if (versionMessage.clientVersion > 60000) {
            write(channel, new Ping(random.nextLong()));
        }
        else
            write(channel, new Ping());
    }

    @Override
    public String toString() {
        return "[" + remoteIp.getHostAddress() + "]:" + params.port;
    }

    public class NetworkHandler extends ReplayingDecoder<VoidEnum> implements ChannelDownstreamHandler {
        @Override
        public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            super.channelConnected(ctx, e);
            channel = e.getChannel();
            // The version message does not use checksumming, until Feb 2012 when it magically does.
            // Announce ourselves. This has to come first to connect to clients beyond v0.30.20.2 which wait to hear
            // from us until they send their version message back.
            log.info("Announcing to {} as: {}", channel.getRemoteAddress(), myVersionMessage.subVer);
            write(channel, myVersionMessage);
            // When connecting, the remote peer sends us a version message with various bits of
            // useful data in it. We need to know the peer protocol version before we can talk to it.
        }

        // Attempt to decode a Bitcoin message passing upstream in the channel.
        //
        // By extending ReplayingDecoder, reading past the end of buffer will throw a special Error
        // causing the channel to read more and retry.
        //
        // On VMs/systems where exception handling is slow, this will impact performance.  On the
        // other hand, implementing a FrameDecoder will increase code complexity due to having
        // to implement retries ourselves.
        //
        // TODO: consider using a decoder state and checkpoint() if performance is an issue.
        @Override
        protected Object decode(ChannelHandlerContext ctx, Channel chan,
                                ChannelBuffer buffer, VoidEnum state) throws Exception {
            Message message = serializer.deserialize(new ChannelBufferInputStream(buffer));
            if (message instanceof VersionMessage)
                onVersionMessage(message);
            return message;
        }

        /** Serialize outgoing Bitcoin messages passing downstream in the channel. */
        public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent evt) throws Exception {
            if (!(evt instanceof MessageEvent)) {
                ctx.sendDownstream(evt);
                return;
            }

            MessageEvent e = (MessageEvent) evt;
            Message message = (Message)e.getMessage();

            ChannelBuffer buffer = ChannelBuffers.dynamicBuffer();
            serializer.serialize(message, new ChannelBufferOutputStream(buffer));
            write(ctx, e.getFuture(), buffer, e.getRemoteAddress());
        }

        public TCPNetworkConnection getOwnerObject() {
            return TCPNetworkConnection.this;
        }
    }
    
    /** Returns the Netty Pipeline stage handling Bitcoin serialization for this connection. */
    public NetworkHandler getHandler() {
        return handler;
    }

    public VersionMessage getVersionMessage() {
        return versionMessage;
    }

    public PeerAddress getPeerAddress() {
        return new PeerAddress(remoteIp, params.port);
    }

    public void close() {
        channel.close();
    }

    public void setRemoteAddress(SocketAddress address) {
        if (address instanceof InetSocketAddress)
            remoteIp = ((InetSocketAddress)address).getAddress();
    }
}
