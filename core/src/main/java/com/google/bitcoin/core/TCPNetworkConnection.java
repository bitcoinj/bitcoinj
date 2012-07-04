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

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferInputStream;
import org.jboss.netty.buffer.ChannelBufferOutputStream;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.*;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
import org.jboss.netty.handler.codec.replay.VoidEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Date;

import static org.jboss.netty.channel.Channels.write;

/**
 * A {@code TCPNetworkConnection} is used for connecting to a Bitcoin node over the standard TCP/IP protocol.<p>
 *
 * <p>{@link TCPNetworkConnection#getHandler()} is part of a Netty Pipeline, downstream of other pipeline stages. 
 * <p>Multiple {@code TCPNetworkConnection}s can wait if another NetworkConnection instance is deserializing a
 * message and discard duplicates before reading them. This is intended to avoid memory usage spikes in constrained
 * environments like Android where deserializing a large message (like a block) on multiple threads simultaneously is
 * both wasteful and can cause OOM failures. This feature is controlled at construction time.
 */
public class TCPNetworkConnection {
	private static final Logger log = LoggerFactory.getLogger(TCPNetworkConnection.class);
	
    // The IP address to which we are connecting.
    private InetAddress remoteIp;
    private final NetworkParameters params;
    private VersionMessage versionMessage;

    private BitcoinSerializer serializer = null;

    private VersionMessage myVersionMessage;
    private static final Date checksummingProtocolChangeDate = new Date(1329696000000L);
    
    private long messageCount;

    private Channel channel;
    
    private NetworkHandler handler;

    /**
     * Construct a network connection with the given params and version.
     *
     * @param params Defines which network to connect to and details of the protocol.
     * @param ver The VersionMessage to announce to the other side of the connection.
     */
    public TCPNetworkConnection(NetworkParameters params, VersionMessage ver) {
        this.params = params;
        this.myVersionMessage = ver;

        // So pre-Feb 2012, update checkumming property after version is read.
        this.serializer = new BitcoinSerializer(this.params, false);
        this.serializer.setUseChecksumming(Utils.now().after(checksummingProtocolChangeDate));
        this.handler = new NetworkHandler();
    }

    private void onFirstMessage(Message m) throws IOException, ProtocolException {
        if (!(m instanceof VersionMessage)) {
            // Bad peers might not follow the protocol. This has been seen in the wild (issue 81).
            log.info("First message received was not a version message but rather " + m);
            return;
        }
        versionMessage = (VersionMessage) m;
        // Now it's our turn ...
        // Send an ACK message stating we accept the peers protocol version.
        write(channel, new VersionAck());
    }
        
    private void onSecondMessage(Message m) throws IOException, ProtocolException {
        // Switch to the new protocol version.
        int peerVersion = versionMessage.clientVersion;
        log.info("Connected to peer: version={}, subVer='{}', services=0x{}, time={}, blocks={}", new Object[] {
                peerVersion,
                versionMessage.subVer,
                versionMessage.localServices,
                new Date(versionMessage.time * 1000),
                versionMessage.bestHeight
        });
        // BitCoinJ is a client mode implementation. That means there's not much point in us talking to other client
        // mode nodes because we can't download the data from them we need to find/verify transactions. Some bogus
        // implementations claim to have a block chain in their services field but then report a height of zero, filter
        // them out here.
        if (!versionMessage.hasBlockChain() || versionMessage.bestHeight <= 0) {
            // Shut down the channel
            throw new ProtocolException("Peer does not have a copy of the block chain.");
        }
        // Newer clients use checksumming.
        serializer.setUseChecksumming(peerVersion >= 209);
        // Handshake is done!
    }

    public void ping() throws IOException {
        write(channel, new Ping());
    }

    @Override
    public String toString() {
        return "[" + remoteIp.getHostAddress() + "]:" + params.port;
    }

    public class NetworkHandler extends ReplayingDecoder<VoidEnum> implements ChannelDownstreamHandler {
        @Override
        public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e)
        throws Exception {
            channel = e.getChannel();
            // The version message does not use checksumming, until Feb 2012 when it magically does.
            // Announce ourselves. This has to come first to connect to clients beyond v0.30.20.2 which wait to hear
            // from us until they send their version message back.
            log.info("Announcing ourselves as: {}", myVersionMessage.subVer);
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
            messageCount++;
            if (messageCount == 1) {
                onFirstMessage(message);
            } else if (messageCount == 2) {
                onSecondMessage(message);
            }
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

    public void setRemoteAddress(SocketAddress address) {
        if (address instanceof InetSocketAddress)
            remoteIp = ((InetSocketAddress)address).getAddress();
    }
}
