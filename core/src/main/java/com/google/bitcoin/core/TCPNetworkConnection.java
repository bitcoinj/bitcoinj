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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Date;

/**
 * A {@code TCPNetworkConnection} is used for connecting to a Bitcoin node over the standard TCP/IP protocol.<p>
 *
 * Multiple {@code TCPNetworkConnection}s can wait if another NetworkConnection instance is deserializing a
 * message and discard duplicates before reading them. This is intended to avoid memory usage spikes in constrained
 * environments like Android where deserializing a large message (like a block) on multiple threads simultaneously is
 * both wasteful and can cause OOM failures. This feature is controlled at construction time.
 */
public class TCPNetworkConnection implements NetworkConnection {
	private static final Logger log = LoggerFactory.getLogger(TCPNetworkConnection.class);
	
    private final Socket socket;
    private OutputStream out;
    private InputStream in;
    // The IP address to which we are connecting.
    private InetAddress remoteIp;
    private final NetworkParameters params;
    private VersionMessage versionMessage;

    private BitcoinSerializer serializer = null;

    private VersionMessage myVersionMessage;
    private static final Date checksummingProtocolChangeDate = new Date(1329696000000L);

    /**
     * Construct a network connection with the given params and version. To actually connect to a remote node, call
     * {@link TCPNetworkConnection#connect(PeerAddress, int)}.
     *
     * @param params Defines which network to connect to and details of the protocol.
     * @param ver The VersionMessage to announce to the other side of the connection.
     * @throws IOException if there is a network related failure.
     * @throws ProtocolException if the version negotiation failed.
     */
    public TCPNetworkConnection(NetworkParameters params, VersionMessage ver)
            throws IOException, ProtocolException {
        this.params = params;
        this.myVersionMessage = ver;

        socket = new Socket();

        // So pre-Feb 2012, update checkumming property after version is read.
        this.serializer = new BitcoinSerializer(this.params, false);
        this.serializer.setUseChecksumming(Utils.now().after(checksummingProtocolChangeDate));
    }

    /**
     * Connect to the given IP address using the port specified as part of the network parameters. Once construction
     * is complete a functioning network channel is set up and running.
     *
     * @param params Defines which network to connect to and details of the protocol.
     * @param bestHeight The height of the best chain we know about, sent to the other side.
     * @throws IOException if there is a network related failure.
     * @throws ProtocolException if the version negotiation failed.
     */
    public TCPNetworkConnection(NetworkParameters params, int bestHeight)
            throws IOException, ProtocolException {
        this(params, new VersionMessage(params, bestHeight));
    }

    public void connect(PeerAddress peerAddress, int connectTimeoutMsec) throws IOException, ProtocolException {
        remoteIp = peerAddress.getAddr();
        int port = (peerAddress.getPort() > 0) ? peerAddress.getPort() : this.params.port;

        InetSocketAddress address = new InetSocketAddress(remoteIp, port);

        socket.connect(address, connectTimeoutMsec);

        out = socket.getOutputStream();
        in = socket.getInputStream();

        // The version message does not use checksumming, until Feb 2012 when it magically does.
        // Announce ourselves. This has to come first to connect to clients beyond v0.30.20.2 which wait to hear
        // from us until they send their version message back.
        log.info("Announcing ourselves as: {}", myVersionMessage.subVer);
        writeMessage(myVersionMessage);
        // When connecting, the remote peer sends us a version message with various bits of
        // useful data in it. We need to know the peer protocol version before we can talk to it.
        // There is a bug in Satoshis code such that it can sometimes send us alert messages before version negotiation
        // has completed. There's no harm in ignoring them (they're meant for Bitcoin-Qt users anyway) so we just cycle
        // here until we find the right message.
        Message m;
        while (!((m = readMessage()) instanceof VersionMessage));
        versionMessage = (VersionMessage) m;
        // Now it's our turn ...
        // Send an ACK message stating we accept the peers protocol version.
        writeMessage(new VersionAck());
        // And get one back ...
        readMessage();
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
            // Shut down the socket
            try {
                shutdown();
            } catch (IOException ex) {
                // ignore exceptions while aborting
            }
            throw new ProtocolException("Peer does not have a copy of the block chain.");
        }
        // Newer clients use checksumming.
        serializer.setUseChecksumming(peerVersion >= 209);
        // Handshake is done!
    }

    public void ping() throws IOException {
        writeMessage(new Ping());
    }

    public void shutdown() throws IOException {
        socket.close();
    }

    @Override
    public String toString() {
        return "[" + remoteIp.getHostAddress() + "]:" + params.port + " (" + (socket.isConnected() ? "connected" :
                "disconnected") + ")";
    }

    public Message readMessage() throws IOException, ProtocolException {
        Message message;
        do {
            message = serializer.deserialize(in);
            // If message is null, it means deduping was enabled, we read a duplicated message and skipped parsing to
            // avoid doing redundant work. So go around and wait for another message.
        } while (message == null);
        return message;
    }

    public void writeMessage(Message message) throws IOException {
        synchronized (out) {
            serializer.serialize(message, out);
        }
    }

    public VersionMessage getVersionMessage() {
        return versionMessage;
    }

    public PeerAddress getPeerAddress() {
        return new PeerAddress(remoteIp, params.port);
    }
}
