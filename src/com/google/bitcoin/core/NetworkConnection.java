/**
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
import java.util.LinkedHashMap;

/**
 * A NetworkConnection handles talking to a remote BitCoin peer at a low level. It understands how to read and write
 * messages off the network, but doesn't asynchronously communicate with the peer or handle the higher level details
 * of the protocol. After constructing a NetworkConnection, use a {@link Peer} to hand off communication to a
 * background thread.<p>
 *
 * Multiple NetworkConnections will, by default, wait if another NetworkConnection instance is deserializing a
 * message and discard duplicates before reading them. This is intended to avoid memory usage spikes in constrained
 * environments like Android where deserializing a large message (like a block) on multiple threads simultaneously is
 * both wasteful and can cause OOM failures.<p>
 *
 * Construction is blocking whilst the protocol version is negotiated.
 */
public class NetworkConnection {
    private static final Logger log = LoggerFactory.getLogger(NetworkConnection.class);

    private final Socket socket;
    private final OutputStream out;
    private final InputStream in;
    // The IP address to which we are connecting.
    private final InetAddress remoteIp;
    private final NetworkParameters params;
    private final VersionMessage versionMessage;

    // Given to the BitcoinSerializer to de-duplicate messages.
    private static final LinkedHashMap<Sha256Hash, Integer> dedupeList = BitcoinSerializer.createDedupeList();
    private BitcoinSerializer serializer = null;

    /**
     * Connect to the given IP address using the port specified as part of the network parameters. Once construction
     * is complete a functioning network channel is set up and running.
     *
     * @param peerAddress    address to connect to. IPv6 is not currently supported by BitCoin.  If
     *                       port is not positive the default port from params is used.
     * @param params         Defines which network to connect to and details of the protocol.
     * @param bestHeight     How many blocks are in our best chain
     * @param connectTimeout Timeout in milliseconds when initially connecting to peer
     * @param dedupe         Whether to avoid parsing duplicate messages from the network (ie from other peers).
     * @throws IOException       if there is a network related failure.
     * @throws ProtocolException if the version negotiation failed.
     */
    public NetworkConnection(PeerAddress peerAddress, NetworkParameters params,
                             int bestHeight, int connectTimeout, boolean dedupe)
            throws IOException, ProtocolException {
        this.params = params;
        this.remoteIp = peerAddress.getAddr();

        int port = (peerAddress.getPort() > 0) ? peerAddress.getPort() : params.port;

        InetSocketAddress address = new InetSocketAddress(remoteIp, port);
        socket = new Socket();
        socket.connect(address, connectTimeout);

        out = socket.getOutputStream();
        in = socket.getInputStream();

        // The version message never uses checksumming. Update checkumming property after version is read.
        this.serializer = new BitcoinSerializer(params, false, dedupe ? dedupeList : null);

        // Announce ourselves. This has to come first to connect to clients beyond v0.30.20.2 which wait to hear
        // from us until they send their version message back.
        writeMessage(new VersionMessage(params, bestHeight));
        // When connecting, the remote peer sends us a version message with various bits of
        // useful data in it. We need to know the peer protocol version before we can talk to it.
        Message m = readMessage();
        if (!(m instanceof VersionMessage)) {
            // Bad peers might not follow the protocol. This has been seen in the wild (issue 81).
            throw new ProtocolException("First message received was not a version message but rather " + m);
        }
        versionMessage = (VersionMessage) m;
        // Now it's our turn ...
        // Send an ACK message stating we accept the peers protocol version.
        writeMessage(new VersionAck());
        // And get one back ...
        readMessage();
        // Switch to the new protocol version.
        int peerVersion = versionMessage.clientVersion;
        log.info("Connected to peer: version={}, subVer='{}', services=0x{}, time={}, blocks={}", new Object[]{
                peerVersion,
                versionMessage.subVer,
                versionMessage.localServices,
                new Date(versionMessage.time * 1000),
                versionMessage.bestHeight
        });
        // BitCoinJ is a client mode implementation. That means there's not much point in us talking to other client
        // mode nodes because we can't download the data from them we need to find/verify transactions.
        if (!versionMessage.hasBlockChain()) {
            // Shut down the socket
            try {
                shutdown();
            } catch (IOException ex) {
                // ignore exceptions while aborting
            }
            throw new ProtocolException("Peer does not have a copy of the block chain.");
        }
        // newer clients use checksumming
        serializer.setUseChecksumming(peerVersion >= 209);
        // Handshake is done!
    }

    public NetworkConnection(InetAddress inetAddress, NetworkParameters params, int bestHeight, int connectTimeout)
            throws IOException, ProtocolException {
        this(new PeerAddress(inetAddress), params, bestHeight, connectTimeout, true);
    }

    /**
     * Sends a "ping" message to the remote node. The protocol doesn't presently use this feature much.
     *
     * @throws IOException
     */
    public void ping() throws IOException {
        writeMessage(new Ping());
    }

    /**
     * Shuts down the network socket. Note that there's no way to wait for a socket to be fully flushed out to the
     * wire, so if you call this immediately after sending a message it might not get sent.
     */
    public void shutdown() throws IOException {
        socket.shutdownOutput();
        socket.shutdownInput();
        socket.close();
    }

    @Override
    public String toString() {
        return "[" + remoteIp.getHostAddress() + "]:" + params.port + " (" + (socket.isConnected() ? "connected" :
                "disconnected") + ")";
    }

    /**
     * Reads a network message from the wire, blocking until the message is fully received.
     *
     * @return An instance of a Message subclass
     * @throws ProtocolException if the message is badly formatted, failed checksum or there was a TCP failure.
     */
    public Message readMessage() throws IOException, ProtocolException {
        Message message;
        do {
            message = serializer.deserialize(in);
            // If message is null, it means deduping was enabled, we read a duplicated message and skipped parsing to
            // avoid doing redundant work. So go around and wait for another message.
        } while (message == null);
        return message;
    }

    /**
     * Writes the given message out over the network using the protocol tag. For a Transaction
     * this should be "tx" for example. It's safe to call this from multiple threads simultaneously,
     * the actual writing will be serialized.
     *
     * @throws IOException
     */
    public void writeMessage(Message message) throws IOException {
        synchronized (out) {
            serializer.serialize(message, out);
        }
    }

    /**
     * Returns the version message received from the other end of the connection during the handshake.
     */
    public VersionMessage getVersionMessage() {
        return versionMessage;
    }
}
