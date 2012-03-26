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

import java.io.IOException;

/**
 * A NetworkConnection handles talking to a remote BitCoin peer at a low level. It understands how to read and write
 * messages, but doesn't asynchronously communicate with the peer or handle the higher level details
 * of the protocol. After constructing a NetworkConnection, use a {@link Peer} to hand off communication to a
 * background thread.<p>
 *
 * NetworkConnection is an interface in order to support multiple low level protocols. You likely want a
 * {@link TCPNetworkConnection} as it's currently the only NetworkConnection implementation. In future there may be
 * others that support connections over Bluetooth, NFC, UNIX domain sockets and so on.<p>
 *
 * Construction is blocking whilst the protocol version is negotiated.
 */
public interface NetworkConnection {
    /**
     * Connect to the remote peer.
     * 
     * @param peerAddress the address of the remote peer
     * @param connectTimeoutMsec timeout in milliseconds
     */
    public void connect(PeerAddress peerAddress, int connectTimeoutMsec)
            throws IOException, ProtocolException;

     /**
     * Sends a "ping" message to the remote node. The protocol doesn't presently use this feature much.
     *
     * @throws IOException
     */
    void ping() throws IOException;

    /**
     * Shuts down the network socket. Note that there's no way to wait for a socket to be fully flushed out to the
     * wire, so if you call this immediately after sending a message it might not get sent.
     */
    void shutdown() throws IOException;

    /**
     * Reads a network message from the wire, blocking until the message is fully received.
     *
     * @return An instance of a Message subclass
     * @throws ProtocolException if the message is badly formatted, failed checksum or there was a TCP failure.
     */
    Message readMessage() throws IOException, ProtocolException;

    /**
     * Writes the given message out over the network using the protocol tag. For a Transaction
     * this should be "tx" for example. It's safe to call this from multiple threads simultaneously,
     * the actual writing will be serialized.
     *
     * @throws IOException
     */
    void writeMessage(Message message) throws IOException;

    /**
     * Returns the version message received from the other end of the connection during the handshake.
     */
    VersionMessage getVersionMessage();

    /**
     * @return The address of the other side of the network connection.
     */
    public PeerAddress getPeerAddress();
}
