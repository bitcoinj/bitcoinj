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
 * <p>A NetworkConnection handles talking to a remote Bitcoin peer at a low level. It understands how to read and write
 * messages, but doesn't asynchronously communicate with the peer or handle the higher level details
 * of the protocol. A NetworkConnection is typically stateless, so after constructing a NetworkConnection, give it to a
 * newly created {@link Peer} to handle messages to and from that specific peer.</p>
 *
 * <p>If you just want to "get on the network" and don't care about the details, you want to use a {@link PeerGroup}
 * instead. A {@link PeerGroup} handles the process of setting up connections to multiple peers, running background threads
 * for them, and many other things.</p>
 *
 * <p>NetworkConnection is an interface in order to support multiple low level protocols. You likely want a
 * {@link TCPNetworkConnection} as it's currently the only NetworkConnection implementation. In future there may be
 * others that support connections over Bluetooth, NFC, UNIX domain sockets and so on.</p>
 */
public interface NetworkConnection {
     /**
     * Sends a "ping" message to the remote node. The protocol doesn't presently use this feature much.
     *
     * @throws IOException
     */
    public void ping() throws IOException;

    /**
     * Writes the given message out over the network using the protocol tag. For a Transaction
     * this should be "tx" for example. It's safe to call this from multiple threads simultaneously,
     * the actual writing will be serialized.
     *
     * @throws IOException
     */
    public void writeMessage(Message message) throws IOException;

    /**
     * Returns the version message received from the other end of the connection during the handshake.
     */
    public VersionMessage getVersionMessage();

    /**
     * @return The address of the other side of the network connection.
     */
    public PeerAddress getPeerAddress();

    /**
     * Does whatever needed to clean up the given connection, if necessary.
     */
    public void close();
}
