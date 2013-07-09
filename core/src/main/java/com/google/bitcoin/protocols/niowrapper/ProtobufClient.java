/*
 * Copyright 2013 Google Inc.
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

package com.google.bitcoin.protocols.niowrapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import javax.annotation.Nonnull;

import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkState;

/**
 * Creates a simple connection to a server using a {@link ProtobufParser} to process data.
 */
public class ProtobufClient extends MessageWriteTarget {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(ProtobufClient.class);

    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    @Nonnull private final ByteBuffer dbuf;
    @Nonnull private final SocketChannel sc;

    /**
     * <p>Creates a new client to the given server address using the given {@link ProtobufParser} to decode the data.
     * The given parser <b>MUST</b> be unique to this object. This does not block while waiting for the connection to
     * open, but will call either the {@link ProtobufParser#connectionOpen()} or {@link ProtobufParser#connectionClosed()}
     * callback on the created network event processing thread.</p>
     *
     * @param connectTimeoutMillis The connect timeout set on the connection (in milliseconds). 0 is interpreted as no
     *                             timeout.
     */
    public ProtobufClient(final InetSocketAddress serverAddress, final ProtobufParser parser,
                          final int connectTimeoutMillis) throws IOException {
        // Try to fit at least one message in the network buffer, but place an upper and lower limit on its size to make
        // sure it doesnt get too large or have to call read too often.
        dbuf = ByteBuffer.allocateDirect(Math.min(Math.max(parser.maxMessageSize, BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        parser.setWriteTarget(this);
        sc = SocketChannel.open();

        new Thread() {
            @Override
            public void run() {
                try {
                    sc.socket().connect(serverAddress, connectTimeoutMillis);
                    parser.connectionOpen();

                    while (true) {
                        int read = sc.read(dbuf);
                        if (read == 0)
                            continue;
                        else if (read == -1)
                            return;
                        // "flip" the buffer - setting the limit to the current position and setting position to 0
                        dbuf.flip();
                        // Use parser.receive's return value as a double-check that it stopped reading at the right
                        // location
                        int bytesConsumed = parser.receive(dbuf);
                        checkState(dbuf.position() == bytesConsumed);
                        // Now drop the bytes which were read by compacting dbuf (resetting limit and keeping relative
                        // position)
                        dbuf.compact();
                    }
                } catch (AsynchronousCloseException e) {// Expected if the connection is closed
                } catch (ClosedChannelException e) { // Expected if the connection is closed
                } catch (Exception e) {
                    log.error("Error trying to open/read from connection", e);
                } finally {
                    try {
                        sc.close();
                    } catch (IOException e1) {
                        // At this point there isn't much we can do, and we can probably assume the channel is closed
                    }
                    parser.connectionClosed();
                }
            }
        }.start();
    }

    /**
     * Closes the connection to the server, triggering the {@link ProtobufParser#connectionClosed()}
     * event on the network-handling thread where all callbacks occur.
     */
    public void closeConnection() {
        // Closes the channel, triggering an exception in the network-handling thread triggering connectionClosed()
        try {
            sc.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Writes raw bytes to the channel (used by the write method in ProtobufParser)
    @Override
    synchronized void writeBytes(byte[] message) {
        try {
            if (sc.write(ByteBuffer.wrap(message)) != message.length)
                throw new IOException("Couldn't write all of message to socket");
        } catch (IOException e) {
            log.error("Error writing message to connection, closing connection", e);
            closeConnection();
        }
    }
}
