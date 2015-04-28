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

package org.bitcoinj.net;

import com.google.common.util.concurrent.*;
import org.bitcoinj.core.*;
import org.slf4j.*;

import javax.annotation.*;
import javax.net.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.*;

import static com.google.common.base.Preconditions.*;

/**
 * <p>Creates a simple connection to a server using a {@link StreamParser} to process data.</p>
 *
 * <p>Generally, using {@link NioClient} and {@link NioClientManager} should be preferred over {@link BlockingClient}
 * and {@link BlockingClientManager}, unless you wish to connect over a proxy or use some other network settings that
 * cannot be set using NIO.</p>
 */
public class BlockingClient implements MessageWriteTarget {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(BlockingClient.class);

    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    private final ByteBuffer dbuf;
    private Socket socket;
    private volatile boolean vCloseRequested = false;
    private SettableFuture<SocketAddress> connectFuture;

    /**
     * <p>Creates a new client to the given server address using the given {@link StreamParser} to decode the data.
     * The given parser <b>MUST</b> be unique to this object. This does not block while waiting for the connection to
     * open, but will call either the {@link StreamParser#connectionOpened()} or
     * {@link StreamParser#connectionClosed()} callback on the created network event processing thread.</p>
     *
     * @param connectTimeoutMillis The connect timeout set on the connection (in milliseconds). 0 is interpreted as no
     *                             timeout.
     * @param socketFactory An object that creates {@link Socket} objects on demand, which may be customised to control
     *                      how this client connects to the internet. If not sure, use SocketFactory.getDefault()
     * @param clientSet A set which this object will add itself to after initialization, and then remove itself from
     */
    public BlockingClient(final SocketAddress serverAddress, final StreamParser parser,
                          final int connectTimeoutMillis, final SocketFactory socketFactory, @Nullable final Set<BlockingClient> clientSet) throws IOException {
        connectFuture = SettableFuture.create();
        // Try to fit at least one message in the network buffer, but place an upper and lower limit on its size to make
        // sure it doesnt get too large or have to call read too often.
        dbuf = ByteBuffer.allocateDirect(Math.min(Math.max(parser.getMaxMessageSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        parser.setWriteTarget(this);
        socket = socketFactory.createSocket();
        final Context context = Context.get();
        Thread t = new Thread() {
            @Override
            public void run() {
                Context.propagate(context);
                if (clientSet != null)
                    clientSet.add(BlockingClient.this);
                try {
                    socket.connect(serverAddress, connectTimeoutMillis);
                    parser.connectionOpened();
                    connectFuture.set(serverAddress);
                    InputStream stream = socket.getInputStream();
                    byte[] readBuff = new byte[dbuf.capacity()];

                    while (true) {
                        // TODO Kill the message duplication here
                        checkState(dbuf.remaining() > 0 && dbuf.remaining() <= readBuff.length);
                        int read = stream.read(readBuff, 0, Math.max(1, Math.min(dbuf.remaining(), stream.available())));
                        if (read == -1)
                            return;
                        dbuf.put(readBuff, 0, read);
                        // "flip" the buffer - setting the limit to the current position and setting position to 0
                        dbuf.flip();
                        // Use parser.receiveBytes's return value as a double-check that it stopped reading at the right
                        // location
                        int bytesConsumed = parser.receiveBytes(dbuf);
                        checkState(dbuf.position() == bytesConsumed);
                        // Now drop the bytes which were read by compacting dbuf (resetting limit and keeping relative
                        // position)
                        dbuf.compact();
                    }
                } catch (Exception e) {
                    if (!vCloseRequested) {
                        log.error("Error trying to open/read from connection: {}: {}", serverAddress, e.getMessage());
                        connectFuture.setException(e);
                    }
                } finally {
                    try {
                        socket.close();
                    } catch (IOException e1) {
                        // At this point there isn't much we can do, and we can probably assume the channel is closed
                    }
                    if (clientSet != null)
                        clientSet.remove(BlockingClient.this);
                    parser.connectionClosed();
                }
            }
        };
        t.setName("BlockingClient network thread for " + serverAddress);
        t.setDaemon(true);
        t.start();
    }

    /**
     * Closes the connection to the server, triggering the {@link StreamParser#connectionClosed()}
     * event on the network-handling thread where all callbacks occur.
     */
    @Override
    public void closeConnection() {
        // Closes the channel, triggering an exception in the network-handling thread triggering connectionClosed()
        try {
            vCloseRequested = true;
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public synchronized void writeBytes(byte[] message) throws IOException {
        try {
            OutputStream stream = socket.getOutputStream();
            stream.write(message);
            stream.flush();
        } catch (IOException e) {
            log.error("Error writing message to connection, closing connection", e);
            closeConnection();
            throw e;
        }
    }

    /** Returns a future that completes once connection has occurred at the socket level or with an exception if failed to connect. */
    public ListenableFuture<SocketAddress> getConnectFuture() {
        return connectFuture;
    }
}
