/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.net;

import com.google.common.base.Throwables;
import org.bitcoinj.utils.ListenableCompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

/**
 * Creates a simple connection to a server using a {@link StreamConnection} to process data.
 */
public class NioClient implements MessageWriteTarget {
    private static final Logger log = LoggerFactory.getLogger(NioClient.class);

    private final Handler handler;
    private final NioClientManager manager = new NioClientManager();

    class Handler implements TimeoutHandler, StreamConnection {
        private final StreamConnection upstreamConnection;
        private final SocketTimeoutTask timeoutTask;
        private MessageWriteTarget writeTarget;
        private boolean closeOnOpen = false;
        private boolean closeCalled = false;

        Handler(StreamConnection upstreamConnection, int connectTimeoutMillis) {
            this.upstreamConnection = upstreamConnection;
            this.timeoutTask = new SocketTimeoutTask(this::timeoutOccurred);
            setSocketTimeout(connectTimeoutMillis);
            setTimeoutEnabled(true);
        }

        private synchronized void timeoutOccurred() {
            closeOnOpen = true;
            connectionClosed();
        }

        @Override
        public void setTimeoutEnabled(boolean timeoutEnabled) {
            timeoutTask.setTimeoutEnabled(timeoutEnabled);
        }

        @Override
        public void setSocketTimeout(int timeoutMillis) {
            timeoutTask.setSocketTimeout(timeoutMillis);
        }

        @Override
        public synchronized void connectionClosed() {
            manager.stopAsync();
            if (!closeCalled) {
                closeCalled = true;
                upstreamConnection.connectionClosed();
            }
        }

        @Override
        public synchronized void connectionOpened() {
            if (!closeOnOpen)
                upstreamConnection.connectionOpened();
        }

        @Override
        public int receiveBytes(ByteBuffer buff) throws Exception {
            return upstreamConnection.receiveBytes(buff);
        }

        @Override
        public synchronized void setWriteTarget(MessageWriteTarget writeTarget) {
            if (closeOnOpen)
                writeTarget.closeConnection();
            else {
                setTimeoutEnabled(false);
                this.writeTarget = writeTarget;
                upstreamConnection.setWriteTarget(writeTarget);
            }
        }

        @Override
        public int getMaxMessageSize() {
            return upstreamConnection.getMaxMessageSize();
        }
    }

    /**
     * <p>Creates a new client to the given server address using the given {@link StreamConnection} to decode the data.
     * The given connection <b>MUST</b> be unique to this object. This does not block while waiting for the connection to
     * open, but will call either the {@link StreamConnection#connectionOpened()} or
     * {@link StreamConnection#connectionClosed()} callback on the created network event processing thread.</p>
     *
     * @param connectTimeoutMillis The connect timeout set on the connection (in milliseconds). 0 is interpreted as no
     *                             timeout.
     */
    public NioClient(final SocketAddress serverAddress, final StreamConnection parser,
                     final int connectTimeoutMillis) throws IOException {
        manager.startAsync();
        manager.awaitRunning();
        handler = new Handler(parser, connectTimeoutMillis);
        manager.openConnection(serverAddress, handler).whenComplete((result, t) -> {
            if (t != null) {
                log.error("Connect to {} failed: {}", serverAddress, Throwables.getRootCause(t));
            }
        });
    }

    @Override
    public void closeConnection() {
        handler.writeTarget.closeConnection();
    }

    @Override
    public synchronized ListenableCompletableFuture<Void> writeBytes(byte[] message) throws IOException {
        return handler.writeTarget.writeBytes(message);
    }
}
