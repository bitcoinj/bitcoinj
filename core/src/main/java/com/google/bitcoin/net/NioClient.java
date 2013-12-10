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

package com.google.bitcoin.net;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;

import static com.google.common.base.Preconditions.checkState;

/**
 * Creates a simple connection to a server using a {@link StreamParser} to process data.
 */
public class NioClient implements MessageWriteTarget {
    private final Handler handler;
    private final NioClientManager manager = new NioClientManager();

    class Handler extends AbstractTimeoutHandler implements StreamParser {
        private final StreamParser upstreamParser;
        private MessageWriteTarget writeTarget;
        private boolean closeOnOpen = false;
        Handler(StreamParser upstreamParser, int connectTimeoutMillis) {
            this.upstreamParser = upstreamParser;
            setSocketTimeout(connectTimeoutMillis);
            setTimeoutEnabled(true);
        }

        @Override
        protected synchronized void timeoutOccurred() {
            upstreamParser.connectionClosed();
            closeOnOpen = true;
        }

        @Override
        public void connectionClosed() {
            upstreamParser.connectionClosed();
            manager.stop();
        }

        @Override
        public synchronized void connectionOpened() {
            if (!closeOnOpen)
                upstreamParser.connectionOpened();
        }

        @Override
        public int receiveBytes(ByteBuffer buff) throws Exception {
            return upstreamParser.receiveBytes(buff);
        }

        @Override
        public synchronized void setWriteTarget(MessageWriteTarget writeTarget) {
            if (closeOnOpen)
                writeTarget.closeConnection();
            else {
                setTimeoutEnabled(false);
                this.writeTarget = writeTarget;
                upstreamParser.setWriteTarget(writeTarget);
            }
        }

        @Override
        public int getMaxMessageSize() {
            return upstreamParser.getMaxMessageSize();
        }
    }

    /**
     * <p>Creates a new client to the given server address using the given {@link StreamParser} to decode the data.
     * The given parser <b>MUST</b> be unique to this object. This does not block while waiting for the connection to
     * open, but will call either the {@link StreamParser#connectionOpened()} or
     * {@link StreamParser#connectionClosed()} callback on the created network event processing thread.</p>
     *
     * @param connectTimeoutMillis The connect timeout set on the connection (in milliseconds). 0 is interpreted as no
     *                             timeout.
     */
    public NioClient(final SocketAddress serverAddress, final StreamParser parser,
                     final int connectTimeoutMillis) throws IOException {
        manager.startAndWait();
        handler = new Handler(parser, connectTimeoutMillis);
        manager.openConnection(serverAddress, handler);
    }

    @Override
    public void closeConnection() {
        handler.writeTarget.closeConnection();
    }

    @Override
    public synchronized void writeBytes(byte[] message) throws IOException {
        handler.writeTarget.writeBytes(message);
    }
}
