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
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.Iterator;
import java.util.concurrent.locks.ReentrantLock;

import com.google.bitcoin.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Creates a simple server listener which listens for incoming client connections and uses a {@link ProtobufParser} to
 * process data.
 */
public class ProtobufServer {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(ProtobufServer.class);

    private final ProtobufParserFactory parserFactory;

    @VisibleForTesting final Thread handlerThread;
    private final ServerSocketChannel sc;

    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    private class ConnectionHandler extends MessageWriteTarget {
        private final ReentrantLock lock = Threading.lock("protobufServerConnectionHandler");
        private final ByteBuffer dbuf;
        private final SocketChannel channel;
        private final ProtobufParser parser;
        private boolean closeCalled = false;

        ConnectionHandler(SocketChannel channel) throws IOException {
            this.channel = checkNotNull(channel);
            ProtobufParser newParser = parserFactory.getNewParser(channel.socket().getInetAddress(), channel.socket().getPort());
            if (newParser == null) {
                closeConnection();
                throw new IOException("Parser factory.getNewParser returned null");
            }
            this.parser = newParser;
            dbuf = ByteBuffer.allocateDirect(Math.min(Math.max(newParser.maxMessageSize, BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
            newParser.setWriteTarget(this);
        }

        @Override
        void writeBytes(byte[] message) {
            lock.lock();
            try {
                if (channel.write(ByteBuffer.wrap(message)) != message.length)
                    throw new IOException("Couldn't write all of message to socket");
            } catch (IOException e) {
                log.error("Error writing message to connection, closing connection", e);
                closeConnection();
            } finally {
                lock.unlock();
            }
        }

        @Override
        void closeConnection() {
            try {
                channel.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            connectionClosed();
        }

        private void connectionClosed() {
            boolean callClosed = false;
            lock.lock();
            try {
                callClosed = !closeCalled;
                closeCalled = true;
            } finally {
                lock.unlock();
            }
            if (callClosed)
                parser.connectionClosed();
        }
    }

    // Handle a SelectionKey which was selected
    private void handleKey(Selector selector, SelectionKey key) throws IOException {
        if (key.isValid() && key.isAcceptable()) {
            // Accept a new connection, give it a parser as an attachment
            SocketChannel newChannel = sc.accept();
            newChannel.configureBlocking(false);
            ConnectionHandler handler = new ConnectionHandler(newChannel);
            newChannel.register(selector, SelectionKey.OP_READ).attach(handler);
            handler.parser.connectionOpen();
        } else { // Got a closing channel or a channel to a client connection
            ConnectionHandler handler = ((ConnectionHandler)key.attachment());
            try {
                if (!key.isValid() && handler != null)
                    handler.closeConnection(); // Key has been cancelled, make sure the socket gets closed
                else if (handler != null && key.isReadable()) {
                    // Do a socket read and invoke the parser's receive message
                    int read = handler.channel.read(handler.dbuf);
                    if (read == 0)
                        return; // Should probably never happen, but just in case it actually can just return 0
                    else if (read == -1) { // Socket was closed
                        key.cancel();
                        handler.closeConnection();
                        return;
                    }
                    // "flip" the buffer - setting the limit to the current position and setting position to 0
                    handler.dbuf.flip();
                    // Use parser.receive's return value as a double-check that it stopped reading at the right location
                    int bytesConsumed = handler.parser.receive(handler.dbuf);
                    checkState(handler.dbuf.position() == bytesConsumed);
                    // Now drop the bytes which were read by compacting dbuf (resetting limit and keeping relative
                    // position)
                    handler.dbuf.compact();
                }
            } catch (Exception e) {
                // This can happen eg if the channel closes while the tread is about to get killed
                // (ClosedByInterruptException), or if parser.parser.receive throws something
                log.error("Error handling SelectionKey", e);
                if (handler != null)
                    handler.closeConnection();
            }
        }
    }

    /**
     * Creates a new server which is capable of listening for incoming connections and processing client provided data
     * using {@link ProtobufParser}s created by the given {@link ProtobufParserFactory}
     *
     * @throws IOException If there is an issue opening the server socket (note that we don't bind yet)
     */
    public ProtobufServer(final ProtobufParserFactory parserFactory) throws IOException {
        this.parserFactory = parserFactory;

        sc = ServerSocketChannel.open();
        sc.configureBlocking(false);
        final Selector selector = SelectorProvider.provider().openSelector();

        handlerThread = new Thread() {
            @Override
            public void run() {
                try {
                    sc.register(selector, SelectionKey.OP_ACCEPT);

                    while (selector.select() > 0) { // Will get 0 on stop() due to thread interrupt
                        Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                        while (keyIterator.hasNext()) {
                            SelectionKey key = keyIterator.next();
                            keyIterator.remove();

                            handleKey(selector, key);
                        }
                    }
                } catch (Exception e) {
                    log.error("Error trying to open/read from connection: {}", e);
                } finally {
                    // Go through and close everything, without letting IOExceptions getting in our way
                    for (SelectionKey key : selector.keys()) {
                        try {
                            key.channel().close();
                        } catch (IOException e) {
                            log.error("Error closing channel", e);
                        }
                        try {
                            key.cancel();
                            handleKey(selector, key);
                        } catch (IOException e) {
                            log.error("Error closing selection key", e);
                        }
                    }
                    try {
                        selector.close();
                    } catch (IOException e) {
                        log.error("Error closing server selector", e);
                    }
                    try {
                        sc.close();
                    } catch (IOException e) {
                        log.error("Error closing server channel", e);
                    }
                }
            }
        };
    }

    /**
     * Starts the server by binding to the given address and starting the connection handling thread.
     *
     * @throws IOException If binding fails for some reason.
     */
    public void start(InetSocketAddress bindAddress) throws IOException {
        sc.socket().bind(bindAddress);
        handlerThread.start();
    }

    /**
     * Attempts to gracefully close all open connections, calling their connectionClosed() events.
     * @throws InterruptedException If we are interrupted while waiting for the process to finish
     */
    public void stop() throws InterruptedException {
        handlerThread.interrupt();
        handlerThread.join();
    }
}
