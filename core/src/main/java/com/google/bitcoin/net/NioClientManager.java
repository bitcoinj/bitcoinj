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

import com.google.common.base.Throwables;
import com.google.common.util.concurrent.AbstractExecutionThreadService;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.*;
import java.nio.channels.spi.SelectorProvider;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * A class which manages a set of client connections. Uses Java NIO to select network events and processes them in a
 * single network processing thread.
 */
public class NioClientManager extends AbstractExecutionThreadService implements ClientConnectionManager {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(NioClientManager.class);

    private final Selector selector;

    // SocketChannels and StreamParsers of newly-created connections which should be registered with OP_CONNECT
    class SocketChannelAndParser {
        SocketChannel sc; StreamParser parser;
        SocketChannelAndParser(SocketChannel sc, StreamParser parser) { this.sc = sc; this.parser = parser; }
    }
    final Queue<SocketChannelAndParser> newConnectionChannels = new LinkedBlockingQueue<SocketChannelAndParser>();

    // Added to/removed from by the individual ConnectionHandler's, thus must by synchronized on its own.
    private final Set<ConnectionHandler> connectedHandlers = Collections.synchronizedSet(new HashSet<ConnectionHandler>());

    // Handle a SelectionKey which was selected
    private void handleKey(SelectionKey key) throws IOException {
        // We could have a !isValid() key here if the connection is already closed at this point
        if (key.isValid() && key.isConnectable()) { // ie a client connection which has finished the initial connect process
            // Create a ConnectionHandler and hook everything together
            StreamParser parser = (StreamParser) key.attachment();
            SocketChannel sc = (SocketChannel) key.channel();
            ConnectionHandler handler = new ConnectionHandler(parser, key, connectedHandlers);
            try {
                if (sc.finishConnect()) {
                    log.info("Successfully connected to {}", sc.socket().getRemoteSocketAddress());
                    key.interestOps(SelectionKey.OP_READ).attach(handler);
                    handler.parser.connectionOpened();
                } else {
                    log.error("Failed to connect to {}", sc.socket().getRemoteSocketAddress());
                    handler.closeConnection(); // Failed to connect for some reason
                }
            } catch (Exception e) {
                // If e is a CancelledKeyException, there is a race to get to interestOps after finishConnect() which
                // may cause this. Otherwise it may be any arbitrary kind of connection failure.
                // Calling sc.socket().getRemoteSocketAddress() here throws an exception, so we can only log the error itself
                log.error("Failed to connect with exception: {}", Throwables.getRootCause(e).getMessage());
                handler.closeConnection();
            }
        } else // Process bytes read
            ConnectionHandler.handleKey(key);
    }

    /**
     * Creates a new client manager which uses Java NIO for socket management. Uses a single thread to handle all select
     * calls.
     */
    public NioClientManager() {
        try {
            selector = SelectorProvider.provider().openSelector();
        } catch (IOException e) {
            throw new RuntimeException(e); // Shouldn't ever happen
        }
    }

    @Override
    public void run() {
        try {
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
            while (isRunning()) {
                SocketChannelAndParser conn;
                while ((conn = newConnectionChannels.poll()) != null) {
                    try {
                        SelectionKey key = conn.sc.register(selector, SelectionKey.OP_CONNECT);
                        key.attach(conn.parser);
                    } catch (ClosedChannelException e) {
                        log.info("SocketChannel was closed before it could be registered");
                    }
                }

                selector.select();

                Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
                    keyIterator.remove();
                    handleKey(key);
                }
            }
        } catch (Exception e) {
            log.error("Error trying to open/read from connection: ", e);
        } finally {
            // Go through and close everything, without letting IOExceptions get in our way
            for (SelectionKey key : selector.keys()) {
                try {
                    key.channel().close();
                } catch (IOException e) {
                    log.error("Error closing channel", e);
                }
                key.cancel();
                if (key.attachment() instanceof ConnectionHandler)
                    ConnectionHandler.handleKey(key); // Close connection if relevant
            }
            try {
                selector.close();
            } catch (IOException e) {
                log.error("Error closing client manager selector", e);
            }
        }
    }

    @Override
    public void openConnection(SocketAddress serverAddress, StreamParser parser) {
        if (!isRunning())
            throw new IllegalStateException();
        // Create a new connection, give it a parser as an attachment
        try {
            SocketChannel sc = SocketChannel.open();
            sc.configureBlocking(false);
            sc.connect(serverAddress);
            newConnectionChannels.offer(new SocketChannelAndParser(sc, parser));
            selector.wakeup();
        } catch (IOException e) {
            log.error("Could not connect to " + serverAddress);
            throw new RuntimeException(e); // This should only happen if we are, eg, out of system resources
        }
    }

    @Override
    public void triggerShutdown() {
        selector.wakeup();
    }

    @Override
    public int getConnectedClientCount() {
        return connectedHandlers.size();
    }

    @Override
    public void closeConnections(int n) {
        while (n-- > 0) {
            ConnectionHandler handler;
            synchronized (connectedHandlers) {
                handler = connectedHandlers.iterator().next();
            }
            if (handler != null)
                handler.closeConnection(); // Removes handler from connectedHandlers before returning
        }
    }
}
