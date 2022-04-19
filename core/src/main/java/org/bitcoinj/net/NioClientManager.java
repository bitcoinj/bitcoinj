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

import com.google.common.base.Throwables;
import com.google.common.util.concurrent.AbstractExecutionThreadService;
import org.bitcoinj.utils.ContextPropagatingThreadFactory;
import org.bitcoinj.utils.ListenableCompletableFuture;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * A class which manages a set of client connections. Uses Java NIO to select network events and processes them in a
 * single network processing thread.
 */
public class NioClientManager extends AbstractExecutionThreadService implements ClientConnectionManager {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(NioClientManager.class);

    private final Selector selector;

    static class PendingConnect {
        SocketChannel sc;
        StreamConnection connection;
        SocketAddress address;
        CompletableFuture<SocketAddress> future = new CompletableFuture<>();

        PendingConnect(SocketChannel sc, StreamConnection connection, SocketAddress address) { this.sc = sc; this.connection = connection; this.address = address; }
    }
    final Queue<PendingConnect> newConnectionChannels = new LinkedBlockingQueue<>();

    // Added to/removed from by the individual ConnectionHandler's, thus must by synchronized on its own.
    private final Set<ConnectionHandler> connectedHandlers = Collections.synchronizedSet(new HashSet<ConnectionHandler>());

    // Handle a SelectionKey which was selected
    private void handleKey(SelectionKey key) throws IOException {
        // We could have a !isValid() key here if the connection is already closed at this point
        if (key.isValid() && key.isConnectable()) { // ie a client connection which has finished the initial connect process
            // Create a ConnectionHandler and hook everything together
            PendingConnect data = (PendingConnect) key.attachment();
            StreamConnection connection = data.connection;
            SocketChannel sc = (SocketChannel) key.channel();
            ConnectionHandler handler = new ConnectionHandler(connection, key, connectedHandlers);
            try {
                if (sc.finishConnect()) {
                    log.info("Connected to {}", sc.socket().getRemoteSocketAddress());
                    key.interestOps((key.interestOps() | SelectionKey.OP_READ) & ~SelectionKey.OP_CONNECT).attach(handler);
                    connection.connectionOpened();
                    data.future.complete(data.address);
                } else {
                    log.warn("Failed to connect to {}", sc.socket().getRemoteSocketAddress());
                    handler.closeConnection(); // Failed to connect for some reason
                    data.future.completeExceptionally(new ConnectException("Unknown reason"));
                    data.future = null;
                }
            } catch (Exception e) {
                // If e is a CancelledKeyException, there is a race to get to interestOps after finishConnect() which
                // may cause this. Otherwise it may be any arbitrary kind of connection failure.
                // Calling sc.socket().getRemoteSocketAddress() here throws an exception, so we can only log the error itself
                Throwable cause = Throwables.getRootCause(e);
                log.warn("Failed to connect with exception: {}: {}", cause.getClass().getName(), cause.getMessage(), e);
                handler.closeConnection();
                data.future.completeExceptionally(cause);
                data.future = null;
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
                PendingConnect conn;
                while ((conn = newConnectionChannels.poll()) != null) {
                    try {
                        SelectionKey key = conn.sc.register(selector, SelectionKey.OP_CONNECT);
                        key.attach(conn);
                    } catch (ClosedChannelException e) {
                        log.warn("SocketChannel was closed before it could be registered");
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
            log.warn("Error trying to open/read from connection: ", e);
        } finally {
            // Go through and close everything, without letting IOExceptions get in our way
            for (SelectionKey key : selector.keys()) {
                try {
                    key.channel().close();
                } catch (IOException e) {
                    log.warn("Error closing channel", e);
                }
                key.cancel();
                if (key.attachment() instanceof ConnectionHandler)
                    ConnectionHandler.handleKey(key); // Close connection if relevant
            }
            try {
                selector.close();
            } catch (IOException e) {
                log.warn("Error closing client manager selector", e);
            }
        }
    }

    @Override
    public ListenableCompletableFuture<SocketAddress> openConnection(SocketAddress serverAddress, StreamConnection connection) {
        if (!isRunning())
            throw new IllegalStateException();
        // Create a new connection, give it a connection as an attachment
        try {
            SocketChannel sc = SocketChannel.open();
            sc.configureBlocking(false);
            sc.connect(serverAddress);
            PendingConnect data = new PendingConnect(sc, connection, serverAddress);
            newConnectionChannels.offer(data);
            selector.wakeup();
            return ListenableCompletableFuture.of(data.future);
        } catch (Throwable e) {
            return ListenableCompletableFuture.failedFuture(e);
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

    @Override
    protected Executor executor() {
        return command -> new ContextPropagatingThreadFactory("NioClientManager").newThread(command).start();
    }
}
