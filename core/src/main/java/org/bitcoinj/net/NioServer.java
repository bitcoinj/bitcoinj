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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.Iterator;

/**
 * Creates a simple server listener which listens for incoming client connections and uses a {@link StreamConnection} to
 * process data.
 */
public class NioServer extends AbstractExecutionThreadService {
    private static final Logger log = LoggerFactory.getLogger(NioServer.class);

    private final StreamConnectionFactory connectionFactory;

    public final ServerSocketChannel sc;
    // For testing only
    final Selector selector;

    // Handle a SelectionKey which was selected
    private void handleKey(Selector selector, SelectionKey key) throws IOException {
        if (key.isValid() && key.isAcceptable()) {
            // Accept a new connection, give it a stream connection as an attachment
            SocketChannel newChannel = sc.accept();
            newChannel.configureBlocking(false);
            SelectionKey newKey = newChannel.register(selector, SelectionKey.OP_READ);
            try {
                ConnectionHandler handler = newHandler(newKey);
                newKey.attach(handler);
                handler.connection.connectionOpened();
            } catch (IOException e) {
                // This can happen if ConnectionHandler's call to get a new handler returned null
                log.error("Error handling new connection", Throwables.getRootCause(e));
                newKey.channel().close();
            }
        } else { // Got a closing channel or a channel to a client connection
            ConnectionHandler.handleKey(key);
        }
    }

    private ConnectionHandler newHandler(SelectionKey key) throws IOException {
        StreamConnection connection = connectionFactory.getNewConnection(((SocketChannel) key.channel()).socket().getInetAddress(), ((SocketChannel) key.channel()).socket().getPort());
        if (connection == null) {
            throw new IOException("Parser factory.getNewConnection returned null");
        }
        return new ConnectionHandler(connection, key);
    }

    /**
     * Creates a new server which is capable of listening for incoming connections and processing client provided data
     * using {@link StreamConnection}s created by the given {@link StreamConnectionFactory}
     *
     * @throws IOException If there is an issue opening the server socket or binding fails for some reason
     */
    public NioServer(final StreamConnectionFactory connectionFactory, InetSocketAddress bindAddress) throws IOException {
        this.connectionFactory = connectionFactory;

        sc = ServerSocketChannel.open();
        sc.configureBlocking(false);
        try {
            sc.socket().bind(bindAddress);
        } catch (BindException e) {
            log.error("BindException {} while creating NioServer at address {}: ", e.getMessage(), bindAddress);
            throw new IOException("Address " + bindAddress + " already in use", e);
        }
        selector = SelectorProvider.provider().openSelector();
        sc.register(selector, SelectionKey.OP_ACCEPT);
    }

    @Override
    protected void run() {
        try {
            while (isRunning()) {
                selector.select();

                Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
                    keyIterator.remove();

                    handleKey(selector, key);
                }
            }
        } catch (IOException e) {
            log.error("Error trying to open/read from connection", e);
        } finally {
            // Go through and close everything, without letting IOExceptions get in our way
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

    /**
     * Invoked by the Execution service when it's time to stop.
     * Calling this method directly will NOT stop the service, call
     * {@link com.google.common.util.concurrent.AbstractExecutionThreadService#stopAsync()} instead.
     */
    @Override
    public void triggerShutdown() {
        // Wake up the selector and let the selection thread break its loop as the ExecutionService !isRunning()
        selector.wakeup();
    }
}
