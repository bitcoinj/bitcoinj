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
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.Iterator;

import com.google.common.annotations.VisibleForTesting;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Creates a simple server listener which listens for incoming client connections and uses a {@link StreamParser} to
 * process data.
 */
public class NioServer {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(NioServer.class);

    private final StreamParserFactory parserFactory;

    @VisibleForTesting final Thread handlerThread;
    private final ServerSocketChannel sc;

    // Handle a SelectionKey which was selected
    private void handleKey(Selector selector, SelectionKey key) throws IOException {
        if (key.isValid() && key.isAcceptable()) {
            // Accept a new connection, give it a parser as an attachment
            SocketChannel newChannel = sc.accept();
            newChannel.configureBlocking(false);
            ConnectionHandler handler = new ConnectionHandler(parserFactory, newChannel);
            newChannel.register(selector, SelectionKey.OP_READ).attach(handler);
            handler.parser.connectionOpened();
        } else { // Got a closing channel or a channel to a client connection
            ConnectionHandler.handleKey(key);
        }
    }

    /**
     * Creates a new server which is capable of listening for incoming connections and processing client provided data
     * using {@link StreamParser}s created by the given {@link StreamParserFactory}
     *
     * @throws IOException If there is an issue opening the server socket (note that we don't bind yet)
     */
    public NioServer(final StreamParserFactory parserFactory) throws IOException {
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
