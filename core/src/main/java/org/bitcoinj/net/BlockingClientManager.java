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

import com.google.common.util.concurrent.AbstractIdleService;

import javax.net.SocketFactory;
import java.io.IOException;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * <p>A thin wrapper around a set of {@link BlockingClient}s.</p>
 *
 * <p>Generally, using {@link NioClient} and {@link NioClientManager} should be preferred over {@link BlockingClient}
 * and {@link BlockingClientManager} as they scale significantly better, unless you wish to connect over a proxy or use
 * some other network settings that cannot be set using NIO.</p>
 */
public class BlockingClientManager extends AbstractIdleService implements ClientConnectionManager {
    private final SocketFactory socketFactory;
    private final Set<BlockingClient> clients = Collections.synchronizedSet(new HashSet<BlockingClient>());

    private Duration connectTimeout = Duration.ofSeconds(1);

    public BlockingClientManager() {
        socketFactory = SocketFactory.getDefault();
    }

    /**
     * Creates a blocking client manager that will obtain sockets from the given factory. Useful for customising how
     * bitcoinj connects to the P2P network.
     */
    public BlockingClientManager(SocketFactory socketFactory) {
        this.socketFactory = Objects.requireNonNull(socketFactory);
    }

    @Override
    public CompletableFuture<SocketAddress> openConnection(SocketAddress serverAddress, StreamConnection connection) {
        try {
            if (!isRunning())
                throw new IllegalStateException();
            return new BlockingClient(serverAddress, connection, connectTimeout, socketFactory, clients).getConnectFuture();
        } catch (IOException e) {
            throw new RuntimeException(e); // This should only happen if we are, eg, out of system resources
        }
    }

    /**
     * Sets the number of milliseconds to wait before giving up on a connect attempt
     * @param connectTimeout timeout for establishing a connection to the client
     */
    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    @Override
    protected void startUp() throws Exception { }

    @Override
    protected void shutDown() throws Exception {
        synchronized (clients) {
            for (BlockingClient client : clients)
                client.closeConnection();
        }
    }

    @Override
    public int getConnectedClientCount() {
        return clients.size();
    }

    @Override
    public void closeConnections(int n) {
        if (!isRunning())
            throw new IllegalStateException();
        synchronized (clients) {
            Iterator<BlockingClient> it = clients.iterator();
            while (n-- > 0 && it.hasNext())
                it.next().closeConnection();
        }
    }
}
