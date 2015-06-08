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

import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.Service;

import java.net.SocketAddress;

/**
 * <p>A generic interface for an object which keeps track of a set of open client connections, creates new ones and
 * ensures they are serviced properly.</p>
 *
 * <p>When the service is {@link com.google.common.util.concurrent.Service#stop()}ed, all connections will be closed and
 * the appropriate connectionClosed() calls must be made.</p>
 */
public interface ClientConnectionManager extends Service {
    /**
     * Creates a new connection to the given address, with the given parser used to handle incoming data. Any errors
     * that occur during connection will be returned in the given future, including errors that can occur immediately.
     */
    ListenableFuture<SocketAddress> openConnection(SocketAddress serverAddress, StreamParser parser);

    /** Gets the number of connected peers */
    int getConnectedClientCount();

    /** Closes n peer connections */
    void closeConnections(int n);
}
