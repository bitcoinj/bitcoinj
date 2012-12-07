/**
 * Copyright 2011 John Sample.
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

package com.google.bitcoin.discovery;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/**
 * A PeerDiscovery object is responsible for finding addresses of other nodes in the Bitcoin P2P network. Note that
 * the addresses returned may or may not be accepting connections.
 */
public interface PeerDiscovery {
    // TODO: Flesh out this interface a lot more.

    /** Returns an array of addresses. This method may block. */
    InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException;

    /** Stops any discovery in progress when we want to shut down quickly. */
    void shutdown();
}
