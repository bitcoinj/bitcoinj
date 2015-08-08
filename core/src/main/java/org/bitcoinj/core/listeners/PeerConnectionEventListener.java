/**
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.core.listeners;

import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerAddress;
import java.util.Set;

/**
 * <p>Implementors can listen to events like blocks being downloaded/transactions being broadcast/connect/disconnects,
 * they can pre-filter messages before they are procesesed by a {@link Peer} or {@link PeerGroup}, and they can
 * provide transactions to remote peers when they ask for them.</p>
 */
public interface PeerConnectionEventListener {
    /**
     * <p>Called when peers are discovered, this happens at startup of {@link PeerGroup} or if we run out of
     * suitable {@link Peer}s to connect to.</p>
     *
     * @param peerAddresses the set of discovered {@link PeerAddress}es
     */
    void onPeersDiscovered(Set<PeerAddress> peerAddresses);

    /**
     * Called when a peer is connected. If this listener is registered to a {@link Peer} instead of a {@link PeerGroup},
     * peerCount will always be 1.
     *
     * @param peer
     * @param peerCount the total number of connected peers
     */
    void onPeerConnected(Peer peer, int peerCount);

    /**
     * Called when a peer is disconnected. Note that this won't be called if the listener is registered on a
     * {@link PeerGroup} and the group is in the process of shutting down. If this listener is registered to a
     * {@link Peer} instead of a {@link PeerGroup}, peerCount will always be 0. This handler can be called without
     * a corresponding invocation of onPeerConnected if the initial connection is never successful.
     *
     * @param peer
     * @param peerCount the total number of connected peers
     */
    void onPeerDisconnected(Peer peer, int peerCount);
}
