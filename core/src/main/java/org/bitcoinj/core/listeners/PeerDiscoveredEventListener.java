/*
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
import org.bitcoinj.core.PeerGroup;

import java.util.Set;

/**
 * <p>Implementors can listen to events for peers being discovered.</p>
 */
public interface PeerDiscoveredEventListener {
    /**
     * <p>Called when peers are discovered, this happens at startup of {@link PeerGroup} or if we run out of
     * suitable {@link Peer}s to connect to.</p>
     *
     * @param peerAddresses the set of discovered {@link PeerAddress}es
     */
    void onPeersDiscovered(Set<PeerAddress> peerAddresses);
}
