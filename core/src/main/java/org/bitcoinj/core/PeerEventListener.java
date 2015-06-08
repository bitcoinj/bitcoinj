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

package org.bitcoinj.core;

import javax.annotation.*;
import java.util.*;

/**
 * <p>Implementors can listen to events like blocks being downloaded/transactions being broadcast/connect/disconnects,
 * they can pre-filter messages before they are procesesed by a {@link Peer} or {@link PeerGroup}, and they can
 * provide transactions to remote peers when they ask for them.</p>
 */
public interface PeerEventListener {
    /**
     * <p>Called when peers are discovered, this happens at startup of {@link PeerGroup} or if we run out of
     * suitable {@link Peer}s to connect to.</p>
     *
     * @param peerAddresses the set of discovered {@link PeerAddress}es
     */
    public void onPeersDiscovered(Set<PeerAddress> peerAddresses);

    // TODO: Fix the Block/FilteredBlock type hierarchy so we can avoid the stupid typeless API here.
    /**
     * <p>Called on a Peer thread when a block is received.</p>
     *
     * <p>The block may be a Block object that contains transactions, a Block object that is only a header when
     * fast catchup is being used. If set, filteredBlock can be used to retrieve the list of associated transactions.</p>
     *
     * @param peer       the peer receiving the block
     * @param block      the downloaded block
     * @param filteredBlock if non-null, the object that wraps the block header passed as the block param.
     * @param blocksLeft the number of blocks left to download
     */
    public void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft);

    /**
     * Called when a download is started with the initial number of blocks to be downloaded.
     *
     * @param peer       the peer receiving the block
     * @param blocksLeft the number of blocks left to download
     */
    public void onChainDownloadStarted(Peer peer, int blocksLeft);

    /**
     * Called when a peer is connected. If this listener is registered to a {@link Peer} instead of a {@link PeerGroup},
     * peerCount will always be 1.
     *
     * @param peer
     * @param peerCount the total number of connected peers
     */
    public void onPeerConnected(Peer peer, int peerCount);

    /**
     * Called when a peer is disconnected. Note that this won't be called if the listener is registered on a
     * {@link PeerGroup} and the group is in the process of shutting down. If this listener is registered to a
     * {@link Peer} instead of a {@link PeerGroup}, peerCount will always be 0. This handler can be called without
     * a corresponding invocation of onPeerConnected if the initial connection is never successful.
     *
     * @param peer
     * @param peerCount the total number of connected peers
     */
    public void onPeerDisconnected(Peer peer, int peerCount);

    /**
     * <p>Called when a message is received by a peer, before the message is processed. The returned message is
     * processed instead. Returning null will cause the message to be ignored by the Peer returning the same message
     * object allows you to see the messages received but not change them. The result from one event listeners
     * callback is passed as "m" to the next, forming a chain.</p>
     *
     * <p>Note that this will never be called if registered with any executor other than
     * {@link org.bitcoinj.utils.Threading#SAME_THREAD}</p>
     */
    public Message onPreMessageReceived(Peer peer, Message m);

    /**
     * Called when a new transaction is broadcast over the network.
     */
    public void onTransaction(Peer peer, Transaction t);

    /**
     * <p>Called when a peer receives a getdata message, usually in response to an "inv" being broadcast. Return as many
     * items as possible which appear in the {@link GetDataMessage}, or null if you're not interested in responding.</p>
     *
     * <p>Note that this will never be called if registered with any executor other than
     * {@link org.bitcoinj.utils.Threading#SAME_THREAD}</p>
     */
    @Nullable
    public List<Message> getData(Peer peer, GetDataMessage m);
}
