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

import org.bitcoinj.core.Block;
import org.bitcoinj.core.FilteredBlock;
import org.bitcoinj.core.GetDataMessage;
import org.bitcoinj.core.Message;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.Transaction;
import javax.annotation.Nullable;
import java.util.List;

/**
 * <p>Implementors can listen to events like blocks being downloaded/transactions being broadcast/connect/disconnects,
 * they can pre-filter messages before they are procesesed by a {@link Peer} or {@link PeerGroup}, and they can
 * provide transactions to remote peers when they ask for them.</p>
 */
public interface PeerDataEventListener {

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
    void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft);

    /**
     * Called when a download is started with the initial number of blocks to be downloaded.
     *
     * @param peer       the peer receiving the block
     * @param blocksLeft the number of blocks left to download
     */
    void onChainDownloadStarted(Peer peer, int blocksLeft);

    /**
     * <p>Called when a message is received by a peer, before the message is processed. The returned message is
     * processed instead. Returning null will cause the message to be ignored by the Peer returning the same message
     * object allows you to see the messages received but not change them. The result from one event listeners
     * callback is passed as "m" to the next, forming a chain.</p>
     *
     * <p>Note that this will never be called if registered with any executor other than
     * {@link org.bitcoinj.utils.Threading#SAME_THREAD}</p>
     */
    Message onPreMessageReceived(Peer peer, Message m);

    /**
     * Called when a new transaction is broadcast over the network.
     */
    void onTransaction(Peer peer, Transaction t);

    /**
     * <p>Called when a peer receives a getdata message, usually in response to an "inv" being broadcast. Return as many
     * items as possible which appear in the {@link GetDataMessage}, or null if you're not interested in responding.</p>
     *
     * <p>Note that this will never be called if registered with any executor other than
     * {@link org.bitcoinj.utils.Threading#SAME_THREAD}</p>
     */
    @Nullable
    List<Message> getData(Peer peer, GetDataMessage m);
}
