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

import org.bitcoinj.core.*;

import javax.annotation.*;

/**
 * <p>Implementors can listen to events like blocks being downloaded/transactions being broadcast/connect/disconnects,
 * they can pre-filter messages before they are processed by a {@link Peer} or {@link PeerGroup}, and they can
 * provide transactions to remote peers when they ask for them.</p>
 */
public interface BlocksDownloadedEventListener {

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
}
