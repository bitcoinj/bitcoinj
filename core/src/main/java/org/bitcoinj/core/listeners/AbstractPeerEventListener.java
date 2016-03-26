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

import org.bitcoinj.core.Block;
import org.bitcoinj.core.FilteredBlock;
import org.bitcoinj.core.GetDataMessage;
import org.bitcoinj.core.Message;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.Transaction;
import javax.annotation.*;
import java.util.List;
import java.util.Set;

/**
 * Deprecated: implement the more specific event listener interfaces instead to fill out only what you need
 */
@Deprecated
public abstract class AbstractPeerEventListener extends AbstractPeerDataEventListener implements PeerConnectionEventListener, OnTransactionBroadcastListener {
    @Override
    public void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft) {
    }

    @Override
    public void onChainDownloadStarted(Peer peer, int blocksLeft) {
    }

    @Override
    public Message onPreMessageReceived(Peer peer, Message m) {
        // Just pass the message right through for further processing.
        return m;
    }

    @Override
    public void onTransaction(Peer peer, Transaction t) {
    }

    @Override
    public List<Message> getData(Peer peer, GetDataMessage m) {
        return null;
    }

    @Override
    public void onPeersDiscovered(Set<PeerAddress> peerAddresses) {
    }

    @Override
    public void onPeerConnected(Peer peer, int peerCount) {
    }

    @Override
    public void onPeerDisconnected(Peer peer, int peerCount) {
    }
}
