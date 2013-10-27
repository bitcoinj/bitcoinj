/**
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

package com.google.bitcoin.core;

import com.google.bitcoin.utils.Threading;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a single transaction broadcast that we are performing. A broadcast occurs after a new transaction is created
 * (typically by a {@link Wallet} and needs to be sent to the network. A broadcast can succeed or fail. A success is
 * defined as seeing the transaction be announced by peers via inv messages, thus indicating their acceptance. A failure
 * is defined as not reaching acceptance within a timeout period, or getting an explicit error message from peers
 * indicating that the transaction was not acceptable (this isn't currently implemented in v0.8 of the network protocol
 * but should be coming in 0.9).
 */
public class TransactionBroadcast {
    private static final Logger log = LoggerFactory.getLogger(TransactionBroadcast.class);

    private final SettableFuture<Transaction> future = SettableFuture.create();
    private final PeerGroup peerGroup;
    private final Transaction tx;
    private int minConnections;

    public TransactionBroadcast(PeerGroup peerGroup, Transaction tx) {
        this.peerGroup = peerGroup;
        this.tx = tx;
        this.minConnections = Math.max(1, peerGroup.getMinBroadcastConnections());
    }

    public ListenableFuture<Transaction> future() {
        return future;
    }

    public void setMinConnections(int minConnections) {
        this.minConnections = minConnections;
    }

    public ListenableFuture<Transaction> broadcast() {
        log.info("Waiting for {} peers required for broadcast ...", minConnections);
        ListenableFuture<PeerGroup> peerAvailabilityFuture = peerGroup.waitForPeers(minConnections);
        peerAvailabilityFuture.addListener(new Runnable() {
            public void run() {
                // We now have enough connected peers to send the transaction.
                // This can be called immediately if we already have enough. Otherwise it'll be called from a peer
                // thread.

                // Pick a peer to be the lucky recipient of our tx. This can race if the peer we pick dies immediately.
                final Peer somePeer = peerGroup.getDownloadPeer();
                log.info("broadcastTransaction: Enough peers, adding {} to the memory pool and sending to {}",
                        tx.getHashAsString(), somePeer);
                final Transaction pinnedTx = peerGroup.getMemoryPool().seen(tx, somePeer.getAddress());
                // Prepare to send the transaction by adding a listener that'll be called when confidence changes.
                // Only bother with this if we might actually hear back:
                if (minConnections > 1) pinnedTx.getConfidence().addEventListener(new TransactionConfidence.Listener() {
                    public void onConfidenceChanged(Transaction tx, TransactionConfidence.Listener.ChangeReason reason) {
                        // The number of peers that announced this tx has gone up.
                        final TransactionConfidence conf = tx.getConfidence();
                        int numSeenPeers = conf.numBroadcastPeers();
                        boolean mined = tx.getAppearsInHashes() != null;
                        log.info("broadcastTransaction: {}:  TX {} seen by {} peers{}", reason, pinnedTx.getHashAsString(),
                                numSeenPeers, mined ? " and mined" : "");
                        if (!(numSeenPeers >= minConnections || mined))
                            return;
                        // We've seen the min required number of peers announce the transaction, or it was included
                        // in a block. Normally we'd expect to see it fully propagate before it gets mined, but
                        // it can be that a block is solved very soon after broadcast, and it's also possible that
                        // due to version skew and changes in the relay rules our transaction is not going to
                        // fully propagate yet can get mined anyway.
                        //
                        // Note that we can't wait for the current number of connected peers right now because we
                        // could have added more peers after the broadcast took place, which means they won't
                        // have seen the transaction. In future when peers sync up their memory pools after they
                        // connect we could come back and change this.
                        //
                        // We're done! It's important that the PeerGroup lock is not held (by this thread) at this
                        // point to avoid triggering inversions when the Future completes.
                        log.info("broadcastTransaction: {} complete", pinnedTx.getHashAsString());
                        tx.getConfidence().removeEventListener(this);
                        future.set(pinnedTx);  // RE-ENTRANCY POINT
                    }
                });

                // Satoshis code sends an inv in this case and then lets the peer request the tx data. We just
                // blast out the TX here for a couple of reasons. Firstly it's simpler: in the case where we have
                // just a single connection we don't have to wait for getdata to be received and handled before
                // completing the future in the code immediately below. Secondly, it's faster. The reason the
                // Satoshi client sends an inv is privacy - it means you can't tell if the peer originated the
                // transaction or not. However, we are not a fully validating node and this is advertised in
                // our version message, as SPV nodes cannot relay it doesn't give away any additional information
                // to skip the inv here - we wouldn't send invs anyway.
                //
                // TODO: The peer we picked might be dead by now. If we can't write the message, pick again and retry.
                somePeer.sendMessage(pinnedTx);
                // If we've been limited to talk to only one peer, we can't wait to hear back because the
                // remote peer won't tell us about transactions we just announced to it for obvious reasons.
                // So we just have to assume we're done, at that point. This happens when we're not given
                // any peer discovery source and the user just calls connectTo() once.
                if (minConnections == 1) {
                    future.set(pinnedTx);
                }
            }
        }, Threading.SAME_THREAD);
        return future;
    }
}
