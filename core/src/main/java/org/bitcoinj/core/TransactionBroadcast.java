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

package org.bitcoinj.core;

import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.base.internal.FutureUtils;
import org.bitcoinj.base.internal.StreamUtils;
import org.bitcoinj.base.internal.InternalUtils;
import org.bitcoinj.core.listeners.PreMessageReceivedEventListener;
import org.bitcoinj.utils.ListenableCompletableFuture;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Function;

import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Represents a single transaction broadcast that we are performing. A broadcast occurs after a new transaction is created
 * (typically by a {@link Wallet}) and needs to be sent to the network. A broadcast can succeed or fail. A success is
 * defined as seeing the transaction be announced by peers via inv messages, thus indicating their acceptance. A failure
 * is defined as not reaching acceptance within a timeout period, or getting an explicit reject message from a peer
 * indicating that the transaction was not acceptable.
 */
public class TransactionBroadcast {
    private static final Logger log = LoggerFactory.getLogger(TransactionBroadcast.class);

    // This future completes when all broadcast messages were sent (to a buffer)
    private final CompletableFuture<TransactionBroadcast> sentFuture = new CompletableFuture<>();

    // This future completes when we have verified that more than numWaitingFor Peers have seen the broadcast
    private final CompletableFuture<TransactionBroadcast> seenFuture = new CompletableFuture<>();
    private final PeerGroup peerGroup;
    private final Transaction tx;
    private int minConnections;
    private boolean dropPeersAfterBroadcast = false;
    private int numWaitingFor;

    /** Used for shuffling the peers before broadcast: unit tests can replace this to make themselves deterministic. */
    @VisibleForTesting
    public static Random random = new Random();
    
    // Tracks which nodes sent us a reject message about this broadcast, if any. Useful for debugging.
    private final Map<Peer, RejectMessage> rejects = Collections.synchronizedMap(new HashMap<Peer, RejectMessage>());

    TransactionBroadcast(PeerGroup peerGroup, Transaction tx) {
        this.peerGroup = peerGroup;
        this.tx = tx;
        this.minConnections = Math.max(1, peerGroup.getMinBroadcastConnections());
    }

    // Only for mock broadcasts.
    private TransactionBroadcast(Transaction tx) {
        this.peerGroup = null;
        this.tx = tx;
    }

    public Transaction transaction() {
        return tx;
    }

    @VisibleForTesting
    public static TransactionBroadcast createMockBroadcast(Transaction tx, final CompletableFuture<Transaction> future) {
        return new TransactionBroadcast(tx) {
            @Override
            public ListenableCompletableFuture<Transaction> broadcast() {
                return ListenableCompletableFuture.of(future);
            }

            @Override
            public ListenableCompletableFuture<Transaction> future() {
                return ListenableCompletableFuture.of(future);
            }
        };
    }

    /**
     * @return future that completes when some number of remote peers has rebroadcast the transaction
     * @deprecated Use {@link #awaitRelayed()} (and maybe {@link CompletableFuture#thenApply(Function)})
     */
    @Deprecated
    public ListenableCompletableFuture<Transaction> future() {
        return ListenableCompletableFuture.of(awaitRelayed().thenApply(TransactionBroadcast::transaction));
    }

    public void setMinConnections(int minConnections) {
        this.minConnections = minConnections;
    }

    public void setDropPeersAfterBroadcast(boolean dropPeersAfterBroadcast) {
        this.dropPeersAfterBroadcast = dropPeersAfterBroadcast;
    }

    private final PreMessageReceivedEventListener rejectionListener = new PreMessageReceivedEventListener() {
        @Override
        public Message onPreMessageReceived(Peer peer, Message m) {
            if (m instanceof RejectMessage) {
                RejectMessage rejectMessage = (RejectMessage)m;
                if (tx.getTxId().equals(rejectMessage.getRejectedObjectHash())) {
                    rejects.put(peer, rejectMessage);
                    int size = rejects.size();
                    long threshold = Math.round(numWaitingFor / 2.0);
                    if (size > threshold) {
                        log.warn("Threshold for considering broadcast rejected has been reached ({}/{})", size, threshold);
                        seenFuture.completeExceptionally(new RejectedTransactionException(tx, rejectMessage));
                        peerGroup.removePreMessageReceivedEventListener(this);
                    }
                }
            }
            return m;
        }
    };

    // TODO: Should this method be moved into the PeerGroup?
    /**
     * Broadcast this transaction to the proper calculated number of peers. Returns a future that completes when the message
     * has been "sent" to a set of remote peers. The {@link TransactionBroadcast} itself is the returned type/value for the future.
     * <p>
     * The complete broadcast process includes the following steps:
     * <ol>
     *     <li>Wait until enough {@link org.bitcoinj.core.Peer}s are connected.</li>
     *     <li>Broadcast the transaction to a determined number of {@link org.bitcoinj.core.Peer}s</li>
     *     <li>Wait for confirmation from a determined number of remote peers that they have received the broadcast</li>
     *     <li>Mark {@link TransactionBroadcast#awaitRelayed()} ()} ("seen future") as complete</li>
     * </ol>
     * The future returned from this method completes when Step 2 is completed.
     * <p>
     * It should further be noted that "broadcast" in this class means that
     * {@link org.bitcoinj.net.MessageWriteTarget#writeBytes} has completed successfully which means the message has
     * been sent to the "OS network buffer" -- see {@link org.bitcoinj.net.MessageWriteTarget#writeBytes} or its implementation.
     * <p>
     * @return A future that completes when the message has been sent (or at least buffered) to the correct number of remote Peers. The future
     * will complete exceptionally if <i>any</i> of the peer broadcasts fails.
     */
    public CompletableFuture<TransactionBroadcast> broadcastOnly() {
        peerGroup.addPreMessageReceivedEventListener(Threading.SAME_THREAD, rejectionListener);
        log.info("Waiting for {} peers required for broadcast, we have {} ...", minConnections, peerGroup.getConnectedPeers().size());
        final Context context = Context.get();
        return peerGroup.waitForPeers(minConnections).thenComposeAsync( peerList /* not used */ -> {
            Context.propagate(context);
            // We now have enough connected peers to send the transaction.
            // This can be called immediately if we already have enough. Otherwise it'll be called from a peer
            // thread.

            // We will send the tx simultaneously to half the connected peers and wait to hear back from at least half
            // of the other half, i.e., with 4 peers connected we will send the tx to 2 randomly chosen peers, and then
            // wait for it to show up on one of the other two. This will be taken as sign of network acceptance. As can
            // be seen, 4 peers is probably too little - it doesn't taken many broken peers for tx propagation to have
            // a big effect.
            List<Peer> peers = peerGroup.getConnectedPeers();    // snapshots
            // Prepare to send the transaction by adding a listener that'll be called when confidence changes.
            tx.getConfidence().addEventListener(new ConfidenceChange());
            // Bitcoin Core sends an inv in this case and then lets the peer request the tx data. We just
            // blast out the TX here for a couple of reasons. Firstly it's simpler: in the case where we have
            // just a single connection we don't have to wait for getdata to be received and handled before
            // completing the future in the code immediately below. Secondly, it's faster. The reason the
            // Bitcoin Core sends an inv is privacy - it means you can't tell if the peer originated the
            // transaction or not. However, we are not a fully validating node and this is advertised in
            // our version message, as SPV nodes cannot relay it doesn't give away any additional information
            // to skip the inv here - we wouldn't send invs anyway.
            List<Peer> broadcastPeers = chooseBroadcastPeers(peers);
            int numToBroadcastTo = broadcastPeers.size();
            numWaitingFor = (int) Math.ceil((peers.size() - numToBroadcastTo) / 2.0);
            log.info("broadcastTransaction: We have {} peers, adding {} to the memory pool", peers.size(), tx.getTxId());
            log.info("Sending to {} peers, will wait for {}, sending to: {}", numToBroadcastTo, numWaitingFor, InternalUtils.joiner(",").join(peers));
            List<CompletableFuture<Void>> sentFutures = broadcastPeers.stream()
                    .map(this::broadcastOne)
                    .collect(StreamUtils.toUnmodifiableList());
            // Complete successfully if ALL peer.sendMessage complete successfully, fail otherwise
            return CompletableFuture.allOf(sentFutures.toArray(new CompletableFuture[0]));
        }, Threading.SAME_THREAD)
        .whenComplete((v, err) -> {
            // Complete `sentFuture` (even though it is currently unused)
            if (err == null) {
                log.info("broadcast has been written to correct number of peers with peer.sendMessage(tx)");
                sentFuture.complete(this);
            } else {
                log.error("broadcast - one ore more peers failed to send", err);
                sentFuture.completeExceptionally(err);
            }
        })
        .thenCompose(v -> sentFuture);
    }

    /**
     * Broadcast the transaction and wait for confirmation that the transaction has been received by the appropriate
     * number of Peers before completing.
     * @return A future that completes when the message has been relayed by the appropriate number of remote peers
     */
    public CompletableFuture<TransactionBroadcast> broadcastAndAwaitRelay() {
        return broadcastOnly()
                .thenCompose(broadcast -> this.seenFuture);
    }

    /**
     * Wait for confirmation the transaction has been relayed.
     * @return A future that completes when the message has been relayed by the appropriate number of remote peers
     */
    public CompletableFuture<TransactionBroadcast> awaitRelayed() {
        return seenFuture;
    }

    /**
     * Wait for confirmation the transaction has been sent to a remote peer. (Or at least buffered to be sent to
     * a peer.)
     * @return A future that completes when the message has been relayed by the appropriate number of remote peers
     */
    public CompletableFuture<TransactionBroadcast> awaitSent() {
        return sentFuture;
    }

    /**
     * If you migrate to {@link #broadcastAndAwaitRelay()} and need a {@link CompletableFuture} that returns
     *  {@link Transaction} you can use:
     * <pre>{@code
     *  CompletableFuture<Transaction> seenFuture = broadcast
     *              .broadcastAndAwaitRelay()
     *              .thenApply(TransactionBroadcast::transaction);
     * }</pre>
     * @deprecated Use {@link #broadcastAndAwaitRelay()} or {@link #broadcastOnly()} as appropriate
     */
    @Deprecated
    public ListenableCompletableFuture<Transaction> broadcast() {
        return ListenableCompletableFuture.of(
                broadcastAndAwaitRelay().thenApply(TransactionBroadcast::transaction)
        );
    }

    private CompletableFuture<Void> broadcastOne(Peer peer) {
        try {
            CompletableFuture<Void> future = peer.sendMessage(tx);
            if (dropPeersAfterBroadcast) {
                // We drop the peer shortly after the transaction has been sent, because this peer will not
                // send us back useful broadcast confirmations.
                future.thenRunAsync(dropPeerAfterBroadcastHandler(peer), Threading.THREAD_POOL);
            }
            // We don't record the peer as having seen the tx in the memory pool because we want to track only
            // how many peers announced to us.
            return future;
        } catch (Exception e) {
            log.error("Caught exception sending to {}", peer, e);
            return FutureUtils.failedFuture(e);
        }
    }

    private static Runnable dropPeerAfterBroadcastHandler(Peer peer) {
        return () ->  {
            try {
                Thread.sleep(Duration.ofSeconds(1).toMillis());
            } catch (InterruptedException e) {
                log.warn("Sleep before drop-peer-after-broadcast interrupted. Peer will be closed now.");
            }
            peer.close();
        };
    }

    /**
     * Randomly choose a subset of connected peers to broadcast to
     * @param connectedPeers connected peers to chose from
     * @return list of chosen broadcast peers
     */
    private List<Peer> chooseBroadcastPeers(List<Peer> connectedPeers) {
        int numToBroadcastTo = (int) Math.max(1, Math.round(Math.ceil(connectedPeers.size() / 2.0)));
        List<Peer> peerListCopy = new ArrayList<>(connectedPeers);
        Collections.shuffle(peerListCopy, random);
        return peerListCopy.subList(0, numToBroadcastTo);
    }

    private int numSeemPeers;
    private boolean mined;

    private class ConfidenceChange implements TransactionConfidence.Listener {
        @Override
        public void onConfidenceChanged(TransactionConfidence conf, ChangeReason reason) {
            // The number of peers that announced this tx has gone up.
            int numSeenPeers = conf.numBroadcastPeers() + rejects.size();
            boolean mined = tx.getAppearsInHashes() != null;
            log.info("broadcastTransaction: {}:  TX {} seen by {} peers{}", reason, tx.getTxId(),
                    numSeenPeers, mined ? " and mined" : "");

            // Progress callback on the requested thread.
            invokeAndRecord(numSeenPeers, mined);

            if (numSeenPeers >= numWaitingFor || mined) {
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
                log.info("broadcastTransaction: {} complete", tx.getTxId());
                peerGroup.removePreMessageReceivedEventListener(rejectionListener);
                conf.removeEventListener(this);
                seenFuture.complete(TransactionBroadcast.this);  // RE-ENTRANCY POINT
            }
        }
    }

    private void invokeAndRecord(int numSeenPeers, boolean mined) {
        synchronized (this) {
            this.numSeemPeers = numSeenPeers;
            this.mined = mined;
        }
        invokeProgressCallback(numSeenPeers, mined);
    }

    private void invokeProgressCallback(int numSeenPeers, boolean mined) {
        final ProgressCallback callback;
        Executor executor;
        synchronized (this) {
            callback = this.callback;
            executor = this.progressCallbackExecutor;
        }
        if (callback != null) {
            final double progress = Math.min(1.0, mined ? 1.0 : numSeenPeers / (double) numWaitingFor);
            checkState(progress >= 0.0 && progress <= 1.0, () ->
                    "" + progress);
            try {
                if (executor == null)
                    callback.onBroadcastProgress(progress);
                else
                    executor.execute(() -> callback.onBroadcastProgress(progress));
            } catch (Throwable e) {
                log.error("Exception during progress callback", e);
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /** An interface for receiving progress information on the propagation of the tx, from 0.0 to 1.0 */
    public interface ProgressCallback {
        /**
         * onBroadcastProgress will be invoked on the provided executor when the progress of the transaction
         * broadcast has changed, because the transaction has been announced by another peer or because the transaction
         * was found inside a mined block (in this case progress will go to 1.0 immediately). Any exceptions thrown
         * by this callback will be logged and ignored.
         */
        void onBroadcastProgress(double progress);
    }

    @Nullable private ProgressCallback callback;
    @Nullable private Executor progressCallbackExecutor;

    /**
     * Sets the given callback for receiving progress values, which will run on the user thread. See
     * {@link Threading} for details.  If the broadcast has already started then the callback will
     * be invoked immediately with the current progress.
     */
    public void setProgressCallback(ProgressCallback callback) {
        setProgressCallback(callback, Threading.USER_THREAD);
    }

    /**
     * Sets the given callback for receiving progress values, which will run on the given executor. If the executor
     * is null then the callback will run on a network thread and may be invoked multiple times in parallel. You
     * probably want to provide your UI thread or Threading.USER_THREAD for the second parameter. If the broadcast
     * has already started then the callback will be invoked immediately with the current progress.
     */
    public void setProgressCallback(ProgressCallback callback, @Nullable Executor executor) {
        boolean shouldInvoke;
        int num;
        boolean mined;
        synchronized (this) {
            this.callback = callback;
            this.progressCallbackExecutor = executor;
            num = this.numSeemPeers;
            mined = this.mined;
            shouldInvoke = numWaitingFor > 0;
        }
        if (shouldInvoke)
            invokeProgressCallback(num, mined);
    }
}
