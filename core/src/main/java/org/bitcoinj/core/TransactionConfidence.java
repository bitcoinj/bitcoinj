/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import com.google.common.collect.*;
import com.google.common.util.concurrent.*;
import org.bitcoinj.utils.*;
import org.bitcoinj.wallet.Wallet;

import javax.annotation.*;
import java.util.*;
import java.util.concurrent.*;

import static com.google.common.base.Preconditions.*;

// TODO: Modify the getDepthInBlocks method to require the chain height to be specified, in preparation for ceasing to touch every tx on every block.

/**
 * <p>A TransactionConfidence object tracks data you can use to make a confidence decision about a transaction.
 * It also contains some pre-canned rules for common scenarios: if you aren't really sure what level of confidence
 * you need, these should prove useful. You can get a confidence object using {@link Transaction#getConfidence()}.
 * They cannot be constructed directly.</p>
 *
 * <p>Confidence in a transaction can come in multiple ways:</p>
 *
 * <ul>
 * <li>Because you created it yourself and only you have the necessary keys.</li>
 * <li>Receiving it from a fully validating peer you know is trustworthy, for instance, because it's run by yourself.</li>
 * <li>Receiving it from a peer on the network you randomly chose. If your network connection is not being
 *     intercepted, you have a pretty good chance of connecting to a node that is following the rules.</li>
 * <li>Receiving it from multiple peers on the network. If your network connection is not being intercepted,
 *     hearing about a transaction from multiple peers indicates the network has accepted the transaction and
 *     thus miners likely have too (miners have the final say in whether a transaction becomes valid or not).</li>
 * <li>Seeing the transaction appear appear in a block on the main chain. Your confidence increases as the transaction
 *     becomes further buried under work. Work can be measured either in blocks (roughly, units of time), or
 *     amount of work done.</li>
 * </ul>
 *
 * <p>Alternatively, you may know that the transaction is "dead", that is, one or more of its inputs have
 * been double spent and will never confirm unless there is another re-org.</p>
 *
 * <p>TransactionConfidence is updated via the {@link org.bitcoinj.core.TransactionConfidence#incrementDepthInBlocks()}
 * method to ensure the block depth is up to date.</p>
 * To make a copy that won't be changed, use {@link org.bitcoinj.core.TransactionConfidence#duplicate()}.
 */
public class TransactionConfidence {

    /**
     * The peers that have announced the transaction to us. Network nodes don't have stable identities, so we use
     * IP address as an approximation. It's obviously vulnerable to being gamed if we allow arbitrary people to connect
     * to us, so only peers we explicitly connected to should go here.
     */
    private CopyOnWriteArrayList<PeerAddress> broadcastBy;
    /** The time the transaction was last announced to us. */
    private Date lastBroadcastedAt;
    /** The Transaction that this confidence object is associated with. */
    private final Sha256Hash hash;
    // Lazily created listeners array.
    private CopyOnWriteArrayList<ListenerRegistration<Listener>> listeners;

    // The depth of the transaction on the best chain in blocks. An unconfirmed block has depth 0.
    private int depth;

    /** Describes the state of the transaction in general terms. Properties can be read to learn specifics. */
    public enum ConfidenceType {
        /** If BUILDING, then the transaction is included in the best chain and your confidence in it is increasing. */
        BUILDING(1),

        /**
         * If PENDING, then the transaction is unconfirmed and should be included shortly, as long as it is being
         * announced and is considered valid by the network. A pending transaction will be announced if the containing
         * wallet has been attached to a live {@link PeerGroup} using {@link PeerGroup#addWallet(Wallet)}.
         * You can estimate how likely the transaction is to be included by connecting to a bunch of nodes then measuring
         * how many announce it, using {@link org.bitcoinj.core.TransactionConfidence#numBroadcastPeers()}.
         * Or if you saw it from a trusted peer, you can assume it's valid and will get mined sooner or later as well.
         */
        PENDING(2),

        /**
         * If DEAD, then it means the transaction won't confirm unless there is another re-org,
         * because some other transaction is spending one of its inputs. Such transactions should be alerted to the user
         * so they can take action, eg, suspending shipment of goods if they are a merchant.
         * It can also mean that a coinbase transaction has been made dead from it being moved onto a side chain.
         */
        DEAD(4),

        /**
         * If IN_CONFLICT, then it means there is another transaction (or several other transactions) spending one
         * (or several) of its inputs but nor this transaction nor the other/s transaction/s are included in the best chain.
         * The other/s transaction/s should be IN_CONFLICT too.
         * IN_CONFLICT can be thought as an intermediary state between a) PENDING and BUILDING or b) PENDING and DEAD.
         * Another common name for this situation is "double spend".
         */
        IN_CONFLICT(5),

        /**
         * If a transaction hasn't been broadcast yet, or there's no record of it, its confidence is UNKNOWN.
         */
        UNKNOWN(0);
        
        private int value;
        ConfidenceType(int value) {
            this.value = value;
        }
        
        public int getValue() {
            return value;
        }
    }

    private ConfidenceType confidenceType = ConfidenceType.UNKNOWN;
    private int appearedAtChainHeight = -1;
    // The transaction that double spent this one, if any.
    private Transaction overridingTransaction;

    /**
     * Information about where the transaction was first seen (network, sent direct from peer, created by ourselves).
     * Useful for risk analyzing pending transactions. Probably not that useful after a tx is included in the chain,
     * unless re-org double spends start happening frequently.
     */
    public enum Source {
        /** We don't know where the transaction came from. */
        UNKNOWN,
        /** We got this transaction from a network peer. */
        NETWORK,
        /** This transaction was created by our own wallet, so we know it's not a double spend. */
        SELF
    }
    private Source source = Source.UNKNOWN;

    public TransactionConfidence(Sha256Hash hash) {
        // Assume a default number of peers for our set.
        broadcastBy = new CopyOnWriteArrayList<PeerAddress>();
        listeners = new CopyOnWriteArrayList<ListenerRegistration<Listener>>();
        this.hash = hash;
    }

    /**
     * <p>A confidence listener is informed when the level of {@link TransactionConfidence} is updated by something, like
     * for example a {@link Wallet}. You can add listeners to update your user interface or manage your order tracking
     * system when confidence levels pass a certain threshold. <b>Note that confidence can go down as well as up.</b>
     * For example, this can happen if somebody is doing a double-spend attack against you. Whilst it's unlikely, your
     * code should be able to handle that in order to be correct.</p>
     *
     * <p>During listener execution, it's safe to remove the current listener but not others.</p>
     */
    public interface Listener {
        /** An enum that describes why a transaction confidence listener is being invoked (i.e. the class of change). */
        enum ChangeReason {
            /**
             * Occurs when the type returned by {@link org.bitcoinj.core.TransactionConfidence#getConfidenceType()}
             * has changed. For example, if a PENDING transaction changes to BUILDING or DEAD, then this reason will
             * be given. It's a high level summary.
             */
            TYPE,

            /**
             * Occurs when a transaction that is in the best known block chain gets buried by another block. If you're
             * waiting for a certain number of confirmations, this is the reason to watch out for.
             */
            DEPTH,

            /**
             * Occurs when a pending transaction (not in the chain) was announced by another connected peers. By
             * watching the number of peers that announced a transaction go up, you can see whether it's being
             * accepted by the network or not. If all your peers announce, it's a pretty good bet the transaction
             * is considered relayable and has thus reached the miners.
             */
            SEEN_PEERS,
        }
        void onConfidenceChanged(TransactionConfidence confidence, ChangeReason reason);
    }

    // This is used to ensure that confidence objects which aren't referenced from anywhere but which have an event
    // listener set on them don't become eligible for garbage collection. Otherwise the TxConfidenceTable, which only
    // has weak references to these objects, would not be enough to keep the event listeners working as transactions
    // propagate around the network - it cannot know directly if the API user is interested in the object, so it uses
    // heap reachability as a proxy for interest.
    //
    // We add ourselves to this set when a listener is added and remove ourselves when the listener list is empty.
    private static final Set<TransactionConfidence> pinnedConfidenceObjects = Collections.synchronizedSet(new HashSet<TransactionConfidence>());

    /**
     * <p>Adds an event listener that will be run when this confidence object is updated. The listener will be locked and
     * is likely to be invoked on a peer thread.</p>
     *
     * <p>Note that this is NOT called when every block arrives. Instead it is called when the transaction
     * transitions between confidence states, ie, from not being seen in the chain to being seen (not necessarily in
     * the best chain). If you want to know when the transaction gets buried under another block, consider using
     * a future from {@link #getDepthFuture(int)}.</p>
     */
    public void addEventListener(Executor executor, Listener listener) {
        checkNotNull(listener);
        listeners.addIfAbsent(new ListenerRegistration<Listener>(listener, executor));
        pinnedConfidenceObjects.add(this);
    }

    /**
     * <p>Adds an event listener that will be run when this confidence object is updated. The listener will be locked and
     * is likely to be invoked on a peer thread.</p>
     *
     * <p>Note that this is NOT called when every block arrives. Instead it is called when the transaction
     * transitions between confidence states, ie, from not being seen in the chain to being seen (not necessarily in
     * the best chain). If you want to know when the transaction gets buried under another block, implement a
     * {@link BlockChainListener}, attach it to a {@link BlockChain} and then use the getters on the
     * confidence object to determine the new depth.</p>
     */
    public void addEventListener(Listener listener) {
        addEventListener(Threading.USER_THREAD, listener);
    }

    public boolean removeEventListener(Listener listener) {
        checkNotNull(listener);
        boolean removed = ListenerRegistration.removeFromList(listener, listeners);
        if (listeners.isEmpty())
            pinnedConfidenceObjects.remove(this);
        return removed;
    }

    /**
     * Returns the chain height at which the transaction appeared if confidence type is BUILDING.
     * @throws IllegalStateException if the confidence type is not BUILDING.
     */
    public synchronized int getAppearedAtChainHeight() {
        if (getConfidenceType() != ConfidenceType.BUILDING)
            throw new IllegalStateException("Confidence type is " + getConfidenceType() + ", not BUILDING");
        return appearedAtChainHeight;
    }

    /**
     * The chain height at which the transaction appeared, if it has been seen in the best chain. Automatically sets
     * the current type to {@link ConfidenceType#BUILDING} and depth to one.
     */
    public synchronized void setAppearedAtChainHeight(int appearedAtChainHeight) {
        if (appearedAtChainHeight < 0)
            throw new IllegalArgumentException("appearedAtChainHeight out of range");
        this.appearedAtChainHeight = appearedAtChainHeight;
        this.depth = 1;
        setConfidenceType(ConfidenceType.BUILDING);
    }

    /**
     * Returns a general statement of the level of confidence you can have in this transaction.
     */
    public synchronized ConfidenceType getConfidenceType() {
        return confidenceType;
    }

    /**
     * Called by other objects in the system, like a {@link Wallet}, when new information about the confidence of a 
     * transaction becomes available.
     */
    public synchronized void setConfidenceType(ConfidenceType confidenceType) {
        if (confidenceType == this.confidenceType)
            return;
        this.confidenceType = confidenceType;
        if (confidenceType != ConfidenceType.DEAD) {
            overridingTransaction = null;
        }
        if (confidenceType == ConfidenceType.PENDING || confidenceType == ConfidenceType.IN_CONFLICT) {
            depth = 0;
            appearedAtChainHeight = -1;
        }
    }


    /**
     * Called by a {@link Peer} when a transaction is pending and announced by a peer. The more peers announce the
     * transaction, the more peers have validated it (assuming your internet connection is not being intercepted).
     * If confidence is currently unknown, sets it to {@link ConfidenceType#PENDING}. Does not run listeners.
     *
     * @param address IP address of the peer, used as a proxy for identity.
     * @return true if marked, false if this address was already seen
     */
    public boolean markBroadcastBy(PeerAddress address) {
        lastBroadcastedAt = Utils.now();
        if (!broadcastBy.addIfAbsent(address))
            return false;  // Duplicate.
        synchronized (this) {
            if (getConfidenceType() == ConfidenceType.UNKNOWN) {
                this.confidenceType = ConfidenceType.PENDING;
            }
        }
        return true;
    }

    /**
     * Returns how many peers have been passed to {@link TransactionConfidence#markBroadcastBy}.
     */
    public int numBroadcastPeers() {
        return broadcastBy.size();
    }

    /**
     * Returns a snapshot of {@link PeerAddress}es that announced the transaction.
     */
    public Set<PeerAddress> getBroadcastBy() {
        ListIterator<PeerAddress> iterator = broadcastBy.listIterator();
        return Sets.newHashSet(iterator);
    }

    /** Returns true if the given address has been seen via markBroadcastBy() */
    public boolean wasBroadcastBy(PeerAddress address) {
        return broadcastBy.contains(address);
    }

    /** Return the time the transaction was last announced to us. */
    public Date getLastBroadcastedAt() {
        return lastBroadcastedAt;
    }

    /** Set the time the transaction was last announced to us. */
    public void setLastBroadcastedAt(Date lastBroadcastedAt) {
        this.lastBroadcastedAt = lastBroadcastedAt;
    }

    @Override
    public synchronized String toString() {
        StringBuilder builder = new StringBuilder();
        int peers = numBroadcastPeers();
        if (peers > 0) {
            builder.append("Seen by ").append(peers).append(peers > 1 ? " peers" : " peer");
            if (lastBroadcastedAt != null)
                builder.append(" (most recently: ").append(Utils.dateTimeFormat(lastBroadcastedAt)).append(")");
            builder.append(". ");
        }
        switch (getConfidenceType()) {
            case UNKNOWN:
                builder.append("Unknown confidence level.");
                break;
            case DEAD:
                builder.append("Dead: overridden by double spend and will not confirm.");
                break;
            case PENDING:
                builder.append("Pending/unconfirmed.");
                break;
            case IN_CONFLICT:
                builder.append("In conflict.");
                break;
            case BUILDING:
                builder.append(String.format(Locale.US, "Appeared in best chain at height %d, depth %d.",
                        getAppearedAtChainHeight(), getDepthInBlocks()));
                break;
        }
        if (source != Source.UNKNOWN)
            builder.append(" Source: ").append(source);
        return builder.toString();
    }

    /**
     * Called by the wallet when the tx appears on the best chain and a new block is added to the top. Updates the
     * internal counter that tracks how deeply buried the block is.
     *
     * @return the new depth
     */
    public synchronized int incrementDepthInBlocks() {
        return ++this.depth;
    }

    /**
     * <p>Depth in the chain is an approximation of how much time has elapsed since the transaction has been confirmed.
     * On average there is supposed to be a new block every 10 minutes, but the actual rate may vary. Bitcoin Core
     * considers a transaction impractical to reverse after 6 blocks, but as of EOY 2011 network
     * security is high enough that often only one block is considered enough even for high value transactions. For low
     * value transactions like songs, or other cheap items, no blocks at all may be necessary.</p>
     *     
     * <p>If the transaction appears in the top block, the depth is one. If it's anything else (pending, dead, unknown)
     * the depth is zero.</p>
     */
    public synchronized int getDepthInBlocks() {
        return depth;
    }

    /*
     * Set the depth in blocks. Having one block confirmation is a depth of one.
     */
    public synchronized void setDepthInBlocks(int depth) {
        this.depth = depth;
    }

    /**
     * Erases the set of broadcast/seen peers. This cannot be called whilst the confidence is PENDING. It is useful
     * for saving memory and wallet space once a tx is buried so deep it doesn't seem likely to go pending again.
     */
    public void clearBroadcastBy() {
        checkState(getConfidenceType() != ConfidenceType.PENDING);
        broadcastBy.clear();
        lastBroadcastedAt = null;
    }

    /**
     * If this transaction has been overridden by a double spend (is dead), this call returns the overriding transaction.
     * Note that this call <b>can return null</b> if you have migrated an old wallet, as pre-Jan 2012 wallets did not
     * store this information.
     *
     * @return the transaction that double spent this one
     * @throws IllegalStateException if confidence type is not DEAD.
     */
    public synchronized Transaction getOverridingTransaction() {
        if (getConfidenceType() != ConfidenceType.DEAD)
            throw new IllegalStateException("Confidence type is " + getConfidenceType() +
                                            ", not DEAD");
        return overridingTransaction;
    }

    /**
     * Called when the transaction becomes newly dead, that is, we learn that one of its inputs has already been spent
     * in such a way that the double-spending transaction takes precedence over this one. It will not become valid now
     * unless there is a re-org. Automatically sets the confidence type to DEAD. The overriding transaction may not
     * directly double spend this one, but could also have double spent a dependency of this tx.
     */
    public synchronized void setOverridingTransaction(@Nullable Transaction overridingTransaction) {
        this.overridingTransaction = overridingTransaction;
        setConfidenceType(ConfidenceType.DEAD);
    }

    /** Returns a copy of this object. Event listeners are not duplicated. */
    public TransactionConfidence duplicate() {
        TransactionConfidence c = new TransactionConfidence(hash);
        c.broadcastBy.addAll(broadcastBy);
        c.lastBroadcastedAt = lastBroadcastedAt;
        synchronized (this) {
            c.confidenceType = confidenceType;
            c.overridingTransaction = overridingTransaction;
            c.appearedAtChainHeight = appearedAtChainHeight;
        }
        return c;
    }

    /**
     * Call this after adjusting the confidence, for cases where listeners should be notified. This has to be done
     * explicitly rather than being done automatically because sometimes complex changes to transaction states can
     * result in a series of confidence changes that are not really useful to see separately. By invoking listeners
     * explicitly, more precise control is available. Note that this will run the listeners on the user code thread.
     */
    public void queueListeners(final Listener.ChangeReason reason) {
        for (final ListenerRegistration<Listener> registration : listeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onConfidenceChanged(TransactionConfidence.this, reason);
                }
            });
        }
    }

    /**
     * The source of a transaction tries to identify where it came from originally. For instance, did we download it
     * from the peer to peer network, or make it ourselves, or receive it via Bluetooth, or import it from another app,
     * and so on. This information is useful for {@link org.bitcoinj.wallet.CoinSelector} implementations to risk analyze
     * transactions and decide when to spend them.
     */
    public synchronized Source getSource() {
        return source;
    }

    /**
     * The source of a transaction tries to identify where it came from originally. For instance, did we download it
     * from the peer to peer network, or make it ourselves, or receive it via Bluetooth, or import it from another app,
     * and so on. This information is useful for {@link org.bitcoinj.wallet.CoinSelector} implementations to risk analyze
     * transactions and decide when to spend them.
     */
    public synchronized void setSource(Source source) {
        this.source = source;
    }

    /**
     * Returns a future that completes when the transaction has been confirmed by "depth" blocks. For instance setting
     * depth to one will wait until it appears in a block on the best chain, and zero will wait until it has been seen
     * on the network.
     */
    public synchronized ListenableFuture<TransactionConfidence> getDepthFuture(final int depth, Executor executor) {
        final SettableFuture<TransactionConfidence> result = SettableFuture.create();
        if (getDepthInBlocks() >= depth) {
            result.set(this);
        }
        addEventListener(executor, new Listener() {
            @Override public void onConfidenceChanged(TransactionConfidence confidence, ChangeReason reason) {
                if (getDepthInBlocks() >= depth) {
                    removeEventListener(this);
                    result.set(confidence);
                }
            }
        });
        return result;
    }

    public synchronized ListenableFuture<TransactionConfidence> getDepthFuture(final int depth) {
        return getDepthFuture(depth, Threading.USER_THREAD);
    }

    public Sha256Hash getTransactionHash() {
        return hash;
    }
}
