/*
 * Copyright 2012 Google Inc.
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

import org.bitcoinj.utils.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>Tracks transactions that are being announced across the network. Typically one is created for you by a
 * {@link PeerGroup} and then given to each Peer to update. The current purpose is to let Peers update the confidence
 * (number of peers broadcasting). It helps address an attack scenario in which a malicious remote peer (or several)
 * feeds you invalid transactions, eg, ones that spend coins which don't exist. If you don't see most of the peers
 * announce the transaction within a reasonable time, it may be that the TX is not valid. Alternatively, an attacker
 * may control your entire internet connection: in this scenario counting broadcasting peers does not help you.</p>
 *
 * <p>It is <b>not</b> at this time directly equivalent to the Satoshi clients memory pool, which tracks
 * all transactions not currently included in the best chain - it's simply a cache.</p>
 */
public class MemoryPool {
    private static final Logger log = LoggerFactory.getLogger(MemoryPool.class);
    protected ReentrantLock lock = Threading.lock("mempool");

    // For each transaction we may have seen:
    //   - only its hash in an inv packet
    //   - the full transaction itself, if we asked for it to be sent to us (or a peer sent it regardless), or if we
    //     sent it.
    //
    // Before we see the full transaction, we need to track how many peers advertised it, so we can estimate its
    // confidence pre-chain inclusion assuming an un-tampered with network connection. After we see the full transaction
    // we need to switch from tracking that data in the Entry to tracking it in the TransactionConfidence object itself.
    private static class WeakTransactionReference extends WeakReference<Transaction> {
        public Sha256Hash hash;
        public WeakTransactionReference(Transaction tx, ReferenceQueue<Transaction> queue) {
            super(tx, queue);
            hash = tx.getHash();
        }
    }
    private static class Entry {
        // Invariants: one of the two fields must be null, to indicate which is used.
        Set<PeerAddress> addresses;
        // We keep a weak reference to the transaction. This means that if no other bit of code finds the transaction
        // worth keeping around it will drop out of memory and we will, at some point, forget about it, which means
        // both addresses and tx.get() will be null. When this happens the WeakTransactionReference appears in the queue
        // allowing us to delete the associated entry (the tx itself has already gone away).
        WeakTransactionReference tx;
    }
    private LinkedHashMap<Sha256Hash, Entry> memoryPool;

    // This ReferenceQueue gets entries added to it when they are only weakly reachable, ie, the MemoryPool is the
    // only thing that is tracking the transaction anymore. We check it from time to time and delete memoryPool entries
    // corresponding to expired transactions. In this way memory usage of the system is in line with however many
    // transactions you actually care to track the confidence of. We can still end up with lots of hashes being stored
    // if our peers flood us with invs but the MAX_SIZE param caps this.
    private ReferenceQueue<Transaction> referenceQueue;

    /** The max size of a memory pool created with the no-args constructor. */
    public static final int MAX_SIZE = 1000;

    /**
     * Creates a memory pool that will track at most the given number of transactions (allowing you to bound memory
     * usage).
     * @param size Max number of transactions to track. The pool will fill up to this size then stop growing.
     */
    public MemoryPool(final int size) {
        memoryPool = new LinkedHashMap<Sha256Hash, Entry>() {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Sha256Hash, Entry> entry) {
                // An arbitrary choice to stop the memory used by tracked transactions getting too huge in the event
                // of some kind of DoS attack.
                return size() > size;
            }
        };
        referenceQueue = new ReferenceQueue<Transaction>();
    }

    /**
     * Creates a memory pool that will track at most {@link MemoryPool#MAX_SIZE} entries. You should normally use
     * this constructor.
     */
    public MemoryPool() {
        this(MAX_SIZE);
    }

    /**
     * If any transactions have expired due to being only weakly reachable through us, go ahead and delete their
     * memoryPool entries - it means we downloaded the transaction and sent it to various event listeners, none of
     * which bothered to keep a reference. Typically, this is because the transaction does not involve any keys that
     * are relevant to any of our wallets.
     */
    private void cleanPool() {
        lock.lock();
        try {
            Reference<? extends Transaction> ref;
            while ((ref = referenceQueue.poll()) != null) {
                // Find which transaction got deleted by the GC.
                WeakTransactionReference txRef = (WeakTransactionReference) ref;
                // And remove the associated map entry so the other bits of memory can also be reclaimed.
                memoryPool.remove(txRef.hash);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the number of peers that have seen the given hash recently.
     */
    public int numBroadcastPeers(Sha256Hash txHash) {
        lock.lock();
        try {
            cleanPool();
            Entry entry = memoryPool.get(txHash);
            if (entry == null) {
                // No such TX known.
                return 0;
            } else if (entry.tx == null) {
                // We've seen at least one peer announce with an inv.
                checkNotNull(entry.addresses);
                return entry.addresses.size();
            } else {
                final Transaction tx = entry.tx.get();
                if (tx == null) {
                    // We previously downloaded this transaction, but nothing cared about it so the garbage collector threw
                    // it away. We also deleted the set that tracked which peers had seen it. Treat this case as a zero and
                    // just delete it from the map.
                    memoryPool.remove(txHash);
                    return 0;
                } else {
                    checkState(entry.addresses == null);
                    return tx.getConfidence().numBroadcastPeers();
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Puts the tx into the table and returns either it, or a different Transaction object that has the same hash.
     * Unlike seen and the other methods, this one does not imply that a tx has been announced by a peer and does
     * not mark it as such.
     */
    public Transaction intern(Transaction tx) {
        lock.lock();
        try {
            cleanPool();
            Entry entry = memoryPool.get(tx.getHash());
            if (entry != null) {
                // This TX or its hash have been previously interned.
                if (entry.tx != null) {
                    // We already interned it (but may have thrown it away).
                    checkState(entry.addresses == null);
                    // We only want one canonical object instance for a transaction no matter how many times it is
                    // deserialized.
                    Transaction transaction = entry.tx.get();
                    if (transaction != null) {
                        // We saw it before and kept it around. Hand back the canonical copy.
                        tx = transaction;
                    }
                    return tx;
                } else {
                    // We received a transaction that we have previously seen announced but not downloaded until now.
                    checkNotNull(entry.addresses);
                    entry.tx = new WeakTransactionReference(tx, referenceQueue);
                    Set<PeerAddress> addrs = entry.addresses;
                    entry.addresses = null;
                    TransactionConfidence confidence = tx.getConfidence();
                    log.debug("Adding tx [{}] {} to the memory pool",
                            confidence.numBroadcastPeers(), tx.getHashAsString());
                    for (PeerAddress a : addrs) {
                        markBroadcast(a, tx);
                    }
                    return tx;
                }
            } else {
                // This often happens when we are downloading a Bloom filtered chain, or recursively downloading
                // dependencies of a relevant transaction (see Peer.downloadDependencies).
                log.debug("Provided with a downloaded transaction we didn't see announced yet: {}", tx.getHashAsString());
                entry = new Entry();
                entry.tx = new WeakTransactionReference(tx, referenceQueue);
                memoryPool.put(tx.getHash(), entry);
                return tx;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Called by peers when they receive a "tx" message containing a valid serialized transaction.
     * @param tx The TX deserialized from the wire.
     * @param byPeer The Peer that received it.
     * @return An object that is semantically the same TX but may be a different object instance.
     */
    public Transaction seen(Transaction tx, PeerAddress byPeer) {
        lock.lock();
        try {
            final Transaction interned = intern(tx);
            markBroadcast(byPeer, interned);
            return interned;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Called by peers when they see a transaction advertised in an "inv" message. It either will increase the
     * confidence of the pre-existing transaction or will just keep a record of the address for future usage.
     */
    public void seen(Sha256Hash hash, PeerAddress byPeer) {
        lock.lock();
        try {
            cleanPool();
            Entry entry = memoryPool.get(hash);
            if (entry != null) {
                // This TX or its hash have been previously announced.
                if (entry.tx != null) {
                    checkState(entry.addresses == null);
                    Transaction tx = entry.tx.get();
                    if (tx != null) {
                        markBroadcast(byPeer, tx);
                        log.debug("{}: Peer announced transaction we have seen before [{}] {}",
                                byPeer, tx.getConfidence().numBroadcastPeers(), tx.getHashAsString());
                    } else {
                        // The inv is telling us about a transaction that we previously downloaded, and threw away
                        // because nothing found it interesting enough to keep around. So do nothing.
                    }
                } else {
                    checkNotNull(entry.addresses);
                    entry.addresses.add(byPeer);
                    log.debug("{}: Peer announced transaction we have seen announced before [{}] {}",
                            byPeer, entry.addresses.size(), hash);
                }
            } else {
                // This TX has never been seen before.
                entry = new Entry();
                // TODO: Using hashsets here is inefficient compared to just having an array.
                entry.addresses = new HashSet<PeerAddress>();
                entry.addresses.add(byPeer);
                memoryPool.put(hash, entry);
                log.info("{}: Peer announced new transaction [1] {}", byPeer, hash);
            }
        } finally {
            lock.unlock();
        }
    }

    private void markBroadcast(PeerAddress byPeer, Transaction tx) {
        checkState(lock.isHeldByCurrentThread());
        final TransactionConfidence confidence = tx.getConfidence();
        if (confidence.markBroadcastBy(byPeer))
            confidence.queueListeners(TransactionConfidence.Listener.ChangeReason.SEEN_PEERS);
    }

    /**
     * Returns the {@link Transaction} for the given hash if we have downloaded it, or null if that hash is unknown or
     * we only saw advertisements for it yet or it has been downloaded but garbage collected due to nowhere else
     * holding a reference to it.
     */
    @Nullable
    public Transaction get(Sha256Hash hash) {
        lock.lock();
        try {
            Entry entry = memoryPool.get(hash);
            if (entry == null) return null;  // Unknown.
            if (entry.tx == null) return null;  // Seen but only in advertisements.
            if (entry.tx.get() == null) return null;  // Was downloaded but garbage collected.
            Transaction tx = entry.tx.get();
            checkNotNull(tx);
            return tx;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns true if the TX identified by hash has been seen before (ie, in an inv). Note that a transaction that
     * was broadcast, downloaded and nothing kept a reference to it will eventually be cleared out by the garbage
     * collector and wasSeen() will return false - it does not keep a permanent record of every hash ever broadcast.
     */
    public boolean maybeWasSeen(Sha256Hash hash) {
        lock.lock();
        try {
            Entry entry = memoryPool.get(hash);
            return entry != null;
        } finally {
            lock.unlock();
        }
    }
}
