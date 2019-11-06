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

package org.bitcoinj.testing;

import org.bitcoinj.core.*;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.SettableFuture;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A mock transaction broadcaster can be used in unit tests as a stand-in for a PeerGroup. It catches any transactions
 * broadcast through it and makes them available via the {@link #waitForTransaction()} method. Using that will cause
 * the broadcast to be seen as if it never propagated though, so you may instead use {@link #waitForTxFuture()} and then
 * set the returned future when you want the "broadcast" to be completed.
 */
public class MockTransactionBroadcaster implements TransactionBroadcaster {
    private final ReentrantLock lock = Threading.lock(MockTransactionBroadcaster.class);
    private final Wallet wallet;

    public static class TxFuturePair {
        public final Transaction tx;
        public final SettableFuture<Transaction> future;

        public TxFuturePair(Transaction tx, SettableFuture<Transaction> future) {
            this.tx = tx;
            this.future = future;
        }

        /** Tells the broadcasting code that the broadcast was a success, just does future.set(tx) */
        public void succeed() {
            future.set(tx);
        }
    }

    private final LinkedBlockingQueue<TxFuturePair> broadcasts = new LinkedBlockingQueue<>();

    /** Sets this mock broadcaster on the given wallet. */
    public MockTransactionBroadcaster(Wallet wallet) {
        // This code achieves nothing directly, but it sets up the broadcaster/peergroup > wallet lock ordering
        // so inversions can be caught.
        lock.lock();
        try {
            this.wallet = wallet;
            wallet.setTransactionBroadcaster(this);
            wallet.getPendingTransactions();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public TransactionBroadcast broadcastTransaction(Transaction tx) {
        // Use a lock just to catch lock ordering inversions e.g. wallet->broadcaster.
        lock.lock();
        try {
            SettableFuture<Transaction> result = SettableFuture.create();
            broadcasts.put(new TxFuturePair(tx, result));
            Futures.addCallback(result, new FutureCallback<Transaction>() {
                @Override
                public void onSuccess(Transaction result) {
                    try {
                        wallet.receivePending(result, null);
                    } catch (VerificationException e) {
                        throw new RuntimeException(e);
                    }
                }

                @Override
                public void onFailure(Throwable t) {
                }
            }, MoreExecutors.directExecutor());
            return TransactionBroadcast.createMockBroadcast(tx, result);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            lock.unlock();
        }
    }

    public Transaction waitForTransaction() {
        return waitForTxFuture().tx;
    }

    public Transaction waitForTransactionAndSucceed() {
        TxFuturePair pair = waitForTxFuture();
        pair.succeed();
        return pair.tx;
    }

    public TxFuturePair waitForTxFuture() {
        try {
            return broadcasts.take();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public int size() {
        return broadcasts.size();
    }
}
