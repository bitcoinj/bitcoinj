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
import com.google.common.util.concurrent.SettableFuture;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.ReentrantLock;

public class MockTransactionBroadcaster implements TransactionBroadcaster {
    private ReentrantLock lock = Threading.lock("mock tx broadcaster");

    public LinkedBlockingQueue<Transaction> broadcasts = new LinkedBlockingQueue<Transaction>();

    public MockTransactionBroadcaster(Wallet wallet) {
        // This code achieves nothing directly, but it sets up the broadcaster/peergroup > wallet lock ordering
        // so inversions can be caught.
        lock.lock();
        try {
            wallet.getPendingTransactions();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public SettableFuture<Transaction> broadcastTransaction(Transaction tx) {
        // Use a lock just to catch lock ordering inversions.
        lock.lock();
        try {
            SettableFuture<Transaction> result = SettableFuture.create();
            broadcasts.put(tx);
            return result;
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            lock.unlock();
        }
    }
}
