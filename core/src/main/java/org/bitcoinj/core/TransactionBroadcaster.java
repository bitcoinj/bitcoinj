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

import org.bitcoinj.base.Sha256Hash;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * A general interface which declares the ability to broadcast transactions. This is implemented
 * by {@link PeerGroup}.
 */
public interface TransactionBroadcaster {
    // Deprecate
    /** Broadcast the given transaction on the network */
    TransactionBroadcast broadcastTransaction(final Transaction tx);

//    /**
//    * Send a transaction asynchronously with success defined by default criteria. Most network-related
//     * failure conditions should result in exceptional completion with a subclass of {@link BroadcastFailure}
//     * that should contain failure information.
//     * @param tx transaction to send (must be finalized/immutable or exceptional completion will occur)
//     * @return A future that completes successfully.
//     */
//   CompletableFuture<BroadcastSuccess> sendTransaction(Transaction tx);

    interface BroadcastOptions {
        Duration timeout();
    }

    // Information available on success or failure
    interface BroadcastResult {
        Sha256Hash txId();
    }

    interface BroadcastSuccess extends BroadcastResult {};
    abstract class BroadcastFailure extends RuntimeException implements BroadcastResult {};
}
