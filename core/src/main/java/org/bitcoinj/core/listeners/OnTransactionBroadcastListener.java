/*
 * Copyright by the original author or authors.
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

import org.bitcoinj.core.Peer;
import org.bitcoinj.core.Transaction;

/**
 * Called when a new transaction is broadcast over the network.
 */
public interface OnTransactionBroadcastListener {
    /**
     * Called when a new transaction is broadcast over the network.
     */
    void onTransaction(Peer peer, Transaction t);
}
