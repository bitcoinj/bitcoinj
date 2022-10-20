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

package org.bitcoinj.core.listeners;

import org.bitcoinj.core.Transaction;
import org.bitcoinj.wallet.Wallet;

/**
 * Implementors are called when confidence of a transaction changes.
 */
public interface TransactionConfidenceEventListener {
    /**
     * Called when a transaction changes its confidence level. You can also attach event listeners to
     * the individual transactions, if you don't care about all of them. Usually you would save the wallet to disk after
     * receiving this callback unless you already set up autosaving.
     * <p>
     * You should pay attention to this callback in case a transaction becomes <i>dead</i>, that is, a transaction
     * you believed to be active (send or receive) becomes overridden by the network. This can happen if:
     *
     * <ol>
     *     <li>You are sharing keys between wallets and accidentally create/broadcast a double spend.</li>
     *     <li>Somebody is attacking the network and reversing transactions, ie, the user is a victim of fraud.</li>
     *     <li>A bug: for example you create a transaction, broadcast it but fail to commit it. The {@link Wallet}
     *     will then re-use the same outputs when creating the next spend.</li>
     * </ol>
     *
     * To find if the transaction is dead, you can use:
     * <pre>
     * {@code
     * tx.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.DEAD}
     * </pre>
     * If it is, you should notify the user in some way so they know the thing they bought may not arrive/the thing they sold should not be dispatched.
     * <p>
     * Note that this callback will be invoked for every transaction in the wallet, for every new block that is
     * received (because the depth has changed). <b>If you want to update a UI view from the contents of the wallet
     * it is more efficient to use onWalletChanged instead.</b>
     */
    void onTransactionConfidenceChanged(Wallet wallet, Transaction tx);
}
