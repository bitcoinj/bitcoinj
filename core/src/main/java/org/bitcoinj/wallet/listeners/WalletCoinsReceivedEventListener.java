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

package org.bitcoinj.wallet.listeners;

import org.bitcoinj.base.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.wallet.Wallet;

/**
 * <p>Implementors are called when the contents of the wallet changes, for instance due to receiving/sending money
 * or a block chain re-organize.</p>
 */
public interface WalletCoinsReceivedEventListener {
    /**
     * This is called when a transaction is seen that sends coins <b>to</b> this wallet, either because it
     * was broadcast across the network or because a block was received. If a transaction is seen when it was broadcast,
     * onCoinsReceived won't be called again when a block containing it is received. If you want to know when such a
     * transaction receives its first confirmation, register a {@link TransactionConfidence} event listener using
     * the object retrieved via {@link Transaction#getConfidence()}. It's safe to modify the
     * wallet in this callback, for example, by spending the transaction just received.
     *
     * @param wallet      The wallet object that received the coins
     * @param tx          The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance  Current balance of the wallet. This is the 'estimated' balance.
     */
    void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance);
}
