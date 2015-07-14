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

package org.bitcoinj.core.listeners;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Wallet;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.KeyChainEventListener;

import java.util.List;

/**
 * <p>Implementors are called when the contents of the wallet changes, for instance due to receiving/sending money
 * or a block chain re-organize. It may be convenient to derive from {@link AbstractWalletEventListener} instead.</p>
 */
public interface WalletCoinEventListener {
    /**
     * This is called when a transaction is seen that sends coins <b>to</b> this wallet, either because it
     * was broadcast across the network or because a block was received. If a transaction is seen when it was broadcast,
     * onCoinsReceived won't be called again when a block containing it is received. If you want to know when such a
     * transaction receives its first confirmation, register a {@link TransactionConfidence} event listener using
     * the object retrieved via {@link org.bitcoinj.core.Transaction#getConfidence()}. It's safe to modify the
     * wallet in this callback, for example, by spending the transaction just received.
     *
     * @param wallet      The wallet object that received the coins
     * @param tx          The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance  Current balance of the wallet. This is the 'estimated' balance.
     */
    void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance);

    /**
     * This is called when a transaction is seen that sends coins <b>from</b> this wallet, either
     * because it was broadcast across the network or because a block was received. This may at first glance seem
     * useless, because in the common case you already know about such transactions because you created them with
     * the Wallets createSend/sendCoins methods. However when you have a wallet containing only keys, and you wish
     * to replay the block chain to fill it with transactions, it's useful to find out when a transaction is discovered
     * that sends coins from the wallet.<p>
     *
     * It's safe to modify the wallet from inside this callback, but if you're replaying the block chain you should
     * be careful to avoid such modifications. Otherwise your changes may be overridden by new data from the chain.
     *
     * @param wallet       The wallet object that this callback relates to (that sent the coins).
     * @param tx           The transaction that sent the coins to someone else.
     * @param prevBalance  The wallets balance before this transaction was seen.
     * @param newBalance   The wallets balance after this transaction was seen. This is the 'estimated' balance.
     */
    void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance);
}
