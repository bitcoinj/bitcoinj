/**
 * Copyright 2011 Google Inc.
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

import java.math.BigInteger;

/**
 * Implementing a subclass WalletEventListener allows you to learn when the contents of the wallet changes due to
 * receiving money or a block chain re-organize. Methods are called with the event listener object locked so your
 * implementation does not have to be thread safe. The default method implementations simply call onChange().
 */
public abstract class AbstractWalletEventListener implements WalletEventListener {
    /**
     * This is called on a Peer thread when a block is received that sends some coins to you. Note that this will
     * also be called when downloading the block chain as the wallet balance catches up so if you don't want that
     * register the event listener after the chain is downloaded. It's safe to use methods of wallet during the
     * execution of this callback.
     *
     * @param wallet      The wallet object that received the coins/
     * @param tx          The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance  Current balance of the wallet.
     */
    public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
        onChange();
    }

    /**
     * This is called on a Peer thread when a transaction is seen that sends coins <b>from</b> this wallet, either
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
     * @param newBalance   The wallets balance after this transaction was seen (should be less than prevBalance).
     */
    public void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
        onChange();
    }

    /**
     * This is called on a Peer thread when a block is received that triggers a block chain re-organization.<p>
     *
     * A re-organize means that the consensus (chain) of the network has diverged and now changed from what we
     * believed it was previously. Usually this won't matter because the new consensus will include all our old
     * transactions assuming we are playing by the rules. However it's theoretically possible for our balance to
     * change in arbitrary ways, most likely, we could lose some money we thought we had.<p>
     *
     * It is safe to use methods of wallet whilst inside this callback.
     *
     * TODO: Finish this interface.
     */
    public void onReorganize(Wallet wallet) {
        onChange();
    }

    /**
     * Called on a Peer thread when a transaction changes its confidence level. You can also attach event listeners to
     * the individual transactions, if you don't care about all of them. Usually you would save the wallet to disk after
     * receiving this callback.<p>
     *
     * You should pay attention to this callback in case a transaction becomes <i>dead</i>, that is, somebody
     * successfully executed a double spend against you. This is a (very!) rare situation but the user should be
     * notified that money they thought they had, was taken away from them.<p>
     *
     * @param wallet
     * @param tx
     */
    public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
        onChange();
    }

    /**
     * Called by the other default method implementations when something (anything) changes in the wallet.
     */
    public void onChange() {
    }
}
