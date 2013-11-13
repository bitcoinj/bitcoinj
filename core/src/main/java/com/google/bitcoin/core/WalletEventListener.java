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

import com.google.bitcoin.script.Script;

import java.math.BigInteger;
import java.util.List;

/**
 * <p>Implementors are called when the contents of the wallet changes, for instance due to receiving/sending money
 * or a block chain re-organize. It may be convenient to derive from {@link AbstractWalletEventListener} instead.</p>
 */
public interface WalletEventListener {
    /**
     * This is called when a transaction is seen that sends coins <b>to</b> this wallet, either because it
     * was broadcast across the network or because a block was received. If a transaction is seen when it was broadcast,
     * onCoinsReceived won't be called again when a block containing it is received. If you want to know when such a
     * transaction receives its first confirmation, register a {@link TransactionConfidence} event listener using
     * the object retrieved via {@link com.google.bitcoin.core.Transaction#getConfidence()}. It's safe to modify the
     * wallet in this callback, for example, by spending the transaction just received.
     *
     * @param wallet      The wallet object that received the coins
     * @param tx          The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance  Current balance of the wallet. This is the 'estimated' balance.
     */
    void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance);

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
    void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance);

    // TODO: Finish onReorganize to be more useful.
    /**
     * <p>This is called when a block is received that triggers a block chain re-organization.</p>
     *
     * <p>A re-organize means that the consensus (chain) of the network has diverged and now changed from what we
     * believed it was previously. Usually this won't matter because the new consensus will include all our old
     * transactions assuming we are playing by the rules. However it's theoretically possible for our balance to
     * change in arbitrary ways, most likely, we could lose some money we thought we had.</p>
     *
     * <p>It is safe to use methods of wallet whilst inside this callback.</p>
     */
    void onReorganize(Wallet wallet);

    /**
     * <p>Called when a transaction changes its confidence level. You can also attach event listeners to
     * the individual transactions, if you don't care about all of them. Usually you would save the wallet to disk after
     * receiving this callback unless you already set up autosaving.</p>
     *
     * <p>You should pay attention to this callback in case a transaction becomes <i>dead</i>, that is, a transaction
     * you believed to be active (send or receive) becomes overridden by the network. This can happen if</p>
     *
     * <ol>
     *     <li>You are sharing keys between wallets and accidentally create/broadcast a double spend.</li>
     *     <li>Somebody is attacking the network and reversing transactions, ie, the user is a victim of fraud.</li>
     *     <li>A bug: for example you create a transaction, broadcast it but fail to commit it. The {@link Wallet}
     *     will then re-use the same outputs when creating the next spend.</li>
     * </ol><p>
     *
     * <p>To find if the transaction is dead, you can use <tt>tx.getConfidence().getConfidenceType() ==
     * TransactionConfidence.ConfidenceType.DEAD</tt>. If it is, you should notify the user
     * in some way so they know the thing they bought may not arrive/the thing they sold should not be dispatched.</p>
     *
     * <p>Note that this callback will be invoked for every transaction in the wallet, for every new block that is
     * received (because the depth has changed). <b>If you want to update a UI view from the contents of the wallet
     * it is more efficient to use onWalletChanged instead.</b></p>
     */
    void onTransactionConfidenceChanged(Wallet wallet, Transaction tx);

    /**
     * <p>Designed for GUI applications to refresh their transaction lists. This callback is invoked in the following
     * situations:</p>
     *
     * <ol>
     *     <li>A new block is received (and thus building transactions got more confidence)</li>
     *     <li>A pending transaction is received</li>
     *     <li>A pending transaction changes confidence due to some non-new-block related event, such as being
     *     announced by more peers or by  a double-spend conflict being observed.</li>
     *     <li>A re-organize occurs. Call occurs only if the re-org modified any of our transactions.</li>
     *     <li>A new spend is committed to the wallet</li>
     * </ol>
     *
     * <p>When this is called you can refresh the UI contents from the wallet contents. It's more efficient to use
     * this rather than onTransactionConfidenceChanged() + onReorganize() because you only get one callback per block
     * rather than one per transaction per block. Note that this is <b>not</b> called when a key is added. </p>
     */
    void onWalletChanged(Wallet wallet);

    /**
     * Called whenever a new key is added to the wallet, whether that be via {@link Wallet#addKeys(java.util.List)}
     * or due to some other automatic derivation.
     */
    void onKeysAdded(Wallet wallet, List<ECKey> keys);

    /** Called whenever a new watched script is added to the wallet. */
    void onScriptsAdded(Wallet wallet, List<Script> scripts);
}
