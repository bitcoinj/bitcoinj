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
 * Implementing WalletEventListener allows you to learn when the contents of the wallet changes due to
 * receiving money or a block chain re-organize. Methods are called with the event listener object locked so your
 * implementation does not have to be thread safe. It may be convenient to derive from
 * {@link AbstractWalletEventListener} instead.<p>
 *
 * It is safe to call methods of the wallet during event listener execution, and also for a listener to remove itself.
 * Other types of modifications generally aren't safe.
 */
public interface WalletEventListener {
    /**
     * This is called on a Peer thread when a transaction is seen that sends coins to this wallet, either because it
     * was broadcast across the network or because a block was received. If a transaction is seen when it was broadcast,
     * onCoinsReceived won't be called again when a block containing it is received. If you want to know when such a
     * transaction receives its first confirmation, register a {@link TransactionConfidence} event listener using
     * the object retrieved via {@link com.google.bitcoin.core.Transaction#getConfidence()}. It's safe to modify the
     * wallet in this callback, for example, by spending the transaction just received.
     *
     * @param wallet      The wallet object that received the coins/
     * @param tx          The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance  Current balance of the wallet.
     */
    void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance);

    /**
     * This is called on a Peer thread when a block is received that triggers a block chain re-organization.<p>
     * <p/>
     * A re-organize means that the consensus (chain) of the network has diverged and now changed from what we
     * believed it was previously. Usually this won't matter because the new consensus will include all our old
     * transactions assuming we are playing by the rules. However it's theoretically possible for our balance to
     * change in arbitrary ways, most likely, we could lose some money we thought we had.<p>
     * <p/>
     * It is safe to use methods of wallet whilst inside this callback.
     * <p/>
     * TODO: Finish this interface.
     */
    void onReorganize(Wallet wallet);

    /**
     * This is called on a Peer thread when a transaction becomes <i>dead</i>. A dead transaction is one that has
     * been overridden by a double spend from the network and so will never confirm no matter how long you wait.<p>
     * <p/>
     * A dead transaction can occur if somebody is attacking the network, or by accident if keys are being shared.
     * You can use this event handler to inform the user of the situation. A dead spend will show up in the BitCoin
     * C++ client of the recipient as 0/unconfirmed forever, so if it was used to purchase something,
     * the user needs to know their goods will never arrive.
     *
     * @param deadTx        The transaction that is newly dead.
     * @param replacementTx The transaction that killed it.
     */
    void onDeadTransaction(Wallet wallet, Transaction deadTx, Transaction replacementTx);
}
