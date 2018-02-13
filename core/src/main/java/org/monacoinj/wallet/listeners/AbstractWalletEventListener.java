/*
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

package org.monacoinj.wallet.listeners;

import org.monacoinj.core.Coin;
import org.monacoinj.core.ECKey;
import org.monacoinj.core.Transaction;
import org.monacoinj.script.Script;
import org.monacoinj.wallet.Wallet;

import java.util.List;

/**
 * Deprecated: implement the more specific event listener interfaces instead.
 */
@Deprecated
public abstract class AbstractWalletEventListener extends AbstractKeyChainEventListener implements WalletEventListener {
    @Override
    public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
        onChange();
    }

    @Override
    public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
        onChange();
    }

    @Override
    public void onReorganize(Wallet wallet) {
        onChange();
    }

    @Override
    public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
        onChange();
    }

    @Override
    public void onKeysAdded(List<ECKey> keys) {
        onChange();
    }

    @Override
    public void onScriptsChanged(Wallet wallet, List<Script> scripts, boolean isAddingScripts) {
        onChange();
    }

    @Override
    public void onWalletChanged(Wallet wallet) {
        onChange();
    }

    /**
     * Default method called on change events.
     */
    public void onChange() {
    }
}
