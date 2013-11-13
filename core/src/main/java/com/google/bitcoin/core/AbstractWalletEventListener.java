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
 * Convenience implementation of {@link WalletEventListener}.
 */
public abstract class AbstractWalletEventListener implements WalletEventListener {
    @Override
    public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
        onChange();
    }

    @Override
    public void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
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
    public void onKeysAdded(Wallet wallet, List<ECKey> keys) {
        onChange();
    }

    @Override
    public void onScriptsAdded(Wallet wallet, List<Script> scripts) {
        onChange();
    }

    @Override
    public void onWalletChanged(Wallet wallet) {
        onChange();
    }

    public void onChange() {
    }
}
