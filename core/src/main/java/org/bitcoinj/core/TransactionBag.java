/*
 * Copyright 2014 Giannis Dzegoutanis
 * Copyright 2019 Andreas Schildbach
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

import javax.annotation.Nullable;

import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletTransaction;

import java.util.Map;

/**
 * This interface is used to abstract the {@link Wallet} and the {@link Transaction}
 */
public interface TransactionBag {
    /**
     * Look for a public key which hashes to the given hash and (optionally) is used for a specific script type.
     * @param pubKeyHash hash of the public key to look for
     * @param scriptType only look for given usage (currently {@link Script.ScriptType#P2PKH} or {@link Script.ScriptType#P2WPKH}) or {@code null} if we don't care
     * @return true if hash was found
     */
    boolean isPubKeyHashMine(byte[] pubKeyHash, @Nullable Script.ScriptType scriptType);

    /** Returns true if this wallet is watching transactions for outputs with the script. */
    boolean isWatchedScript(Script script);

    /** Returns true if this wallet contains a keypair with the given public key. */
    boolean isPubKeyMine(byte[] pubKey);

    /** Returns true if this wallet knows the script corresponding to the given hash. */
    boolean isPayToScriptHashMine(byte[] payToScriptHash);

    /** Returns transactions from a specific pool. */
    Map<Sha256Hash, Transaction> getTransactionPool(WalletTransaction.Pool pool);
}
