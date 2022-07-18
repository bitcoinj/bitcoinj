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

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.WalletTransaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * This interface is used to abstract the {@link org.bitcoinj.wallet.Wallet} and the {@link Transaction}
 */
public interface TransactionBag {
    Logger log = LoggerFactory.getLogger(TransactionOutput.class);

    /**
     * Look for a public key which hashes to the given hash and (optionally) is used for a specific script type.
     * @param pubKeyHash hash of the public key to look for
     * @param scriptType only look for given usage (currently {@link ScriptType#P2PKH} or {@link ScriptType#P2WPKH}) or {@code null} if we don't care
     * @return true if hash was found
     */
    boolean isPubKeyHashMine(byte[] pubKeyHash, @Nullable ScriptType scriptType);

    /** Returns true if this wallet is watching transactions for outputs with the script. */
    boolean isWatchedScript(Script script);

    /** Returns true if this wallet contains a keypair with the given public key. */
    boolean isPubKeyMine(byte[] pubKey);

    /** Returns true if this wallet knows the script corresponding to the given hash. */
    boolean isPayToScriptHashMine(byte[] payToScriptHash);

    /** Returns transactions from a specific pool. */
    Map<Sha256Hash, Transaction> getTransactionPool(WalletTransaction.Pool pool);

    /**
     * Returns false if this transaction has at least one output that is owned by the given wallet and unspent, true
     * otherwise.
     */
    default boolean isEveryOwnedOutputSpent(Transaction tx) {
        for (TransactionOutput output : tx.getOutputs()) {
            if (output.isAvailableForSpending() && isMineOrWatched(output))
                return false;
        }
        return true;
    }

    /**
     * <p>Returns the list of transaction outputs, whether spent or unspent, that match a wallet by address or that are
     * watched by a wallet, i.e., transaction outputs whose script's address is controlled by the wallet and transaction
     * outputs whose script is watched by the wallet.</p>
     *
     * @param tx The transaction.
     * @return linked list of outputs relevant to the wallet in this transaction
     */
    default List<TransactionOutput> getWalletOutputs(Transaction tx) {
        List<TransactionOutput> walletOutputs = new LinkedList<>();
        for (TransactionOutput o : tx.getOutputs()) {
            if (!isMineOrWatched(o)) continue;
            walletOutputs.add(o);
        }

        return walletOutputs;
    }

    /**
     * Returns the difference of {@link #getValueSentToMe(Transaction)} and {@link #getValueSentFromMe(Transaction)}.
     */
    default Coin getValue(Transaction tx) throws ScriptException {
        // TODO: Can we lose the commented-out caching code?
        // FIXME: TEMP PERF HACK FOR ANDROID - this crap can go away once we have a real payments API.
//        boolean isAndroid = Utils.isAndroidRuntime();
//        if (isAndroid && cachedValue != null && cachedForBag == wallet)
//            return cachedValue;
        Coin result = getValueSentToMe(tx).subtract(getValueSentFromMe(tx));
//        if (isAndroid) {
//            cachedValue = result;
//            cachedForBag = wallet;
//        }
        return result;
    }

    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet.
     */
    default Coin getValueSentToMe(Transaction tx) {
        // This is tested in WalletTest.
        Coin v = Coin.ZERO;
        for (TransactionOutput o : tx.getOutputs()) {
            if (!this.isMineOrWatched(o)) continue;
            v = v.add(o.getValue());
        }
        return v;
    }

    /**
     * Calculates the sum of the inputs that are spending coins with keys in the wallet. This requires the
     * transactions sending coins to those keys to be in the wallet. This method will not attempt to download the
     * blocks containing the input transactions if the key is in the wallet but the transactions are not.
     *
     * @return sum of the inputs that are spending coins with keys in the wallet
     */
    default Coin getValueSentFromMe(Transaction tx) throws ScriptException {
        // This is tested in WalletTest.
        Coin v = Coin.ZERO;
        for (TransactionInput input : tx.getInputs()) {
            // This input is taking value from a transaction in our wallet. To discover the value,
            // we must find the connected transaction.
            TransactionOutput connected = input.getConnectedOutput(getTransactionPool(WalletTransaction.Pool.UNSPENT));
            if (connected == null)
                connected = input.getConnectedOutput(getTransactionPool(WalletTransaction.Pool.SPENT));
            if (connected == null)
                connected = input.getConnectedOutput(getTransactionPool(WalletTransaction.Pool.PENDING));
            if (connected == null)
                continue;
            // The connected output may be the change to the sender of a previous input sent to this wallet. In this
            // case we ignore it.
            if (!isMineOrWatched(connected))
                continue;
            v = v.add(connected.getValue());
        }
        return v;
    }


    default boolean isMineOrWatched(TransactionOutput output) {
        return isMine(output) || isWatched(output);
    }

    /**
     * Returns true if this output is to a key, or an address we have the keys for, in the wallet.
     */
    default boolean isWatched(TransactionOutput output) {
        try {
            Script script = output.getScriptPubKey();
            return isWatchedScript(script);
        } catch (ScriptException e) {
            // Just means we didn't understand the output of this transaction: ignore it.
            log.debug("Could not parse tx output script: {}", e.toString());
            return false;
        }
    }

    /**
     * Returns true if this output is to a key, or an address we have the keys for, in the wallet.
     */
    default boolean isMine(TransactionOutput output) {
        try {
            Script script = output.getScriptPubKey();
            if (ScriptPattern.isP2PK(script))
                return isPubKeyMine(ScriptPattern.extractKeyFromP2PK(script));
            else if (ScriptPattern.isP2SH(script))
                return isPayToScriptHashMine(ScriptPattern.extractHashFromP2SH(script));
            else if (ScriptPattern.isP2PKH(script))
                return isPubKeyHashMine(ScriptPattern.extractHashFromP2PKH(script),
                        ScriptType.P2PKH);
            else if (ScriptPattern.isP2WPKH(script))
                return isPubKeyHashMine(ScriptPattern.extractHashFromP2WH(script),
                        ScriptType.P2WPKH);
            else
                return false;
        } catch (ScriptException e) {
            // Just means we didn't understand the output of this transaction: ignore it.
            log.debug("Could not parse tx {} output script: {}",
                    output.getParentTransaction() != null ? output.getParentTransaction().getTxId() : "(no parent)", e.toString());
            return false;
        }
    }
}
