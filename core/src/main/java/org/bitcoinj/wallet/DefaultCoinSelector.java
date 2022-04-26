/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.wallet;

import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionOutput;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * This class implements a {@link CoinSelector} which attempts to get the highest priority
 * possible. This means that the transaction is the most likely to get confirmed. Note that this means we may end up
 * "spending" more priority than would be required to get the transaction we are creating confirmed.
 */
public class DefaultCoinSelector implements CoinSelector, Predicate<TransactionOutput> {

    protected DefaultCoinSelector() {
    }

    // Total may be lower than target here, if the given candidates were insufficient to create to requested
    // transaction.
    @Override
    public CoinSelection select(Coin target, List<TransactionOutput> candidates) {
        // TODO: Take in network parameters when instantiated, and then test against the current network. Or just have a boolean parameter for "give me everything"
        // When calculating the wallet balance, we may be asked to select all possible coins, if so, avoid sorting
        // them in order to improve performance.
        if (!target.equals(NetworkParameters.MAX_MONEY)) {
            // Sort the inputs by age*value so we get the highest "coindays" spent.
            // TODO: Consider changing the wallets internal format to track just outputs and keep them ordered.
            return CoinSelector.sortSelect(target, candidates,  CoinSelector.TXOUT_COMPARATOR, this);
        } else {
            return CoinSelector.select(target, candidates, this);
        }
    }

    @Override
    public boolean test(TransactionOutput transactionOutput) {
        // Only pick chain-included transactions, or transactions that are ours and pending.
        return shouldSelect(transactionOutput.getParentTransaction());
    }

    /**
     * Sort a mutable list of {@link TransactionOutput} in place with the {@link CoinSelector#TXOUT_COMPARATOR}.
     * @param outputs mutable list to be sorted in-place
     * @deprecated Use functional composition with the static methods in {@link CoinSelector} and/or {@link CoinSelector#TXOUT_COMPARATOR} instead
     */
    @Deprecated
    @VisibleForTesting static void sortOutputs(ArrayList<TransactionOutput> outputs) {
        outputs.sort(CoinSelector.TXOUT_COMPARATOR);
    }

    /** Sub-classes can override this to just customize whether transactions are usable, but keep age sorting. */
    protected boolean shouldSelect(Transaction tx) {
        if (tx != null) {
            return isSelectable(tx);
        }
        return true;
    }

    public static boolean isSelectable(Transaction tx) {
        // Only pick chain-included transactions, or transactions that are ours and pending.
        TransactionConfidence confidence = tx.getConfidence();
        TransactionConfidence.ConfidenceType type = confidence.getConfidenceType();
        return type.equals(TransactionConfidence.ConfidenceType.BUILDING) ||

               type.equals(TransactionConfidence.ConfidenceType.PENDING) &&
               confidence.getSource().equals(TransactionConfidence.Source.SELF) &&
               // In regtest mode we expect to have only one peer, so we won't see transactions propagate.
               (confidence.numBroadcastPeers() > 0 || tx.getParams().getId().equals(NetworkParameters.ID_REGTEST));
    }

    private static DefaultCoinSelector instance;

    /** Returns a global static instance of the selector. */
    public static DefaultCoinSelector get() {
        // This doesn't have to be thread safe as the object has no state, so discarded duplicates are
        // harmless.
        if (instance == null)
            instance = new DefaultCoinSelector();
        return instance;
    }
}
