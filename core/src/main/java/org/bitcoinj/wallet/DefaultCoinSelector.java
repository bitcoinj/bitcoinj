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
import com.google.common.math.LongMath;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionOutput;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class implements a {@link CoinSelector} which attempts to get the highest priority
 * possible. This means that the transaction is the most likely to get confirmed. Note that this means we may end up
 * "spending" more priority than would be required to get the transaction we are creating confirmed.
 */
public class DefaultCoinSelector implements CoinSelector {
    protected DefaultCoinSelector() {
    }

    @Override
    public CoinSelection select(Coin target, List<TransactionOutput> candidates) {
        ArrayList<TransactionOutput> selected = new ArrayList<>();
        // Sort the inputs by age*value so we get the highest "coindays" spent.
        // TODO: Consider changing the wallets internal format to track just outputs and keep them ordered.
        ArrayList<TransactionOutput> sortedOutputs = new ArrayList<>(candidates);
        // When calculating the wallet balance, we may be asked to select all possible coins, if so, avoid sorting
        // them in order to improve performance.
        // TODO: Take in network parameters when instantiated, and then test against the current network. Or just have a boolean parameter for "give me everything"
        if (!target.equals(BitcoinNetwork.MAX_MONEY)) {
            sortOutputs(sortedOutputs);
        }
        // Now iterate over the sorted outputs until we have got as close to the target as possible or a little
        // bit over (excessive value will be change).
        long total = 0;
        for (TransactionOutput output : sortedOutputs) {
            if (total >= target.value) break;
            // Only pick chain-included transactions, or transactions that are ours and pending.
            if (!shouldSelect(output.getParentTransaction())) continue;
            selected.add(output);
            total = LongMath.checkedAdd(total, output.getValue().value);
        }
        // Total may be lower than target here, if the given candidates were insufficient to create to requested
        // transaction.
        return new CoinSelection(selected);
    }

    @VisibleForTesting static void sortOutputs(ArrayList<TransactionOutput> outputs) {
        Collections.sort(outputs, (a, b) -> {
            int depth1 = a.getParentTransactionDepthInBlocks();
            int depth2 = b.getParentTransactionDepthInBlocks();
            Coin aValue = a.getValue();
            Coin bValue = b.getValue();
            BigInteger aCoinDepth = BigInteger.valueOf(aValue.value).multiply(BigInteger.valueOf(depth1));
            BigInteger bCoinDepth = BigInteger.valueOf(bValue.value).multiply(BigInteger.valueOf(depth2));
            int c1 = bCoinDepth.compareTo(aCoinDepth);
            if (c1 != 0) return c1;
            // The "coin*days" destroyed are equal, sort by value alone to get the lowest transaction size.
            int c2 = bValue.compareTo(aValue);
            if (c2 != 0) return c2;
            // They are entirely equivalent (possibly pending) so sort by hash to ensure a total ordering.
            BigInteger aHash = a.getParentTransactionHash().toBigInteger();
            BigInteger bHash = b.getParentTransactionHash().toBigInteger();
            return aHash.compareTo(bHash);
        });
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
               (confidence.numBroadcastPeers() > 0 || tx.getParams().getId().equals(BitcoinNetwork.ID_REGTEST));
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
