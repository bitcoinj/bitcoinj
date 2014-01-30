package com.google.bitcoin.wallet;

import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionConfidence;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.params.RegTestParams;
import com.google.common.annotations.VisibleForTesting;

import java.math.BigInteger;
import java.util.*;

/**
 * This class implements a {@link com.google.bitcoin.wallet.CoinSelector} which attempts to get the highest priority
 * possible. This means that the transaction is the most likely to get confirmed. Note that this means we may end up
 * "spending" more priority than would be required to get the transaction we are creating confirmed.
 */
public class DefaultCoinSelector implements CoinSelector {
    public CoinSelection select(BigInteger biTarget, LinkedList<TransactionOutput> candidates) {
        long target = biTarget.longValue();
        HashSet<TransactionOutput> selected = new HashSet<TransactionOutput>();
        // Sort the inputs by age*value so we get the highest "coindays" spent.
        // TODO: Consider changing the wallets internal format to track just outputs and keep them ordered.
        ArrayList<TransactionOutput> sortedOutputs = new ArrayList<TransactionOutput>(candidates);
        // When calculating the wallet balance, we may be asked to select all possible coins, if so, avoid sorting
        // them in order to improve performance.
        if (!biTarget.equals(NetworkParameters.MAX_MONEY)) {
            sortOutputs(sortedOutputs);
        }
        // Now iterate over the sorted outputs until we have got as close to the target as possible or a little
        // bit over (excessive value will be change).
        long total = 0;
        for (TransactionOutput output : sortedOutputs) {
            if (total >= target) break;
            // Only pick chain-included transactions, or transactions that are ours and pending.
            if (!shouldSelect(output.getParentTransaction())) continue;
            selected.add(output);
            total += output.getValue().longValue();
        }
        // Total may be lower than target here, if the given candidates were insufficient to create to requested
        // transaction.
        return new CoinSelection(BigInteger.valueOf(total), selected);
    }

    @VisibleForTesting static void sortOutputs(ArrayList<TransactionOutput> outputs) {
        Collections.sort(outputs, new Comparator<TransactionOutput>() {
            public int compare(TransactionOutput a, TransactionOutput b) {
                int depth1 = 0;
                int depth2 = 0;
                TransactionConfidence conf1 = a.getParentTransaction().getConfidence();
                TransactionConfidence conf2 = b.getParentTransaction().getConfidence();
                if (conf1.getConfidenceType() == TransactionConfidence.ConfidenceType.BUILDING)
                    depth1 = conf1.getDepthInBlocks();
                if (conf2.getConfidenceType() == TransactionConfidence.ConfidenceType.BUILDING)
                    depth2 = conf2.getDepthInBlocks();
                BigInteger aValue = a.getValue();
                BigInteger bValue = b.getValue();
                BigInteger aCoinDepth = aValue.multiply(BigInteger.valueOf(depth1));
                BigInteger bCoinDepth = bValue.multiply(BigInteger.valueOf(depth2));
                int c1 = bCoinDepth.compareTo(aCoinDepth);
                if (c1 != 0) return c1;
                // The "coin*days" destroyed are equal, sort by value alone to get the lowest transaction size.
                int c2 = bValue.compareTo(aValue);
                if (c2 != 0) return c2;
                // They are entirely equivalent (possibly pending) so sort by hash to ensure a total ordering.
                BigInteger aHash = a.getParentTransaction().getHash().toBigInteger();
                BigInteger bHash = b.getParentTransaction().getHash().toBigInteger();
                return aHash.compareTo(bHash);
            }
        });
    }

    /** Sub-classes can override this to just customize whether transactions are usable, but keep age sorting. */
    protected boolean shouldSelect(Transaction tx) {
        return isSelectable(tx);
    }

    public static boolean isSelectable(Transaction tx) {
        // Only pick chain-included transactions, or transactions that are ours and pending.
        TransactionConfidence confidence = tx.getConfidence();
        TransactionConfidence.ConfidenceType type = confidence.getConfidenceType();
        return type.equals(TransactionConfidence.ConfidenceType.BUILDING) ||

               type.equals(TransactionConfidence.ConfidenceType.PENDING) &&
               confidence.getSource().equals(TransactionConfidence.Source.SELF) &&
               // In regtest mode we expect to have only one peer, so we won't see transactions propagate.
               // TODO: The value 1 below dates from a time when transactions we broadcast *to* were counted, set to 0
               (confidence.numBroadcastPeers() > 1 || tx.getParams() == RegTestParams.get());
    }
}
