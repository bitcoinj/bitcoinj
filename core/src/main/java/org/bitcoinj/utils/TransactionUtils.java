package org.bitcoinj.utils;

import java.util.LinkedList;
import java.util.List;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionBag;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.wallet.WalletTransaction.Pool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TransactionUtils {

	private static final Logger log = LoggerFactory.getLogger(TransactionUtils.class);
	
    public static boolean isTransactionUnspent(Transaction tx, TransactionBag transactionBag) {
        return isTransactionConsistent(tx, transactionBag, false);
    }

    public static boolean isTransactionSpent(Transaction tx, TransactionBag transactionBag) {
        return isTransactionConsistent(tx, transactionBag, true);
    }

    /*
     * If isSpent - check that all transaction outputs spent, otherwise check that there at least
     * one unspent.
     */
    public static boolean isTransactionConsistent(Transaction tx, TransactionBag transactionBag, boolean isSpent) {
        boolean isActuallySpent = true;
        for (TransactionOutput o : tx.getOutputs()) {
            if (o.isAvailableForSpending()) {
                if (o.isMineOrWatched(transactionBag)) isActuallySpent = false;
                if (o.getSpentBy() != null) {
                    log.error("isAvailableForSpending != spentBy");
                    return false;
                }
            } else {
                if (o.getSpentBy() == null) {
                    log.error("isAvailableForSpending != spentBy");
                    return false;
                }
            }
        }
        return isActuallySpent == isSpent;
    }
    
    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet. The flag controls whether to
     * include spent outputs or not.
     */
    public static Coin getValueSentToTx(Transaction tx, TransactionBag transactionBag, boolean includeSpent) {
        // This is tested in WalletTest.
        Coin v = Coin.ZERO;
        for (TransactionOutput o : tx.getOutputs()) {
            if (!o.isMineOrWatched(transactionBag)) continue;
            if (!includeSpent && !o.isAvailableForSpending()) continue;
            v = v.add(o.getValue());
        }
        return v;
    }
    
    public static Coin getValueSentToTx(Transaction tx, TransactionBag transactionBag) {
    	return getValueSentToTx(tx, transactionBag, true);
    }

    /**
     * Calculates the sum of the inputs that are spending coins with keys in the wallet. This requires the
     * transactions sending coins to those keys to be in the wallet. This method will not attempt to download the
     * blocks containing the input transactions if the key is in the wallet but the transactions are not.
     *
     * @return sum of the inputs that are spending coins with keys in the wallet
     */
    public static Coin getValueSentFromTx(Transaction tx, TransactionBag wallet) throws ScriptException {
        // This is tested in WalletTest.
        Coin v = Coin.ZERO;
        for (TransactionInput input : tx.getInputs()) {
            // This input is taking value from a transaction in our wallet. To discover the value,
            // we must find the connected transaction.
            TransactionOutput connected = input.getConnectedOutput(wallet.getTransactionPool(Pool.UNSPENT));
            if (connected == null)
                connected = input.getConnectedOutput(wallet.getTransactionPool(Pool.SPENT));
            if (connected == null)
                connected = input.getConnectedOutput(wallet.getTransactionPool(Pool.PENDING));
            if (connected == null)
                continue;
            // The connected output may be the change to the sender of a previous input sent to this wallet. In this
            // case we ignore it.
            if (!connected.isMineOrWatched(wallet))
                continue;
            v = v.add(connected.getValue());
        }
        return v;
    }

    /**
     * Returns false if this transaction has at least one output that is owned by the given wallet and unspent, true
     * otherwise.
     */
    public static boolean isEveryOwnedOutputSpent(Transaction tx, TransactionBag transactionBag) {
        for (TransactionOutput output : tx.getOutputs()) {
            if (output.isAvailableForSpending() && output.isMineOrWatched(transactionBag))
                return false;
        }
        return true;
    }

    /**
     * <p>Returns the list of transacion outputs, whether spent or unspent, that match a wallet by address or that are
     * watched by a wallet, i.e., transaction outputs whose script's address is controlled by the wallet and transaction
     * outputs whose script is watched by the wallet.</p>
     *
     * @param transactionBag The wallet that controls addresses and watches scripts.
     * @return linked list of outputs relevant to the wallet in this transaction
     */
    public static List<TransactionOutput> getWalletOutputs(Transaction tx, TransactionBag transactionBag){
        List<TransactionOutput> walletOutputs = new LinkedList<TransactionOutput>();
        Coin v = Coin.ZERO;
        for (TransactionOutput o : tx.getOutputs()) {
            if (!o.isMineOrWatched(transactionBag)) continue;
            walletOutputs.add(o);
        }

        return walletOutputs;
    }
}
