package org.bitcoinj.wallet.maintenance;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionBroadcaster;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

/**
 * Create futures for broadcasting the given transactions. This class delegates to the provided
 * {@link org.bitcoinj.core.TransactionBroadcaster} and additionally logs.
 */
public class BroadcastTransactionsAndLog {
    private final TransactionBroadcaster transactionBroadcaster;
    private String errorMessage = "Failed to broadcast transaction";
    private String successMessage = "Successfully broadcast transaction: {}";
    private Logger logger = LoggerFactory.getLogger(BroadcastTransactionsAndLog.class);

    /**
     * @param transactionBroadcaster the broadcaster to use
     */
    public BroadcastTransactionsAndLog(TransactionBroadcaster transactionBroadcaster) {
        this.transactionBroadcaster = transactionBroadcaster;
    }

    /**
     * @param transactions the transactions to broadcast
     * @return futures generated for broadcasting the given transactions
     */
    public ListenableFuture<List<Transaction>> getBroadcastFutures(List<Transaction> transactions) {
        ArrayList<ListenableFuture<Transaction>> futures = new ArrayList<ListenableFuture<Transaction>>(transactions.size());
        for (Transaction transaction : transactions) {
            addBroadcastFuture(futures, transaction);
        }
        return Futures.allAsList(futures);
    }

    private void addBroadcastFuture(ArrayList<ListenableFuture<Transaction>> futures, Transaction transaction) {
        try {
            futures.add(createBroadcastFuture(transaction));
        } catch (Exception exception) {
            logger.error(errorMessage, exception);
        }
    }

    private ListenableFuture<Transaction> createBroadcastFuture(Transaction keyRotationTransaction) {
        final ListenableFuture<Transaction> future = transactionBroadcaster.broadcastTransaction(keyRotationTransaction).future();
        addLogCallbacksToFuture(future);
        return future;
    }

    private void addLogCallbacksToFuture(ListenableFuture<Transaction> future) {
        Futures.addCallback(future, new FutureCallback<Transaction>() {
            @Override
            public void onSuccess(Transaction transaction) {
                logger.info(successMessage, transaction);
            }

            @Override
            public void onFailure(@Nonnull Throwable throwable) {
                logger.error(errorMessage, throwable);
            }
        });
    }

    /**
     * @param successMessage use this success message instead of the default
     */
    public void setSuccessMessage(String successMessage) {
        this.successMessage = successMessage;
    }

    /**
     * @param errorMessage use this error message instead of the default
     */
    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * @param logger use this logger instead of the default
     */
    public void setLogger(Logger logger) {
        this.logger = logger;
    }

}
