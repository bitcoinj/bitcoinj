package org.bitcoinj.core.listeners;

import org.bitcoinj.core.*;

/**
 * Called when a new transaction is broadcast over the network.
 */
public interface OnTransactionBroadcastListener {
    /**
     * Called when a new transaction is broadcast over the network.
     */
    void onTransaction(Peer peer, Transaction t);
}
