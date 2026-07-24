package org.bitcoinj.core;

import org.bitcoinj.base.Sha256Hash;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 *
 */
public interface P2PTransactionBroadcaster extends TransactionBroadcaster {
    CompletableFuture<BroadcastSuccess> sendTransaction(Transaction tx, BroadcastOptions options);

    /* Internal methods */
    // waitForPeers (if fails NotEnoughPeers)
    // broadcastOnly / awaitBroadcast (if fails, BroadcastSendFailure perhaps with number sent, failed peer info?)
    // awaitRelay (if fails, BroadcastNotRelayed with information on the number of relays and maybe which peers)

    class P2PBroadcastSuccess implements TransactionBroadcaster.BroadcastSuccess {
        private final Sha256Hash txId;
        private final int sendCount;
        private final int relayCount;

        public P2PBroadcastSuccess(Sha256Hash txHash, int sendCount, int relayCount) {
            this.txId = txHash;
            this.sendCount = sendCount;
            this.relayCount = relayCount;
        }

        @Override
        public Sha256Hash txId() {
            return txId;
        }
        public int sendCount() {
            return sendCount;
        }
        public int relayCount() {
            return relayCount;
        }
    }

    /**
     * We were unable to find enough relays
     * Maybe return the number of relays we found out of number required?
     */
    class NotEnoughPeers extends TransactionBroadcaster.BroadcastFailure {
        private final Sha256Hash txId;

        public NotEnoughPeers(Sha256Hash txId) {
            this.txId = txId;
        }

        @Override
        public Sha256Hash txId() {
            return txId;
        }

        public int sendCount() {
            return 0;
        }

        public int relayCount() {
            return 0;
        }
    }

    class P2PBroadcastOptions implements BroadcastOptions {
        private final int minConnections;
        private final boolean dropPeersAfterBroadcast;
        private final boolean requireEncryptedConnection;
        private final Duration timeout;

        public P2PBroadcastOptions(int minConnections,
                                   boolean dropPeersAfterBroadcast,
                                   boolean requireEncryptedConnection,
                                   Duration timeout)
        {
            this.minConnections = minConnections;
            this.dropPeersAfterBroadcast = dropPeersAfterBroadcast;
            this.requireEncryptedConnection = requireEncryptedConnection;
            this.timeout = timeout;
        }

        public P2PBroadcastOptions(int minConnections) {
            this(minConnections, true, false, Duration.ofMinutes(60));
        }

        public int minConnections() {
            return minConnections;
        }

        public boolean dropPeersAfterBroadcast() {
            return dropPeersAfterBroadcast;
        }

        public boolean requireEncryptedConnection() {
            return requireEncryptedConnection;
        }

        @Override
        public Duration timeout() {
            return timeout;
        }
    }
}
