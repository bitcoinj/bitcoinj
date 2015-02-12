/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.*;
import org.bitcoinj.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.HashMultimap;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import net.jcip.annotations.GuardedBy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.Date;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * This class maintains a set of {@link StoredClientChannel}s, automatically (re)broadcasting the contract transaction
 * and broadcasting the refund transaction over the given {@link TransactionBroadcaster}.
 */
public class StoredPaymentChannelClientStates implements WalletExtension {
    private static final Logger log = LoggerFactory.getLogger(StoredPaymentChannelClientStates.class);
    static final String EXTENSION_ID = StoredPaymentChannelClientStates.class.getName();
    static final int MAX_SECONDS_TO_WAIT_FOR_BROADCASTER_TO_BE_SET = 10;

    @GuardedBy("lock") @VisibleForTesting final HashMultimap<Sha256Hash, StoredClientChannel> mapChannels = HashMultimap.create();
    @VisibleForTesting final Timer channelTimeoutHandler = new Timer(true);

    private Wallet containingWallet;
    private final SettableFuture<TransactionBroadcaster> announcePeerGroupFuture = SettableFuture.create();

    protected final ReentrantLock lock = Threading.lock("StoredPaymentChannelClientStates");

    /**
     * Creates a new StoredPaymentChannelClientStates and associates it with the given {@link Wallet} and
     * {@link TransactionBroadcaster} which are used to complete and announce contract and refund
     * transactions.
     */
    public StoredPaymentChannelClientStates(@Nullable Wallet containingWallet, TransactionBroadcaster announcePeerGroup) {
        setTransactionBroadcaster(announcePeerGroup);
        this.containingWallet = containingWallet;
    }

    /**
     * Creates a new StoredPaymentChannelClientStates and associates it with the given {@link Wallet}
     *
     * Use this constructor if you use WalletAppKit, it will provide the broadcaster for you (no need to call the setter)
     */
    public StoredPaymentChannelClientStates(@Nullable Wallet containingWallet) {
        this.containingWallet = containingWallet;
    }

    /**
     * Use this setter if the broadcaster is not available during instantiation and you're not using WalletAppKit.
     * This setter will let you delay the setting of the broadcaster until the Bitcoin network is ready.
     *
     * @param transactionBroadcaster which is used to complete and announce contract and refund transactions.
     */
    public void setTransactionBroadcaster(TransactionBroadcaster transactionBroadcaster) {
        this.announcePeerGroupFuture.set(checkNotNull(transactionBroadcaster));
    }

    /** Returns this extension from the given wallet, or null if no such extension was added. */
    @Nullable
    public static StoredPaymentChannelClientStates getFromWallet(Wallet wallet) {
        return (StoredPaymentChannelClientStates) wallet.getExtensions().get(EXTENSION_ID);
    }

    /** Returns the outstanding amount of money sent back to us for all channels to this server added together. */
    public Coin getBalanceForServer(Sha256Hash id) {
        Coin balance = Coin.ZERO;
        lock.lock();
        try {
            Set<StoredClientChannel> setChannels = mapChannels.get(id);
            for (StoredClientChannel channel : setChannels) {
                synchronized (channel) {
                    if (channel.close != null) continue;
                    balance = balance.add(channel.valueToMe);
                }
            }
            return balance;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the number of seconds from now until this servers next channel will expire, or zero if no unexpired
     * channels found.
     */
    public long getSecondsUntilExpiry(Sha256Hash id) {
        lock.lock();
        try {
            final Set<StoredClientChannel> setChannels = mapChannels.get(id);
            final long nowSeconds = Utils.currentTimeSeconds();
            int earliestTime = Integer.MAX_VALUE;
            for (StoredClientChannel channel : setChannels) {
                synchronized (channel) {
                    if (channel.expiryTimeSeconds() > nowSeconds)
                        earliestTime = Math.min(earliestTime, (int) channel.expiryTimeSeconds());
                }
            }
            return earliestTime == Integer.MAX_VALUE ? 0 : earliestTime - nowSeconds;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Finds an inactive channel with the given id and returns it, or returns null.
     */
    @Nullable
    StoredClientChannel getUsableChannelForServerID(Sha256Hash id) {
        lock.lock();
        try {
            Set<StoredClientChannel> setChannels = mapChannels.get(id);
            for (StoredClientChannel channel : setChannels) {
                synchronized (channel) {
                    // Check if the channel is usable (has money, inactive) and if so, activate it.
                    log.info("Considering channel {} contract {}", channel.hashCode(), channel.contract.getHash());
                    if (channel.close != null || channel.valueToMe.equals(Coin.ZERO)) {
                        log.info("  ... but is closed or empty");
                        continue;
                    }
                    if (!channel.active) {
                        log.info("  ... activating");
                        channel.active = true;
                        return channel;
                    }
                    log.info("  ... but is already active");
                }
            }
        } finally {
            lock.unlock();
        }
        return null;
    }

    /**
     * Finds a channel with the given id and contract hash and returns it, or returns null.
     */
    @Nullable
    StoredClientChannel getChannel(Sha256Hash id, Sha256Hash contractHash) {
        lock.lock();
        try {
            Set<StoredClientChannel> setChannels = mapChannels.get(id);
            for (StoredClientChannel channel : setChannels) {
                if (channel.contract.getHash().equals(contractHash))
                    return channel;
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Adds the given channel to this set of stored states, broadcasting the contract and refund transactions when the
     * channel expires and notifies the wallet of an update to this wallet extension
     */
    void putChannel(final StoredClientChannel channel) {
        putChannel(channel, true);
    }

    // Adds this channel and optionally notifies the wallet of an update to this extension (used during deserialize)
    private void putChannel(final StoredClientChannel channel, boolean updateWallet) {
        lock.lock();
        try {
            mapChannels.put(channel.id, channel);
            channelTimeoutHandler.schedule(new TimerTask() {
                @Override
                public void run() {
                    TransactionBroadcaster announcePeerGroup = getAnnouncePeerGroup();
                    removeChannel(channel);
                    announcePeerGroup.broadcastTransaction(channel.contract);
                    announcePeerGroup.broadcastTransaction(channel.refund);
                }
                // Add the difference between real time and Utils.now() so that test-cases can use a mock clock.
            }, new Date(channel.expiryTimeSeconds() * 1000 + (System.currentTimeMillis() - Utils.currentTimeMillis())));
        } finally {
            lock.unlock();
        }
        if (updateWallet)
            containingWallet.addOrUpdateExtension(this);
    }

    /**
     * If the peer group has not been set for MAX_SECONDS_TO_WAIT_FOR_BROADCASTER_TO_BE_SET seconds, then
     * the programmer probably forgot to set it and we should throw exception.
     */
    private TransactionBroadcaster getAnnouncePeerGroup() {
        try {
            return announcePeerGroupFuture.get(MAX_SECONDS_TO_WAIT_FOR_BROADCASTER_TO_BE_SET, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        } catch (TimeoutException e) {
            String err = "Transaction broadcaster not set";
            log.error(err);
            throw new RuntimeException(err, e);
        }
    }

    /**
     * <p>Removes the channel with the given id from this set of stored states and notifies the wallet of an update to
     * this wallet extension.</p>
     *
     * <p>Note that the channel will still have its contract and refund transactions broadcast via the connected
     * {@link TransactionBroadcaster} as long as this {@link StoredPaymentChannelClientStates} continues to
     * exist in memory.</p>
     */
    void removeChannel(StoredClientChannel channel) {
        lock.lock();
        try {
            mapChannels.remove(channel.id, channel);
        } finally {
            lock.unlock();
        }
        containingWallet.addOrUpdateExtension(this);
    }

    @Override
    public String getWalletExtensionID() {
        return EXTENSION_ID;
    }

    @Override
    public boolean isWalletExtensionMandatory() {
        return false;
    }

    @Override
    public byte[] serializeWalletExtension() {
        lock.lock();
        try {
            ClientState.StoredClientPaymentChannels.Builder builder = ClientState.StoredClientPaymentChannels.newBuilder();
            for (StoredClientChannel channel : mapChannels.values()) {
                // First a few asserts to make sure things won't break
                checkState(channel.valueToMe.signum() >= 0 && channel.valueToMe.compareTo(NetworkParameters.MAX_MONEY) < 0);
                checkState(channel.refundFees.signum() >= 0 && channel.refundFees.compareTo(NetworkParameters.MAX_MONEY) < 0);
                checkNotNull(channel.myKey.getPrivKeyBytes());
                checkState(channel.refund.getConfidence().getSource() == TransactionConfidence.Source.SELF);
                final ClientState.StoredClientPaymentChannel.Builder value = ClientState.StoredClientPaymentChannel.newBuilder()
                        .setId(ByteString.copyFrom(channel.id.getBytes()))
                        .setContractTransaction(ByteString.copyFrom(channel.contract.bitcoinSerialize()))
                        .setRefundTransaction(ByteString.copyFrom(channel.refund.bitcoinSerialize()))
                        .setMyKey(ByteString.copyFrom(channel.myKey.getPrivKeyBytes()))
                        .setValueToMe(channel.valueToMe.value)
                        .setRefundFees(channel.refundFees.value);
                if (channel.close != null)
                    value.setCloseTransactionHash(ByteString.copyFrom(channel.close.getHash().getBytes()));
                builder.addChannels(value);
            }
            return builder.build().toByteArray();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void deserializeWalletExtension(Wallet containingWallet, byte[] data) throws Exception {
        lock.lock();
        try {
            checkState(this.containingWallet == null || this.containingWallet == containingWallet);
            this.containingWallet = containingWallet;
            NetworkParameters params = containingWallet.getParams();
            ClientState.StoredClientPaymentChannels states = ClientState.StoredClientPaymentChannels.parseFrom(data);
            for (ClientState.StoredClientPaymentChannel storedState : states.getChannelsList()) {
                Transaction refundTransaction = new Transaction(params, storedState.getRefundTransaction().toByteArray());
                refundTransaction.getConfidence().setSource(TransactionConfidence.Source.SELF);
                StoredClientChannel channel = new StoredClientChannel(new Sha256Hash(storedState.getId().toByteArray()),
                        new Transaction(params, storedState.getContractTransaction().toByteArray()),
                        refundTransaction,
                        ECKey.fromPrivate(storedState.getMyKey().toByteArray()),
                        Coin.valueOf(storedState.getValueToMe()),
                        Coin.valueOf(storedState.getRefundFees()), false);
                if (storedState.hasCloseTransactionHash()) {
                    Sha256Hash closeTxHash = new Sha256Hash(storedState.getCloseTransactionHash().toByteArray());
                    channel.close = containingWallet.getTransaction(closeTxHash);
                }
                putChannel(channel, false);
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public String toString() {
        lock.lock();
        try {
            StringBuilder buf = new StringBuilder("Client payment channel states:\n");
            for (StoredClientChannel channel : mapChannels.values())
                buf.append("  ").append(channel).append("\n");
            return buf.toString();
        } finally {
            lock.unlock();
        }
    }
}

/**
 * Represents the state of a channel once it has been opened in such a way that it can be stored and used to resume a
 * channel which was interrupted (eg on connection failure) or keep track of refund transactions which need broadcast
 * when they expire.
 */
class StoredClientChannel {
    Sha256Hash id;
    Transaction contract, refund;
    // The transaction that closed the channel (generated by the server)
    Transaction close;
    ECKey myKey;
    Coin valueToMe, refundFees;

    // In-memory flag to indicate intent to resume this channel (or that the channel is already in use)
    boolean active = false;

    StoredClientChannel(Sha256Hash id, Transaction contract, Transaction refund, ECKey myKey, Coin valueToMe,
                        Coin refundFees, boolean active) {
        this.id = id;
        this.contract = contract;
        this.refund = refund;
        this.myKey = myKey;
        this.valueToMe = valueToMe;
        this.refundFees = refundFees;
        this.active = active;
    }

    long expiryTimeSeconds() {
        return refund.getLockTime() + 60 * 5;
    }

    @Override
    public String toString() {
        final String newline = String.format("%n");
        final String closeStr = close == null ? "still open" : close.toString().replaceAll(newline, newline + "   ");
        return String.format("Stored client channel for server ID %s (%s)%n" +
                "    Key:         %s%n" +
                "    Value left:  %s%n" +
                "    Refund fees: %s%n" +
                "    Contract:  %s" +
                "Refund:    %s" +
                "Close:     %s",
                id, active ? "active" : "inactive", myKey, valueToMe, refundFees,
                contract.toString().replaceAll(newline, newline + "    "),
                refund.toString().replaceAll(newline, newline + "    "),
                closeStr);
    }
}
