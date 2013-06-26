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

package com.google.bitcoin.protocols.channels;

import java.io.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import com.google.bitcoin.core.*;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.HashMultimap;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * This class maintains a set of {@link StoredClientChannel}s, automatically (re)broadcasting the contract transaction
 * and broadcasting the refund transaction over the given {@link TransactionBroadcaster}.
 */
public class StoredPaymentChannelClientStates implements WalletExtension {
    static final String EXTENSION_ID = StoredPaymentChannelClientStates.class.getName();

    @VisibleForTesting final HashMultimap<Sha256Hash, StoredClientChannel> mapChannels = HashMultimap.create();
    @VisibleForTesting final Timer channelTimeoutHandler = new Timer();

    private Wallet containingWallet;
    private final TransactionBroadcaster announcePeerGroup;

    /**
     * Creates a new StoredPaymentChannelClientStates and associates it with the given {@link Wallet} and
     * {@link TransactionBroadcaster} which are used to complete and announce contract and refund
     * transactions.
     */
    public StoredPaymentChannelClientStates(TransactionBroadcaster announcePeerGroup, Wallet containingWallet) {
        this.announcePeerGroup = checkNotNull(announcePeerGroup);
        this.containingWallet = checkNotNull(containingWallet);
    }

    /**
     * Finds an inactive channel with the given id and returns it, or returns null.
     */
    public synchronized StoredClientChannel getInactiveChannelById(Sha256Hash id) {
        Set<StoredClientChannel> setChannels = mapChannels.get(id);
        for (StoredClientChannel channel : setChannels) {
            synchronized (channel) {
                if (!channel.active) {
                    channel.active = true;
                    return channel;
                }
            }
        }
        return null;
    }

    /**
     * Finds a channel with the given id and contract hash and returns it, or returns null.
     */
    public synchronized StoredClientChannel getChannel(Sha256Hash id, Sha256Hash contractHash) {
        Set<StoredClientChannel> setChannels = mapChannels.get(id);
        for (StoredClientChannel channel : setChannels) {
            if (channel.contract.getHash().equals(contractHash))
                return channel;
        }
        return null;
    }

    /**
     * Adds the given channel to this set of stored states, broadcasting the contract and refund transactions when the
     * channel expires and notifies the wallet of an update to this wallet extension
     */
    public void putChannel(final StoredClientChannel channel) {
        putChannel(channel, true);
    }

    // Adds this channel and optionally notifies the wallet of an update to this extension (used during deserialize)
    private synchronized void putChannel(final StoredClientChannel channel, boolean updateWallet) {
        mapChannels.put(channel.id, channel);
        channelTimeoutHandler.schedule(new TimerTask() {
            @Override
            public void run() {
                removeChannel(channel);
                announcePeerGroup.broadcastTransaction(channel.contract);
                announcePeerGroup.broadcastTransaction(channel.refund);
            }
            // Add the difference between real time and Utils.now() so that test-cases can use a mock clock.
        }, new Date((channel.refund.getLockTime() + 60 * 5) * 1000 + (System.currentTimeMillis() - Utils.now().getTime())));
        if (updateWallet)
            containingWallet.addOrUpdateExtension(this);
    }

    /**
     * <p>Removes the channel with the given id from this set of stored states and notifies the wallet of an update to
     * this wallet extension.</p>
     *
     * <p>Note that the channel will still have its contract and refund transactions broadcast via the connected
     * {@link TransactionBroadcaster} as long as this {@link StoredPaymentChannelClientStates} continues to
     * exist in memory.</p>
     */
    public synchronized void removeChannel(StoredClientChannel channel) {
        mapChannels.remove(channel.id, channel);
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
    public synchronized byte[] serializeWalletExtension() {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(out);
            for (StoredClientChannel channel : mapChannels.values()) {
                oos.writeObject(channel);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public synchronized void deserializeWalletExtension(Wallet containingWallet, byte[] data) throws Exception {
        checkState(this.containingWallet == null || this.containingWallet == containingWallet);
        this.containingWallet = containingWallet;
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(inStream);
        while (inStream.available() > 0) {
            StoredClientChannel channel = (StoredClientChannel)ois.readObject();
            putChannel(channel, false);
        }
    }
}

/**
 * Represents the state of a channel once it has been opened in such a way that it can be stored and used to resume a
 * channel which was interrupted (eg on connection failure) or keep track of refund transactions which need broadcast
 * when they expire.
 */
class StoredClientChannel implements Serializable {
    Sha256Hash id;
    Transaction contract, refund;
    ECKey myKey;
    BigInteger valueToMe, refundFees;

    // In-memory flag to indicate intent to resume this channel (or that the channel is already in use)
    transient boolean active = false;

    StoredClientChannel(Sha256Hash id, Transaction contract, Transaction refund, ECKey myKey, BigInteger valueToMe, BigInteger refundFees) {
        this.id = id;
        this.contract = contract;
        this.refund = refund;
        this.myKey = myKey;
        this.valueToMe = valueToMe;
        this.refundFees = refundFees;
        this.active = true;
    }

    void updateValueToMe(BigInteger newValue) {
        this.valueToMe = newValue;
    }
}
