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
import java.util.*;

import com.google.bitcoin.core.*;
import com.google.common.annotations.VisibleForTesting;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Keeps track of a set of {@link StoredServerChannel}s and expires them 2 hours before their refund transactions
 * unlock.
 */
public class StoredPaymentChannelServerStates implements WalletExtension {
    static final String EXTENSION_ID = StoredPaymentChannelServerStates.class.getName();

    @VisibleForTesting final Map<Sha256Hash, StoredServerChannel> mapChannels = new HashMap<Sha256Hash, StoredServerChannel>();
    private final Wallet wallet;
    private final PeerGroup announcePeerGroup;

    private final Timer channelTimeoutHandler = new Timer();

    /**
     * The offset between the refund transaction's lock time and the time channels will be automatically closed.
     * This defines a window during which we must get the last payment transaction verified, ie it should allow time for
     * network propagation and for the payment transaction to be included in a block. Note that the channel expire time
     * is measured in terms of our local clock, and the refund transaction's lock time is measured in terms of Bitcoin
     * block header timestamps, which are allowed to drift up to two hours in the future, as measured by relaying nodes.
     */
    public static final long CHANNEL_EXPIRE_OFFSET = -2*60*60;

    /**
     * Creates a new PaymentChannelServerStateManager and associates it with the given {@link Wallet} and
     * {@link PeerGroup} which are used to complete and announce payment transactions.
     */
    public StoredPaymentChannelServerStates(Wallet wallet, PeerGroup announcePeerGroup) {
        this.wallet = checkNotNull(wallet);
        this.announcePeerGroup = checkNotNull(announcePeerGroup);
    }

    /**
     * <p>Closes the given channel using {@link ServerConnectionEventHandler#closeChannel()} and
     * {@link PaymentChannelServerState#close()} to notify any connected client of channel closure and to complete and
     * broadcast the latest payment transaction.</p>
     *
     * <p>Removes the given channel from this set of {@link StoredServerChannel}s and notifies the wallet of a change to
     * this wallet extension.</p>
     */
    public synchronized void closeChannel(StoredServerChannel channel) {
        synchronized (channel) {
            if (channel.connectedHandler != null)
                channel.connectedHandler.close(); // connectedHandler will be reset to null in connectionClosed
            try {//TODO add event listener to PaymentChannelServerStateManager
                channel.getState(wallet, announcePeerGroup).close(); // Closes the actual connection, not the channel
            } catch (ValueOutOfRangeException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            } catch (VerificationException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
            channel.state = null;
            mapChannels.remove(channel.contract.getHash());
        }
        wallet.addOrUpdateExtension(this);
    }

    /**
     * Gets the {@link StoredServerChannel} with the given channel id (ie contract transaction hash).
     */
    public synchronized StoredServerChannel getChannel(Sha256Hash id) {
        return mapChannels.get(id);
    }

    /**
     * <p>Puts the given channel in the channels map and automatically closes it 2 hours before its refund transaction
     * becomes spendable.</p>
     *
     * <p>Because there must be only one, canonical {@link StoredServerChannel} per channel, this method throws if the
     * channel is already present in the set of channels.</p>
     */
    public synchronized void putChannel(final StoredServerChannel channel) {
        checkArgument(mapChannels.put(channel.contract.getHash(), checkNotNull(channel)) == null);
        channelTimeoutHandler.schedule(new TimerTask() {
            @Override
            public void run() {
                closeChannel(channel);
            }
            // Add the difference between real time and Utils.now() so that test-cases can use a mock clock.
        }, new Date((channel.refundTransactionUnlockTimeSecs + CHANNEL_EXPIRE_OFFSET)*1000L
                + (System.currentTimeMillis() - Utils.now().getTime())));
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
            for (StoredServerChannel channel : mapChannels.values()) {
                oos.writeObject(channel);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public synchronized void deserializeWalletExtension(Wallet containingWallet, byte[] data) throws Exception {
        checkArgument(containingWallet == wallet);
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(inStream);
        while (inStream.available() > 0) {
            StoredServerChannel channel = (StoredServerChannel)ois.readObject();
            putChannel(channel);
        }
    }
}
