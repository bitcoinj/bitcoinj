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
import java.util.concurrent.locks.ReentrantLock;

import com.google.bitcoin.core.*;
import com.google.bitcoin.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import net.jcip.annotations.GuardedBy;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Keeps track of a set of {@link StoredServerChannel}s and expires them 2 hours before their refund transactions
 * unlock.
 */
public class StoredPaymentChannelServerStates implements WalletExtension {
    static final String EXTENSION_ID = StoredPaymentChannelServerStates.class.getName();

    @GuardedBy("lock") @VisibleForTesting final Map<Sha256Hash, StoredServerChannel> mapChannels = new HashMap<Sha256Hash, StoredServerChannel>();
    private final Wallet wallet;
    private final TransactionBroadcaster broadcaster;

    private final Timer channelTimeoutHandler = new Timer();

    private final ReentrantLock lock = Threading.lock("StoredPaymentChannelServerStates");

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
     * {@link TransactionBroadcaster} which are used to complete and announce payment transactions.
     */
    public StoredPaymentChannelServerStates(Wallet wallet, TransactionBroadcaster broadcaster) {
        this.wallet = checkNotNull(wallet);
        this.broadcaster = checkNotNull(broadcaster);
    }

    /**
     * <p>Closes the given channel using {@link ServerConnectionEventHandler#closeChannel()} and
     * {@link PaymentChannelServerState#close()} to notify any connected client of channel closure and to complete and
     * broadcast the latest payment transaction.</p>
     *
     * <p>Removes the given channel from this set of {@link StoredServerChannel}s and notifies the wallet of a change to
     * this wallet extension.</p>
     */
    public void closeChannel(StoredServerChannel channel) {
        lock.lock();
        try {
            if (mapChannels.remove(channel.contract.getHash()) == null)
                return;
        } finally {
            lock.unlock();
        }
        synchronized (channel) {
            if (channel.connectedHandler != null) // connectedHandler will be reset to null in connectionClosed
                channel.connectedHandler.close(); // Closes the actual connection, not the channel
            try {//TODO add event listener to PaymentChannelServerStateManager
                channel.getState(wallet, broadcaster).close();
            } catch (ValueOutOfRangeException e) {
                e.printStackTrace();
            } catch (VerificationException e) {
                e.printStackTrace();
            }
            channel.state = null;
        }
        wallet.addOrUpdateExtension(this);
    }

    /**
     * Gets the {@link StoredServerChannel} with the given channel id (ie contract transaction hash).
     */
    public StoredServerChannel getChannel(Sha256Hash id) {
        lock.lock();
        try {
            return mapChannels.get(id);
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Puts the given channel in the channels map and automatically closes it 2 hours before its refund transaction
     * becomes spendable.</p>
     *
     * <p>Because there must be only one, canonical {@link StoredServerChannel} per channel, this method throws if the
     * channel is already present in the set of channels.</p>
     */
    public void putChannel(final StoredServerChannel channel) {
        lock.lock();
        try {
            checkArgument(mapChannels.put(channel.contract.getHash(), checkNotNull(channel)) == null);
            channelTimeoutHandler.schedule(new TimerTask() {
                @Override
                public void run() {
                    closeChannel(channel);
                }
                // Add the difference between real time and Utils.now() so that test-cases can use a mock clock.
            }, new Date((channel.refundTransactionUnlockTimeSecs + CHANNEL_EXPIRE_OFFSET)*1000L
                    + (System.currentTimeMillis() - Utils.now().getTime())));
        } finally {
            lock.unlock();
        }
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
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(out);
            for (StoredServerChannel channel : mapChannels.values()) {
                oos.writeObject(channel);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void deserializeWalletExtension(Wallet containingWallet, byte[] data) throws Exception {
        lock.lock();
        try {
            checkArgument(containingWallet == wallet);
            ByteArrayInputStream inStream = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(inStream);
            while (inStream.available() > 0) {
                StoredServerChannel channel = (StoredServerChannel)ois.readObject();
                putChannel(channel);
            }
        } finally {
            lock.unlock();
        }
    }
}
