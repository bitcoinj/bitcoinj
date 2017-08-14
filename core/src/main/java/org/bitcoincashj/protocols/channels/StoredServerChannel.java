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

package org.bitcoincashj.protocols.channels;

import org.bitcoincashj.core.*;
import org.bitcoincashj.wallet.Wallet;

import javax.annotation.Nullable;
import java.util.Date;
import java.util.Locale;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Represents the state of a channel once it has been opened in such a way that it can be stored and used to resume a
 * channel which was interrupted (eg on connection failure) or settle the channel automatically as the channel expire
 * time approaches.
 */
public class StoredServerChannel {
    /**
     * Channel version number. Currently can only be version 1
     */
    int majorVersion;
    Coin bestValueToMe;
    byte[] bestValueSignature;
    long refundTransactionUnlockTimeSecs;
    Transaction contract;
    TransactionOutput clientOutput;
    ECKey myKey;
    // Used in protocol v2 only
    ECKey clientKey;

    // In-memory pointer to the event handler which handles this channel if the client is connected.
    // Used as a flag to prevent duplicate connections and to disconnect the channel if its expire time approaches.
    private PaymentChannelServer connectedHandler = null;
    PaymentChannelServerState state = null;

    StoredServerChannel(@Nullable PaymentChannelServerState state, int majorVersion, Transaction contract, TransactionOutput clientOutput,
                        long refundTransactionUnlockTimeSecs, ECKey myKey, ECKey clientKey, Coin bestValueToMe, @Nullable byte[] bestValueSignature) {
        this.majorVersion = majorVersion;
        this.contract = contract;
        this.clientOutput = clientOutput;
        this.refundTransactionUnlockTimeSecs = refundTransactionUnlockTimeSecs;
        this.myKey = myKey;
        this.clientKey = clientKey;
        this.bestValueToMe = bestValueToMe;
        this.bestValueSignature = bestValueSignature;
        this.state = state;
    }

    /**
     * <p>Updates the best value to the server to the given newValue and newSignature without any checking.</p>
     * <p>Does <i>NOT</i> notify the wallet of an update to the {@link StoredPaymentChannelServerStates}.</p>
     */
    synchronized void updateValueToMe(Coin newValue, byte[] newSignature) {
        this.bestValueToMe = newValue;
        this.bestValueSignature = newSignature;
    }

    /**
     * Attempts to connect the given handler to this, returning true if it is the new handler, false if there was
     * already one attached.
     */
    synchronized PaymentChannelServer setConnectedHandler(PaymentChannelServer connectedHandler, boolean override) {
        if (this.connectedHandler != null && !override)
            return this.connectedHandler;
        this.connectedHandler = connectedHandler;
        return connectedHandler;
    }

    /** Clears a handler that was connected with setConnectedHandler. */
    synchronized void clearConnectedHandler() {
        this.connectedHandler = null;
    }

    /**
     * If a handler is connected, call its {@link org.bitcoincashj.protocols.channels.PaymentChannelServer#close()}
     * method thus disconnecting the TCP connection.
     */
    synchronized void closeConnectedHandler() {
        if (connectedHandler != null)
            connectedHandler.close();
    }

    /**
     * Gets the canonical {@link PaymentChannelServerState} object for this channel, either by returning an existing one
     * or by creating a new one.
     *
     * @param wallet The wallet which holds the {@link PaymentChannelServerState} in which this is saved and which will
     *               be used to complete transactions
     * @param broadcaster The {@link TransactionBroadcaster} which will be used to broadcast contract/payment transactions.
     */
    public synchronized PaymentChannelServerState getOrCreateState(Wallet wallet, TransactionBroadcaster broadcaster) throws VerificationException {
        if (state == null) {
            switch (majorVersion) {
                case 1:
                    state = new PaymentChannelV1ServerState(this, wallet, broadcaster);
                    break;
                case 2:
                    state = new PaymentChannelV2ServerState(this, wallet, broadcaster);
                    break;
                default:
                    throw new IllegalStateException("Invalid version number found");
            }
        }
        checkArgument(wallet == state.wallet);
        return state;
    }

    @Override
    public synchronized String toString() {
        final String newline = String.format(Locale.US, "%n");
        return String.format(Locale.US, "Stored server channel (%s)%n" +
                "    Version:       %d%n" +
                "    Key:           %s%n" +
                "    Value to me:   %s%n" +
                "    Client output: %s%n" +
                "    Refund unlock: %s (%d unix time)%n" +
                "    Contract:    %s%n",
                connectedHandler != null ? "connected" : "disconnected", majorVersion, myKey, bestValueToMe,
                clientOutput,  new Date(refundTransactionUnlockTimeSecs * 1000), refundTransactionUnlockTimeSecs,
                contract.toString().replaceAll(newline, newline + "    "));
    }
}
