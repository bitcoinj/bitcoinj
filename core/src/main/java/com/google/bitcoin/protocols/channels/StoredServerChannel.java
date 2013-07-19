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

import com.google.bitcoin.core.*;

import java.math.BigInteger;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Represents the state of a channel once it has been opened in such a way that it can be stored and used to resume a
 * channel which was interrupted (eg on connection failure) or close the channel automatically as the channel expire
 * time approaches.
 */
public class StoredServerChannel {
    BigInteger bestValueToMe;
    byte[] bestValueSignature;
    long refundTransactionUnlockTimeSecs;
    Transaction contract;
    TransactionOutput clientOutput;
    ECKey myKey;

    // In-memory pointer to the event handler which handles this channel if the client is connected.
    // Used as a flag to prevent duplicate connections and to disconnect the channel if its expire time approaches.
    PaymentChannelServer connectedHandler = null;
    PaymentChannelServerState state = null;

    StoredServerChannel(PaymentChannelServerState state, Transaction contract, TransactionOutput clientOutput,
                        long refundTransactionUnlockTimeSecs, ECKey myKey, BigInteger bestValueToMe, byte[] bestValueSignature) {
        this.contract = contract;
        this.clientOutput = clientOutput;
        this.refundTransactionUnlockTimeSecs = refundTransactionUnlockTimeSecs;
        this.myKey = myKey;
        this.bestValueToMe = bestValueToMe;
        this.bestValueSignature = bestValueSignature;
        this.state = state;
    }

    /**
     * <p>Updates the best value to the server to the given newValue and newSignature without any checking.</p>
     * <p>Does <i>NOT</i> notify the wallet of an update to the {@link StoredPaymentChannelServerStates}.</p>
     */
    synchronized void updateValueToMe(BigInteger newValue, byte[] newSignature) {
        this.bestValueToMe = newValue;
        this.bestValueSignature = newSignature;
    }

    /**
     * Attempts to connect the given handler to this, returning true if it is the new handler, false if there was
     * already one attached. A null connectedHandler clears this's connected handler no matter its current state.
     */
    synchronized boolean setConnectedHandler(PaymentChannelServer connectedHandler) {
        if (this.connectedHandler != null && connectedHandler != null)
            return false;
        this.connectedHandler = connectedHandler;
        return true;
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
        if (state == null)
            state = new PaymentChannelServerState(this, wallet, broadcaster);
        checkArgument(wallet == state.wallet);
        return state;
    }
}
