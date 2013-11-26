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

import com.google.bitcoin.core.InsufficientMoneyException;
import com.google.common.util.concurrent.ListenableFuture;
import org.bitcoin.paymentchannel.Protos;

import java.math.BigInteger;

/**
 * A class implementing this interface supports the basic operations of a payment channel. An implementation is provided
 * in {@link PaymentChannelClient}, but alternative implementations are possible. For example, an implementor might
 * send RPCs to a separate (locally installed or even remote) wallet app rather than implementing the algorithm locally.
 */
public interface IPaymentChannelClient {
    /**
     * Called when a message is received from the server. Processes the given message and generates events based on its
     * content.
     */
    void receiveMessage(Protos.TwoWayChannelMessage msg) throws InsufficientMoneyException;

    /**
     * <p>Called when the connection to the server terminates.</p>
     *
     * <p>For stateless protocols, this translates to a client not using the channel for the immediate future, but
     * intending to reopen the channel later. There is likely little reason to use this in a stateless protocol.</p>
     *
     * <p>Note that this <b>MUST</b> still be called even after either
     * {@link PaymentChannelClient.ClientConnection#destroyConnection(com.google.bitcoin.protocols.channels.PaymentChannelCloseException.CloseReason)} or
     * {@link IPaymentChannelClient#settle()} is called, to actually handle the connection close logic.</p>
     */
    void connectionClosed();

    /**
     * <p>Settles the channel, notifying the server it can broadcast the most recent payment transaction.</p>
     *
     * <p>Note that this only generates a CLOSE message for the server and calls
     * {@link PaymentChannelClient.ClientConnection#destroyConnection(com.google.bitcoin.protocols.channels.PaymentChannelCloseException.CloseReason)}
     * to settle the connection, it does not actually handle connection close logic, and
     * {@link PaymentChannelClient#connectionClosed()} must still be called after the connection fully settles.</p>
     *
     * @throws IllegalStateException If the connection is not currently open (ie the CLOSE message cannot be sent)
     */
    void settle() throws IllegalStateException;

    /**
     * <p>Called to indicate the connection has been opened and messages can now be generated for the server.</p>
     *
     * <p>Attempts to find a channel to resume and generates a CLIENT_VERSION message for the server based on the
     * result.</p>
     */
    void connectionOpen();

    /**
     * Increments the total value which we pay the server. Note that the amount of money sent may not be the same as the
     * amount of money actually requested. It can be larger if the amount left over in the channel would be too small to
     * be accepted by the Bitcoin network. ValueOutOfRangeException will be thrown, however, if there's not enough money
     * left in the channel to make the payment at all. Only one payment can be in-flight at once. You have to ensure
     * you wait for the previous increase payment future to complete before incrementing the payment again.
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @throws ValueOutOfRangeException If the size is negative or would pay more than this channel's total value
     *                                  ({@link PaymentChannelClientConnection#state()}.getTotalValue())
     * @throws IllegalStateException If the channel has been closed or is not yet open
     *                               (see {@link PaymentChannelClientConnection#getChannelOpenFuture()} for the second)
     * @return a future that completes when the server acknowledges receipt and acceptance of the payment.
     */
    ListenableFuture<BigInteger> incrementPayment(BigInteger size) throws ValueOutOfRangeException, IllegalStateException;

    /**
     * Implements the connection between this client and the server, providing an interface which allows messages to be
     * sent to the server, requests for the connection to the server to be closed, and a callback which occurs when the
     * channel is fully open.
     */
    interface ClientConnection {
        /**
         * <p>Requests that the given message be sent to the server. There are no blocking requirements for this method,
         * however the order of messages must be preserved.</p>
         *
         * <p>If the send fails, no exception should be thrown, however
         * {@link com.google.bitcoin.protocols.channels.PaymentChannelClient#connectionClosed()} should be called immediately. In the case of messages which
         * are a part of initialization, initialization will simply fail and the refund transaction will be broadcasted
         * when it unlocks (if necessary).  In the case of a payment message, the payment will be lost however if the
         * channel is resumed it will begin again from the channel value <i>after</i> the failed payment.</p>
         *
         * <p>Called while holding a lock on the {@link com.google.bitcoin.protocols.channels.PaymentChannelClient} object - be careful about reentrancy</p>
         */
        void sendToServer(Protos.TwoWayChannelMessage msg);

        /**
         * <p>Requests that the connection to the server be closed. For stateless protocols, note that after this call,
         * no more messages should be received from the server and this object is no longer usable. A
         * {@link com.google.bitcoin.protocols.channels.PaymentChannelClient#connectionClosed()} event should be generated immediately after this call.</p>
         *
         * <p>Called while holding a lock on the {@link com.google.bitcoin.protocols.channels.PaymentChannelClient} object - be careful about reentrancy</p>
         *
         * @param reason The reason for the closure, see the individual values for more details.
         *               It is usually safe to ignore this and treat any value below
         *               {@link com.google.bitcoin.protocols.channels.PaymentChannelCloseException.CloseReason#CLIENT_REQUESTED_CLOSE} as "unrecoverable error" and all others as
         *               "try again once and see if it works then"
         */
        void destroyConnection(PaymentChannelCloseException.CloseReason reason);

        /**
         * <p>Indicates the channel has been successfully opened and
         * {@link com.google.bitcoin.protocols.channels.PaymentChannelClient#incrementPayment(java.math.BigInteger)}
         * may be called at will.</p>
         *
         * <p>Called while holding a lock on the {@link com.google.bitcoin.protocols.channels.PaymentChannelClient}
         * object - be careful about reentrancy</p>
         *
         * @param wasInitiated If true, the channel is newly opened. If false, it was resumed.
         */
        void channelOpen(boolean wasInitiated);
    }

    /**
     * An implementor of this interface creates payment channel clients that "talk back" with the given connection.
     * The client might be a PaymentChannelClient, or an RPC interface, or something else entirely.
     */
    interface Factory {
        IPaymentChannelClient create(String serverPaymentIdentity, ClientConnection connection);
    }
}
