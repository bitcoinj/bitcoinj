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

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.net.NioClient;
import org.bitcoinj.net.ProtobufConnection;
import org.bitcoinj.protocols.channels.IPaymentChannelClient.ClientChannelProperties;
import org.bitcoinj.wallet.Wallet;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;

import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * A simple utility class that runs the micropayment protocol over a raw TCP socket using NIO, standalone.
 */
public class PaymentChannelClientConnection {
    // Various futures which will be completed later
    private final SettableFuture<PaymentChannelClientConnection> channelOpenFuture = SettableFuture.create();

    private final PaymentChannelClient channelClient;
    private final ProtobufConnection<Protos.TwoWayChannelMessage> wireParser;

    /**
     * Attempts to open a new connection to and open a payment channel with the given host and port, blocking until the
     * connection is open. The server is requested to keep the channel open for
     * {@link PaymentChannelClient#DEFAULT_TIME_WINDOW}
     * seconds. If the server proposes a longer time the channel will be closed.
     *
     * @param server         The host/port pair where the server is listening.
     * @param timeoutSeconds The connection timeout and read timeout during initialization. This should be large enough
     *                       to accommodate ECDSA signature operations and network latency.
     * @param wallet         The wallet which will be paid from, and where completed transactions will be committed.
     *                       Must be unencrypted. Must already have a {@link StoredPaymentChannelClientStates} object in its extensions set.
     * @param myKey          A freshly generated keypair used for the multisig contract and refund output.
     * @param maxValue       The maximum value this channel is allowed to request
     * @param serverId       A unique ID which is used to attempt reopening of an existing channel.
     *                       This must be unique to the server, and, if your application is exposing payment channels to some
     *                       API, this should also probably encompass some caller UID to avoid applications opening channels
     *                       which were created by others.
     * @throws IOException              if there's an issue using the network.
     * @throws ValueOutOfRangeException if the balance of wallet is lower than maxValue.
     */
    public PaymentChannelClientConnection(InetSocketAddress server, int timeoutSeconds, Wallet wallet, ECKey myKey,
                                          Coin maxValue, String serverId) throws IOException, ValueOutOfRangeException {
        this(server, timeoutSeconds, wallet, myKey, maxValue, serverId, null);
    }

    /**
     * Attempts to open a new connection to and open a payment channel with the given host and port, blocking until the
     * connection is open.  The server is requested to keep the channel open for
     * {@link PaymentChannelClient#DEFAULT_TIME_WINDOW} seconds.
     * If the server proposes a longer time the channel will be closed.
     *
     * @param server          The host/port pair where the server is listening.
     * @param timeoutSeconds  The connection timeout and read timeout during initialization. This should be large enough
     *                        to accommodate ECDSA signature operations and network latency.
     * @param wallet          The wallet which will be paid from, and where completed transactions will be committed.
     *                        Can be encrypted if user key is supplied when needed. Must already have a
     *                        {@link StoredPaymentChannelClientStates} object in its extensions set.
     * @param myKey           A freshly generated keypair used for the multisig contract and refund output.
     * @param maxValue        The maximum value this channel is allowed to request
     * @param serverId        A unique ID which is used to attempt reopening of an existing channel.
     *                        This must be unique to the server, and, if your application is exposing payment channels to some
     *                        API, this should also probably encompass some caller UID to avoid applications opening channels
     *                        which were created by others.
     * @param userKeySetup    Key derived from a user password, used to decrypt myKey, if it is encrypted, during setup.
     * @throws IOException              if there's an issue using the network.
     * @throws ValueOutOfRangeException if the balance of wallet is lower than maxValue.
     */
    public PaymentChannelClientConnection(InetSocketAddress server, int timeoutSeconds, Wallet wallet, ECKey myKey,
                                          Coin maxValue, String serverId, @Nullable KeyParameter userKeySetup) throws IOException, ValueOutOfRangeException {
        this(server, timeoutSeconds, wallet, myKey, maxValue, serverId, userKeySetup, PaymentChannelClient.defaultChannelProperties);
    }


    /**
     * Attempts to open a new connection to and open a payment channel with the given host and port, blocking until the
     * connection is open.  The server is requested to keep the channel open for {@code timeoutSeconds}
     * seconds. If the server proposes a longer time the channel will be closed.
     *
     * @param server The host/port pair where the server is listening.
     * @param timeoutSeconds The connection timeout and read timeout during initialization. This should be large enough
     *                       to accommodate ECDSA signature operations and network latency.
     * @param wallet The wallet which will be paid from, and where completed transactions will be committed.
     *               Can be encrypted if user key is supplied when needed. Must already have a
     *               {@link StoredPaymentChannelClientStates} object in its extensions set.
     * @param myKey A freshly generated keypair used for the multisig contract and refund output.
     * @param maxValue The maximum value this channel is allowed to request
     * @param serverId A unique ID which is used to attempt reopening of an existing channel.
     *                 This must be unique to the server, and, if your application is exposing payment channels to some
     *                 API, this should also probably encompass some caller UID to avoid applications opening channels
     *                 which were created by others.
     * @param userKeySetup Key derived from a user password, used to decrypt myKey, if it is encrypted, during setup.
     * @param clientChannelProperties Modifier to change the channel's configuration.
     *
     * @throws IOException if there's an issue using the network.
     * @throws ValueOutOfRangeException if the balance of wallet is lower than maxValue.
     */
    public PaymentChannelClientConnection(InetSocketAddress server, int timeoutSeconds, Wallet wallet, ECKey myKey,
                                          Coin maxValue, String serverId,
                                          @Nullable KeyParameter userKeySetup, final ClientChannelProperties clientChannelProperties)
            throws IOException, ValueOutOfRangeException {
        // Glue the object which vends/ingests protobuf messages in order to manage state to the network object which
        // reads/writes them to the wire in length prefixed form.
        channelClient = new PaymentChannelClient(wallet, myKey, maxValue, Sha256Hash.of(serverId.getBytes()),
                userKeySetup, clientChannelProperties, new PaymentChannelClient.ClientConnection() {
            @Override
            public void sendToServer(Protos.TwoWayChannelMessage msg) {
                wireParser.write(msg);
            }

            @Override
            public void destroyConnection(PaymentChannelCloseException.CloseReason reason) {
                channelOpenFuture.setException(new PaymentChannelCloseException("Payment channel client requested that the connection be closed: " + reason, reason));
                wireParser.closeConnection();
            }

            @Override
            public boolean acceptExpireTime(long expireTime) {
                return expireTime <= (clientChannelProperties.timeWindow() + Utils.currentTimeSeconds() + 60);  // One extra minute to compensate for time skew and latency
            }

            @Override
            public void channelOpen(boolean wasInitiated) {
                wireParser.setSocketTimeout(0);
                // Inform the API user that we're done and ready to roll.
                channelOpenFuture.set(PaymentChannelClientConnection.this);
            }
        });

        // And glue back in the opposite direction - network to the channelClient.
        wireParser = new ProtobufConnection<Protos.TwoWayChannelMessage>(new ProtobufConnection.Listener<Protos.TwoWayChannelMessage>() {
            @Override
            public void messageReceived(ProtobufConnection<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                try {
                    channelClient.receiveMessage(msg);
                } catch (InsufficientMoneyException e) {
                    // We should only get this exception during INITIATE, so channelOpen wasn't called yet.
                    channelOpenFuture.setException(e);
                }
            }

            @Override
            public void connectionOpen(ProtobufConnection<Protos.TwoWayChannelMessage> handler) {
                channelClient.connectionOpen();
            }

            @Override
            public void connectionClosed(ProtobufConnection<Protos.TwoWayChannelMessage> handler) {
                channelClient.connectionClosed();
                channelOpenFuture.setException(new PaymentChannelCloseException("The TCP socket died",
                        PaymentChannelCloseException.CloseReason.CONNECTION_CLOSED));
            }
        }, Protos.TwoWayChannelMessage.getDefaultInstance(), Short.MAX_VALUE, timeoutSeconds*1000);

        // Initiate the outbound network connection. We don't need to keep this around. The wireParser object will handle
        // things from here on out.
        new NioClient(server, wireParser, timeoutSeconds * 1000);
    }

    /**
     * <p>Gets a future which returns this when the channel is successfully opened, or throws an exception if there is
     * an error before the channel has reached the open state.</p>
     *
     * <p>After this future completes successfully, you may call
     * {@link PaymentChannelClientConnection#incrementPayment(Coin)} or
     * {@link PaymentChannelClientConnection#incrementPayment(Coin, ByteString, KeyParameter)} to
     * begin paying the server.</p>
     */
    public ListenableFuture<PaymentChannelClientConnection> getChannelOpenFuture() {
        return channelOpenFuture;
    }

    /**
     * Increments the total value which we pay the server.
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @throws ValueOutOfRangeException If the size is negative or would pay more than this channel's total value
     *                                  ({@link PaymentChannelClientConnection#state()}.getTotalValue())
     * @throws IllegalStateException If the channel has been closed or is not yet open
     *                               (see {@link PaymentChannelClientConnection#getChannelOpenFuture()} for the second)
     */
    public ListenableFuture<PaymentIncrementAck> incrementPayment(Coin size) throws ValueOutOfRangeException, IllegalStateException {
        return channelClient.incrementPayment(size, null, null);
    }

    /**
     * Increments the total value which we pay the server.
     *
     * @param size How many satoshis to increment the payment by (note: not the new total).
     * @param info Information about this payment increment, used to extend this protocol.
     * @param userKey Key derived from a user password, needed for any signing when the wallet is encrypted.
     *                The wallet KeyCrypter is assumed.
     * @throws ValueOutOfRangeException If the size is negative or would pay more than this channel's total value
     *                                  ({@link PaymentChannelClientConnection#state()}.getTotalValue())
     * @throws IllegalStateException If the channel has been closed or is not yet open
     *                               (see {@link PaymentChannelClientConnection#getChannelOpenFuture()} for the second)
     */
    public ListenableFuture<PaymentIncrementAck> incrementPayment(Coin size,
                                                                  @Nullable ByteString info,
                                                                  @Nullable KeyParameter userKey)
            throws ValueOutOfRangeException, IllegalStateException {
        return channelClient.incrementPayment(size, info, userKey);
    }

    /**
     * <p>Gets the {@link PaymentChannelV1ClientState} object which stores the current state of the connection with the
     * server.</p>
     *
     * <p>Note that if you call any methods which update state directly the server will not be notified and channel
     * initialization logic in the connection may fail unexpectedly.</p>
     */
    public PaymentChannelClientState state() {
        return channelClient.state();
    }

    /**
     * Closes the connection, notifying the server it should settle the channel by broadcasting the most recent payment
     * transaction.
     */
    public void settle() {
        // Shutdown is a little complicated.
        //
        // This call will cause the CLOSE message to be written to the wire, and then the destroyConnection() method that
        // we defined above will be called, which in turn will call wireParser.closeConnection(), which in turn will invoke
        // NioClient.closeConnection(), which will then close the socket triggering interruption of the network
        // thread it had created. That causes the background thread to die, which on its way out calls
        // ProtobufConnection.connectionClosed which invokes the connectionClosed method we defined above which in turn
        // then configures the open-future correctly and closes the state object. Phew!
        try {
            channelClient.settle();
        } catch (IllegalStateException e) {
            // Already closed...oh well
        }
    }

    /**
     * Disconnects the network connection but doesn't request the server to settle the channel first (literally just
     * unplugs the network socket and marks the stored channel state as inactive).
     */
    public void disconnectWithoutSettlement() {
        wireParser.closeConnection();
    }
}
