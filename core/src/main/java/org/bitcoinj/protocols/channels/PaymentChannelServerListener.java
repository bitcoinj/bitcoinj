/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.TransactionBroadcaster;
import org.bitcoinj.net.NioServer;
import org.bitcoinj.net.ProtobufConnection;
import org.bitcoinj.net.StreamConnectionFactory;
import org.bitcoinj.wallet.Wallet;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;

import javax.annotation.Nullable;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Implements a listening TCP server that can accept connections from payment channel clients, and invokes the provided
 * event listeners when new channels are opened or payments arrive. This is the highest level class in the payment
 * channels API. Internally, sends protobuf messages to/from a newly created {@link PaymentChannelServer}.
 */
public class PaymentChannelServerListener {
    // The wallet and peergroup which are used to complete/broadcast transactions
    private final Wallet wallet;
    private final TransactionBroadcaster broadcaster;

    // The event handler factory which creates new ServerConnectionEventHandler per connection
    private final HandlerFactory eventHandlerFactory;
    private final Coin minAcceptedChannelSize;

    private NioServer server;
    private final int timeoutSeconds;

    /**
     * A factory which generates connection-specific event handlers.
     */
    public interface HandlerFactory {
        /**
         * Called when a new connection completes version handshake to get a new connection-specific listener.
         * If null is returned, the connection is immediately closed.
         */
        @Nullable
        ServerConnectionEventHandler onNewConnection(SocketAddress clientAddress);
    }

    private class ServerHandler {
        public ServerHandler(final SocketAddress address, final int timeoutSeconds) {
            paymentChannelManager = new PaymentChannelServer(broadcaster, wallet, minAcceptedChannelSize, new PaymentChannelServer.ServerConnection() {
                @Override public void sendToClient(Protos.TwoWayChannelMessage msg) {
                    socketProtobufHandler.write(msg);
                }

                @Override public void destroyConnection(PaymentChannelCloseException.CloseReason reason) {
                    if (closeReason != null)
                        closeReason = reason;
                    socketProtobufHandler.closeConnection();
                }

                @Override public void channelOpen(Sha256Hash contractHash) {
                    socketProtobufHandler.setSocketTimeout(0);
                    eventHandler.channelOpen(contractHash);
                }

                @Override public ListenableFuture<ByteString> paymentIncrease(Coin by, Coin to, @Nullable ByteString info) {
                    return eventHandler.paymentIncrease(by, to, info);
                }
            });

            protobufHandlerListener = new ProtobufConnection.Listener<Protos.TwoWayChannelMessage>() {
                @Override
                public synchronized void messageReceived(ProtobufConnection<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                    paymentChannelManager.receiveMessage(msg);
                }

                @Override
                public synchronized void connectionClosed(ProtobufConnection<Protos.TwoWayChannelMessage> handler) {
                    paymentChannelManager.connectionClosed();
                    if (closeReason != null)
                        eventHandler.channelClosed(closeReason);
                    else
                        eventHandler.channelClosed(PaymentChannelCloseException.CloseReason.CONNECTION_CLOSED);
                    eventHandler.setConnectionChannel(null);
                }

                @Override
                public synchronized void connectionOpen(ProtobufConnection<Protos.TwoWayChannelMessage> handler) {
                    ServerConnectionEventHandler eventHandler = eventHandlerFactory.onNewConnection(address);
                    if (eventHandler == null)
                        handler.closeConnection();
                    else {
                        ServerHandler.this.eventHandler = eventHandler;
                        ServerHandler.this.eventHandler.setConnectionChannel(socketProtobufHandler);
                        paymentChannelManager.connectionOpen();
                    }
                }
            };

            socketProtobufHandler = new ProtobufConnection<Protos.TwoWayChannelMessage>
                    (protobufHandlerListener, Protos.TwoWayChannelMessage.getDefaultInstance(), Short.MAX_VALUE, timeoutSeconds*1000);
        }

        private PaymentChannelCloseException.CloseReason closeReason;

        // The user-provided event handler
        private ServerConnectionEventHandler eventHandler;

        // The payment channel server which does the actual payment channel handling
        private final PaymentChannelServer paymentChannelManager;

        // The connection handler which puts/gets protobufs from the TCP socket
        private final ProtobufConnection<Protos.TwoWayChannelMessage> socketProtobufHandler;

        // The listener which connects to socketProtobufHandler
        private final ProtobufConnection.Listener<Protos.TwoWayChannelMessage> protobufHandlerListener;
    }

    /**
     * Binds to the given port and starts accepting new client connections.
     * @throws Exception If binding to the given port fails (eg SocketException: Permission denied for privileged ports)
     */
    public void bindAndStart(int port) throws Exception {
        server = new NioServer(new StreamConnectionFactory() {
            @Override
            public ProtobufConnection<Protos.TwoWayChannelMessage> getNewConnection(InetAddress inetAddress, int port) {
                return new ServerHandler(new InetSocketAddress(inetAddress, port), timeoutSeconds).socketProtobufHandler;
            }
        }, new InetSocketAddress(port));
        server.startAsync();
        server.awaitRunning();
    }

    /**
     * Sets up a new payment channel server which listens on the given port.
     *
     * @param broadcaster The PeerGroup on which transactions will be broadcast - should have multiple connections.
     * @param wallet The wallet which will be used to complete transactions
     * @param timeoutSeconds The read timeout between messages. This should accommodate latency and client ECDSA
     *                       signature operations.
     * @param minAcceptedChannelSize The minimum amount of coins clients must lock in to create a channel. Clients which
     *                               are unwilling or unable to lock in at least this value will immediately disconnect.
     *                               For this reason, a fairly conservative value (in terms of average value spent on a
     *                               channel) should generally be chosen.
     * @param eventHandlerFactory A factory which generates event handlers which are created for each new connection
     */
    public PaymentChannelServerListener(TransactionBroadcaster broadcaster, Wallet wallet,
                                        final int timeoutSeconds, Coin minAcceptedChannelSize,
                                        HandlerFactory eventHandlerFactory) throws IOException {
        this.wallet = checkNotNull(wallet);
        this.broadcaster = checkNotNull(broadcaster);
        this.eventHandlerFactory = checkNotNull(eventHandlerFactory);
        this.minAcceptedChannelSize = checkNotNull(minAcceptedChannelSize);
        this.timeoutSeconds = timeoutSeconds;
    }

    /**
     * <p>Closes all client connections currently connected gracefully.</p>
     *
     * <p>Note that this does <i>not</i> settle the actual payment channels (and broadcast payment transactions), which
     * must be done using the {@link StoredPaymentChannelServerStates} which manages the states for the associated
     * wallet.</p>
     */
    public void close() {
        server.stopAsync();
        server.awaitTerminated();
    }
}
