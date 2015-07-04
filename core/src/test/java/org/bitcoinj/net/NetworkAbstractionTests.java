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

package org.bitcoinj.net;

import org.bitcoinj.core.Utils;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;
import org.bitcoin.paymentchannel.Protos.TwoWayChannelMessage;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.net.SocketFactory;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.google.common.base.Preconditions.checkState;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(value = Parameterized.class)
public class NetworkAbstractionTests {
    private static final int CLIENT_MAJOR_VERSION = 1;
    private AtomicBoolean fail;
    private final int clientType;
    private final ClientConnectionManager channels;

    @Parameterized.Parameters
    public static Collection<Integer[]> parameters() {
        return Arrays.asList(new Integer[]{0}, new Integer[]{1}, new Integer[]{2}, new Integer[]{3});
    }

    public NetworkAbstractionTests(Integer clientType) throws Exception {
        this.clientType = clientType;
        if (clientType == 0) {
            channels = new NioClientManager();
            channels.startAsync();
        } else if (clientType == 1) {
            channels = new BlockingClientManager();
            channels.startAsync();
        } else
            channels = null;
    }

    private MessageWriteTarget openConnection(SocketAddress addr, ProtobufParser<Protos.TwoWayChannelMessage> parser) throws Exception {
        if (clientType == 0 || clientType == 1) {
            channels.openConnection(addr, parser);
            if (parser.writeTarget.get() == null)
                Thread.sleep(100);
            return parser.writeTarget.get();
        } else if (clientType == 2)
            return new NioClient(addr, parser, 100);
        else if (clientType == 3)
            return new BlockingClient(addr, parser, 100, SocketFactory.getDefault(), null);
        else
            throw new RuntimeException();
    }

    @Before
    public void setUp() {
        fail = new AtomicBoolean(false);
    }

    @After
    public void checkFail() {
        assertFalse(fail.get());
    }

    @Test
    public void testNullGetNewParser() throws Exception {
        final SettableFuture<Void> client1ConnectionOpened = SettableFuture.create();
        final SettableFuture<Void> client1Disconnected = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> client2MessageReceived = SettableFuture.create();
        final SettableFuture<Void> serverConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> client2ConnectionOpened = SettableFuture.create();
        final SettableFuture<Void> serverConnectionClosed = SettableFuture.create();
        final SettableFuture<Void> client2Disconnected = SettableFuture.create();
        NioServer server = new NioServer(new StreamParserFactory() {
            boolean finishedFirst = false;
            @Override
            public ProtobufParser<TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                if (!finishedFirst) {
                    finishedFirst = true;
                    return null;
                }

                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        handler.write(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        serverConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        serverConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
            }
        }, new InetSocketAddress("localhost", 4243));
        server.startAsync();
        server.awaitRunning();

        ProtobufParser<Protos.TwoWayChannelMessage> clientHandler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public synchronized void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        fail.set(true);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client1ConnectionOpened.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client1Disconnected.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        openConnection(new InetSocketAddress("localhost", 4243), clientHandler);

        client1ConnectionOpened.get();
        client1Disconnected.get();

        clientHandler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public synchronized void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        if (client2MessageReceived.isDone())
                            fail.set(true);
                        client2MessageReceived.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client2ConnectionOpened.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client2Disconnected.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        MessageWriteTarget client = openConnection(new InetSocketAddress("localhost", 4243), clientHandler);

        serverConnectionOpen.get();
        client2ConnectionOpened.get();

        Protos.TwoWayChannelMessage msg = Protos.TwoWayChannelMessage.newBuilder().setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN).build();
        clientHandler.write(msg);

        assertEquals(msg, client2MessageReceived.get());

        client.closeConnection();
        serverConnectionClosed.get();
        client2Disconnected.get();

        server.stopAsync().awaitTerminated();
    }

    @Test
    public void basicClientServerTest() throws Exception {
        // Tests creating a basic server, opening a client connection and sending a few messages

        final SettableFuture<Void> serverConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> clientConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> serverConnectionClosed = SettableFuture.create();
        final SettableFuture<Void> clientConnectionClosed = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage1Received = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage2Received = SettableFuture.create();
        NioServer server = new NioServer(new StreamParserFactory() {
            @Override
            public ProtobufParser<TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        handler.write(msg);
                        handler.write(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        serverConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        serverConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
            }
        }, new InetSocketAddress("localhost", 4243));
        server.startAsync();
        server.awaitRunning();

        ProtobufParser<Protos.TwoWayChannelMessage> clientHandler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public synchronized void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        if (clientMessage1Received.isDone())
                            clientMessage2Received.set(msg);
                        else
                            clientMessage1Received.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);

        MessageWriteTarget client = openConnection(new InetSocketAddress("localhost", 4243), clientHandler);

        clientConnectionOpen.get();
        serverConnectionOpen.get();

        Protos.TwoWayChannelMessage msg = Protos.TwoWayChannelMessage.newBuilder().setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN).build();
        clientHandler.write(msg);
        assertEquals(msg, clientMessage1Received.get());
        assertEquals(msg, clientMessage2Received.get());

        client.closeConnection();
        serverConnectionClosed.get();
        clientConnectionClosed.get();

        server.stopAsync();
        server.awaitTerminated();
        assertFalse(server.isRunning());
    }

    @Test
    public void basicTimeoutTest() throws Exception {
        // Tests various timeout scenarios

        final SettableFuture<Void> serverConnection1Open = SettableFuture.create();
        final SettableFuture<Void> clientConnection1Open = SettableFuture.create();
        final SettableFuture<Void> serverConnection1Closed = SettableFuture.create();
        final SettableFuture<Void> clientConnection1Closed = SettableFuture.create();

        final SettableFuture<Void> serverConnection2Open = SettableFuture.create();
        final SettableFuture<Void> clientConnection2Open = SettableFuture.create();
        final SettableFuture<Void> serverConnection2Closed = SettableFuture.create();
        final SettableFuture<Void> clientConnection2Closed = SettableFuture.create();
        NioServer server = new NioServer(new StreamParserFactory() {
            @Override
            public ProtobufParser<Protos.TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        fail.set(true);
                    }

                    @Override
                    public synchronized void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        if (serverConnection1Open.isDone()) {
                            handler.setSocketTimeout(0);
                            serverConnection2Open.set(null);
                        } else
                            serverConnection1Open.set(null);
                    }

                    @Override
                    public synchronized void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        if (serverConnection1Closed.isDone()) {
                            serverConnection2Closed.set(null);
                        } else
                            serverConnection1Closed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 10);
            }
        }, new InetSocketAddress("localhost", 4243));
        server.startAsync();
        server.awaitRunning();

        openConnection(new InetSocketAddress("localhost", 4243), new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        fail.set(true);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnection1Open.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnection1Closed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0));

        clientConnection1Open.get();
        serverConnection1Open.get();
        long closeDelayStart = System.currentTimeMillis();
        clientConnection1Closed.get();
        serverConnection1Closed.get();
        long closeDelayFinish = System.currentTimeMillis();

        ProtobufParser<Protos.TwoWayChannelMessage> client2Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        fail.set(true);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnection2Open.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnection2Closed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        openConnection(new InetSocketAddress("localhost", 4243), client2Handler);

        clientConnection2Open.get();
        serverConnection2Open.get();
        Thread.sleep((closeDelayFinish - closeDelayStart) * 10);
        assertFalse(clientConnection2Closed.isDone() || serverConnection2Closed.isDone());

        client2Handler.setSocketTimeout(10);
        clientConnection2Closed.get();
        serverConnection2Closed.get();

        server.stopAsync();
        server.awaitTerminated();
    }

    @Test
    public void largeDataTest() throws Exception {
        /** Test various large-data handling, essentially testing {@link ProtobufParser#receiveBytes(java.nio.ByteBuffer)} */
        final SettableFuture<Void> serverConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> clientConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> serverConnectionClosed = SettableFuture.create();
        final SettableFuture<Void> clientConnectionClosed = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage1Received = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage2Received = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage3Received = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage4Received = SettableFuture.create();
        NioServer server = new NioServer(new StreamParserFactory() {
            @Override
            public ProtobufParser<Protos.TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        handler.write(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        serverConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        serverConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 0x10000, 0);
            }
        }, new InetSocketAddress("localhost", 4243));
        server.startAsync();
        server.awaitRunning();

        ProtobufParser<Protos.TwoWayChannelMessage> clientHandler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public synchronized void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        if (clientMessage1Received.isDone()) {
                            if (clientMessage2Received.isDone()) {
                                if (clientMessage3Received.isDone()) {
                                    if (clientMessage4Received.isDone())
                                        fail.set(true);
                                    clientMessage4Received.set(msg);
                                } else
                                    clientMessage3Received.set(msg);
                            } else
                                clientMessage2Received.set(msg);
                        } else
                            clientMessage1Received.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        clientConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 0x10000, 0);

        MessageWriteTarget client = openConnection(new InetSocketAddress("localhost", 4243), clientHandler);

        clientConnectionOpen.get();
        serverConnectionOpen.get();

        // Large message that is larger than buffer and equal to maximum message size
        Protos.TwoWayChannelMessage msg = Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setMajor(CLIENT_MAJOR_VERSION)
                        .setPreviousChannelContractHash(ByteString.copyFrom(new byte[0x10000 - 12])))
                .build();
        // Small message that fits in the buffer
        Protos.TwoWayChannelMessage msg2 = Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setMajor(CLIENT_MAJOR_VERSION)
                        .setPreviousChannelContractHash(ByteString.copyFrom(new byte[1])))
                .build();
        // Break up the message into chunks to simulate packet network (with strange MTUs...)
        byte[] messageBytes = msg.toByteArray();
        byte[] messageLength = new byte[4];
        Utils.uint32ToByteArrayBE(messageBytes.length, messageLength, 0);
        client.writeBytes(new byte[]{messageLength[0], messageLength[1]});
        Thread.sleep(10);
        client.writeBytes(new byte[]{messageLength[2], messageLength[3]});
        Thread.sleep(10);
        client.writeBytes(new byte[]{messageBytes[0], messageBytes[1]});
        Thread.sleep(10);
        client.writeBytes(Arrays.copyOfRange(messageBytes, 2, messageBytes.length - 1));
        Thread.sleep(10);

        // Now send the end of msg + msg2 + msg3 all at once
        byte[] messageBytes2 = msg2.toByteArray();
        byte[] messageLength2 = new byte[4];
        Utils.uint32ToByteArrayBE(messageBytes2.length, messageLength2, 0);
        byte[] sendBytes = Arrays.copyOf(new byte[] {messageBytes[messageBytes.length-1]}, 1 + messageBytes2.length*2 + messageLength2.length*2);
        System.arraycopy(messageLength2, 0, sendBytes, 1, 4);
        System.arraycopy(messageBytes2, 0, sendBytes, 5, messageBytes2.length);
        System.arraycopy(messageLength2, 0, sendBytes, 5 + messageBytes2.length, 4);
        System.arraycopy(messageBytes2, 0, sendBytes, 9 + messageBytes2.length, messageBytes2.length);
        client.writeBytes(sendBytes);
        assertEquals(msg, clientMessage1Received.get());
        assertEquals(msg2, clientMessage2Received.get());
        assertEquals(msg2, clientMessage3Received.get());

        // Now resent msg2 in chunks, by itself
        Utils.uint32ToByteArrayBE(messageBytes2.length, messageLength2, 0);
        client.writeBytes(new byte[]{messageLength2[0], messageLength2[1]});
        Thread.sleep(10);
        client.writeBytes(new byte[]{messageLength2[2], messageLength2[3]});
        Thread.sleep(10);
        client.writeBytes(new byte[]{messageBytes2[0], messageBytes2[1]});
        Thread.sleep(10);
        client.writeBytes(new byte[]{messageBytes2[2], messageBytes2[3]});
        Thread.sleep(10);
        client.writeBytes(Arrays.copyOfRange(messageBytes2, 4, messageBytes2.length));
        assertEquals(msg2, clientMessage4Received.get());

        Protos.TwoWayChannelMessage msg5 = Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setMajor(CLIENT_MAJOR_VERSION)
                        .setPreviousChannelContractHash(ByteString.copyFrom(new byte[0x10000 - 11])))
                .build();
        try {
            clientHandler.write(msg5);
        } catch (IllegalStateException e) {}

        // Override max size and make sure the server drops our connection
        byte[] messageLength5 = new byte[4];
        Utils.uint32ToByteArrayBE(msg5.toByteArray().length, messageLength5, 0);
        client.writeBytes(messageLength5);

        serverConnectionClosed.get();
        clientConnectionClosed.get();

        server.stopAsync();
        server.awaitTerminated();
    }

    @Test
    public void testConnectionEventHandlers() throws Exception {
        final SettableFuture<Void> serverConnection1Open = SettableFuture.create();
        final SettableFuture<Void> serverConnection2Open = SettableFuture.create();
        final SettableFuture<Void> serverConnection3Open = SettableFuture.create();
        final SettableFuture<Void> client1ConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> client2ConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> client3ConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> serverConnectionClosed1 = SettableFuture.create();
        final SettableFuture<Void> serverConnectionClosed2 = SettableFuture.create();
        final SettableFuture<Void> serverConnectionClosed3 = SettableFuture.create();
        final SettableFuture<Void> client1ConnectionClosed = SettableFuture.create();
        final SettableFuture<Void> client2ConnectionClosed = SettableFuture.create();
        final SettableFuture<Void> client3ConnectionClosed = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> client1MessageReceived = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> client2MessageReceived = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> client3MessageReceived = SettableFuture.create();
        NioServer server = new NioServer(new StreamParserFactory() {
            @Override
            public ProtobufParser<Protos.TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        handler.write(msg);
                    }

                    @Override
                    public synchronized void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        if (serverConnection1Open.isDone()) {
                            if (serverConnection2Open.isDone())
                                serverConnection3Open.set(null);
                            else
                                serverConnection2Open.set(null);
                        } else
                            serverConnection1Open.set(null);
                    }

                    @Override
                    public synchronized void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        if (serverConnectionClosed1.isDone()) {
                            if (serverConnectionClosed2.isDone()) {
                                checkState(!serverConnectionClosed3.isDone());
                                serverConnectionClosed3.set(null);
                            } else
                                serverConnectionClosed2.set(null);
                        } else
                            serverConnectionClosed1.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
            }
        }, new InetSocketAddress("localhost", 4243));
        server.startAsync();
        server.awaitRunning();

        ProtobufParser<Protos.TwoWayChannelMessage> client1Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        client1MessageReceived.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client1ConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client1ConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        MessageWriteTarget client1 = openConnection(new InetSocketAddress("localhost", 4243), client1Handler);

        client1ConnectionOpen.get();
        serverConnection1Open.get();

        ProtobufParser<Protos.TwoWayChannelMessage> client2Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        client2MessageReceived.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client2ConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client2ConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        openConnection(new InetSocketAddress("localhost", 4243), client2Handler);

        client2ConnectionOpen.get();
        serverConnection2Open.get();

        ProtobufParser<Protos.TwoWayChannelMessage> client3Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        client3MessageReceived.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        client3ConnectionOpen.set(null);
                    }

                    @Override
                    public synchronized void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) {
                        checkState(!client3ConnectionClosed.isDone());
                        client3ConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        NioClient client3 = new NioClient(new InetSocketAddress("localhost", 4243), client3Handler, 0);

        client3ConnectionOpen.get();
        serverConnection3Open.get();

        Protos.TwoWayChannelMessage msg = Protos.TwoWayChannelMessage.newBuilder().setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN).build();
        client1Handler.write(msg);
        assertEquals(msg, client1MessageReceived.get());

        Protos.TwoWayChannelMessage msg2 = Protos.TwoWayChannelMessage.newBuilder().setType(Protos.TwoWayChannelMessage.MessageType.INITIATE).build();
        client2Handler.write(msg2);
        assertEquals(msg2, client2MessageReceived.get());

        client1.closeConnection();
        serverConnectionClosed1.get();
        client1ConnectionClosed.get();

        Protos.TwoWayChannelMessage msg3 = Protos.TwoWayChannelMessage.newBuilder().setType(Protos.TwoWayChannelMessage.MessageType.CLOSE).build();
        client3Handler.write(msg3);
        assertEquals(msg3, client3MessageReceived.get());

        // Try to create a race condition by triggering handlerThread closing and client3 closing at the same time
        // This often triggers ClosedByInterruptException in handleKey
        server.stopAsync();
        server.selector.wakeup();
        client3.closeConnection();
        client3ConnectionClosed.get();
        serverConnectionClosed3.get();

        server.stopAsync();
        server.awaitTerminated();
        client2ConnectionClosed.get();
        serverConnectionClosed2.get();

        server.stopAsync();
        server.awaitTerminated();
    }
}
