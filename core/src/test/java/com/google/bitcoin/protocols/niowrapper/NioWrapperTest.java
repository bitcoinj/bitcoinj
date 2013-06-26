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

package com.google.bitcoin.protocols.niowrapper;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.bitcoin.core.Utils;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static com.google.common.base.Preconditions.checkState;
import static org.junit.Assert.*;

public class NioWrapperTest {
    private AtomicBoolean fail;

    @Before
    public void setUp() {
        fail = new AtomicBoolean(false);
    }

    @After
    public void checkFail() {
        assertFalse(fail.get());
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
        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Override
            public ProtobufParser getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        handler.write(msg);
                        handler.write(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        serverConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        serverConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
            }
        });
        server.start(new InetSocketAddress("localhost", 4243));

        ProtobufParser<Protos.TwoWayChannelMessage> clientHandler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public synchronized void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
                        if (clientMessage1Received.isDone())
                            clientMessage2Received.set(msg);
                        else
                            clientMessage1Received.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        clientConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        clientConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);

        ProtobufClient client = new ProtobufClient(new InetSocketAddress("localhost", 4243), clientHandler, 0);

        clientConnectionOpen.get();
        serverConnectionOpen.get();

        Protos.TwoWayChannelMessage msg = Protos.TwoWayChannelMessage.newBuilder().setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN).build();
        clientHandler.write(msg);
        assertEquals(msg, clientMessage1Received.get());
        assertEquals(msg, clientMessage2Received.get());

        client.closeConnection();
        serverConnectionClosed.get();
        clientConnectionClosed.get();

        server.stop();
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
        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Override
            public ProtobufParser getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
                        fail.set(true);
                    }

                    @Override
                    public synchronized void connectionOpen(ProtobufParser handler) {
                        if (serverConnection1Open.isDone()) {
                            handler.setSocketTimeout(0);
                            serverConnection2Open.set(null);
                        } else
                            serverConnection1Open.set(null);
                    }

                    @Override
                    public synchronized void connectionClosed(ProtobufParser handler) {
                        if (serverConnection1Closed.isDone()) {
                            serverConnection2Closed.set(null);
                        } else
                            serverConnection1Closed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 10);
            }
        });
        server.start(new InetSocketAddress("localhost", 4243));

        new ProtobufClient(new InetSocketAddress("localhost", 4243), new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
                        fail.set(true);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        clientConnection1Open.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        clientConnection1Closed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0), 0);

        clientConnection1Open.get();
        serverConnection1Open.get();
        Thread.sleep(15);
        assertTrue(clientConnection1Closed.isDone() && serverConnection1Closed.isDone());

        ProtobufParser<Protos.TwoWayChannelMessage> client2Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
                        fail.set(true);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        clientConnection2Open.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        clientConnection2Closed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        ProtobufClient client2 = new ProtobufClient(new InetSocketAddress("localhost", 4243), client2Handler, 0);

        clientConnection2Open.get();
        serverConnection2Open.get();
        Thread.sleep(15);
        assertFalse(clientConnection2Closed.isDone() || serverConnection2Closed.isDone());

        client2Handler.setSocketTimeout(10);
        Thread.sleep(15);
        assertTrue(clientConnection2Closed.isDone() && serverConnection2Closed.isDone());

        server.stop();
    }

    @Test
    public void largeDataTest() throws Exception {
        /** Test various large-data handling, essentially testing {@link ProtobufParser#receive(java.nio.ByteBuffer)} */
        final SettableFuture<Void> serverConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> clientConnectionOpen = SettableFuture.create();
        final SettableFuture<Void> serverConnectionClosed = SettableFuture.create();
        final SettableFuture<Void> clientConnectionClosed = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage1Received = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage2Received = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage3Received = SettableFuture.create();
        final SettableFuture<Protos.TwoWayChannelMessage> clientMessage4Received = SettableFuture.create();
        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Override
            public ProtobufParser getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        handler.write(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        serverConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        serverConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 0x10000, 0);
            }
        });
        server.start(new InetSocketAddress("localhost", 4243));

        ProtobufParser<Protos.TwoWayChannelMessage> clientHandler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public synchronized void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
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
                    public void connectionOpen(ProtobufParser handler) {
                        clientConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        clientConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 0x10000, 0);

        ProtobufClient client = new ProtobufClient(new InetSocketAddress("localhost", 4243), clientHandler, 0);

        clientConnectionOpen.get();
        serverConnectionOpen.get();

        // Large message that is larger than buffer and equal to maximum message size
        Protos.TwoWayChannelMessage msg = Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setMajor(1)
                        .setPreviousChannelContractHash(ByteString.copyFrom(new byte[0x10000 - 12])))
                .build();
        // Small message that fits in the buffer
        Protos.TwoWayChannelMessage msg2 = Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setMajor(1)
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
                        .setMajor(1)
                        .setPreviousChannelContractHash(ByteString.copyFrom(new byte[0x10000 - 11])))
                .build();
        try {
            clientHandler.write(msg5);
        } catch (IllegalStateException e) {}

        // Override max size and make sure the server drops our connection
        byte[] messageBytes5 = msg5.toByteArray();
        byte[] messageLength5 = new byte[4];
        Utils.uint32ToByteArrayBE(messageBytes5.length, messageLength5, 0);
        client.writeBytes(messageBytes5);
        client.writeBytes(messageLength5);

        serverConnectionClosed.get();
        clientConnectionClosed.get();

        server.stop();
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
        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Override
            public ProtobufParser getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> handler, Protos.TwoWayChannelMessage msg) {
                        handler.write(msg);
                    }

                    @Override
                    public synchronized void connectionOpen(ProtobufParser handler) {
                        if (serverConnection1Open.isDone()) {
                            if (serverConnection2Open.isDone())
                                serverConnection3Open.set(null);
                            else
                                serverConnection2Open.set(null);
                        } else
                            serverConnection1Open.set(null);
                    }

                    @Override
                    public synchronized void connectionClosed(ProtobufParser handler) {
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
        });
        server.start(new InetSocketAddress("localhost", 4243));

        ProtobufParser<Protos.TwoWayChannelMessage> client1Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
                        client1MessageReceived.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        client1ConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        client1ConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        ProtobufClient client1 = new ProtobufClient(new InetSocketAddress("localhost", 4243), client1Handler, 0);

        client1ConnectionOpen.get();
        serverConnection1Open.get();

        ProtobufParser<Protos.TwoWayChannelMessage> client2Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
                        client2MessageReceived.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        client2ConnectionOpen.set(null);
                    }

                    @Override
                    public void connectionClosed(ProtobufParser handler) {
                        client2ConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        ProtobufClient client2 = new ProtobufClient(new InetSocketAddress("localhost", 4243), client2Handler, 0);

        client2ConnectionOpen.get();
        serverConnection2Open.get();

        ProtobufParser<Protos.TwoWayChannelMessage> client3Handler = new ProtobufParser<Protos.TwoWayChannelMessage>(
                new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                    @Override
                    public void messageReceived(ProtobufParser handler, Protos.TwoWayChannelMessage msg) {
                        client3MessageReceived.set(msg);
                    }

                    @Override
                    public void connectionOpen(ProtobufParser handler) {
                        client3ConnectionOpen.set(null);
                    }

                    @Override
                    public synchronized void connectionClosed(ProtobufParser handler) {
                        checkState(!client3ConnectionClosed.isDone());
                        client3ConnectionClosed.set(null);
                    }
                }, Protos.TwoWayChannelMessage.getDefaultInstance(), 1000, 0);
        ProtobufClient client3 = new ProtobufClient(new InetSocketAddress("localhost", 4243), client3Handler, 0);

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

        // Try to create a race condition by triggering handlerTread closing and client3 closing at the same time
        // This often triggers ClosedByInterruptException in handleKey
        server.handlerThread.interrupt();
        client3.closeConnection();
        client3ConnectionClosed.get();
        serverConnectionClosed3.get();

        server.handlerThread.join();
        client2ConnectionClosed.get();
        serverConnectionClosed2.get();

        server.stop();
    }
}
