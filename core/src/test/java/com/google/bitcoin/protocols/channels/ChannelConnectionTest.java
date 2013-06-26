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

import java.io.File;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nullable;

import com.google.bitcoin.core.*;
import com.google.bitcoin.protocols.niowrapper.ProtobufParser;
import com.google.bitcoin.protocols.niowrapper.ProtobufParserFactory;
import com.google.bitcoin.protocols.niowrapper.ProtobufServer;
import com.google.bitcoin.utils.Locks;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;
import org.easymock.Capture;
import org.easymock.IMocksControl;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static com.google.bitcoin.protocols.channels.PaymentChannelCloseException.CloseReason;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

public class ChannelConnectionTest extends TestWithWallet {
    private Wallet serverWallet;
    private AtomicBoolean fail;

    private interface PaymentChannelClientReceiver {
        void receiveMessage(Protos.TwoWayChannelMessage msg);
        void connectionOpen();
        void connectionClosed();
        void close();
    }
    private class PaymentChannelClientReceiverImpl implements PaymentChannelClientReceiver {
        private PaymentChannelClient client;
        public PaymentChannelClientReceiverImpl(PaymentChannelClient client) { this.client = client; }
        public void receiveMessage(Protos.TwoWayChannelMessage msg) { client.receiveMessage(msg); }
        public void connectionOpen() { client.connectionOpen(); }
        public void connectionClosed() { client.connectionClosed(); }
        public void close() { client.close(); }
    }
    private PaymentChannelClientReceiver sendClient;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        sendMoneyToWallet(Utils.COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        sendMoneyToWallet(Utils.COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        wallet.addExtension(new StoredPaymentChannelClientStates(new TransactionBroadcaster() {
            @Override
            public ListenableFuture<Transaction> broadcastTransaction(Transaction tx) {
                fail();
                return null;
            }
        }, wallet));
        chain = new BlockChain(params, wallet, blockStore); // Recreate chain as sendMoneyToWallet will confuse it
        serverWallet = new Wallet(params);
        serverWallet.addKey(new ECKey());
        chain.addWallet(serverWallet);
        // Use an atomic boolean to indicate failure because fail()/assert*() dont work in network threads
        fail = new AtomicBoolean(false);
        // Because there are no separate threads in the tests here (we call back into client/server in server/client
        // handlers), we have lots of lock cycles. A normal user shouldn't have this issue as they are probably not both
        // client+server running in the same thread.
        Locks.warnOnLockCycles();
    }

    @After
    public void checkFail() {
        assertFalse(fail.get());
        Locks.throwOnLockCycles();
    }

    @Test
    public void testSimpleChannel() throws Exception {
        // Test without any issues

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        // We'll broadcast two txns: multisig contract and close transaction.
        SettableFuture<Transaction> multiSigFuture = SettableFuture.create();
        SettableFuture<Transaction> closeFuture = SettableFuture.create();
        final Capture<Transaction> broadcastMultiSig = new Capture<Transaction>();
        Capture<Transaction> broadcastClose = new Capture<Transaction>();
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig))).andReturn(multiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastClose))).andReturn(closeFuture);
        control.replay();

        final SettableFuture<ListenableFuture<PaymentChannelServerState>> serverCloseFuture = SettableFuture.create();
        final SettableFuture<Void> channelOpenFuture = SettableFuture.create();
        final SettableFuture<Void> twoCentsReceivedFuture = SettableFuture.create();
        final PaymentChannelServerListener server = new PaymentChannelServerListener(mockPeerGroup, serverWallet, 1, Utils.COIN,
                new PaymentChannelServerListener.HandlerFactory() {
                    @Nullable
                    @Override
                    public ServerConnectionEventHandler onNewConnection(SocketAddress clientAddress) {
                        return new ServerConnectionEventHandler() {
                            @Override
                            public void channelOpen(Sha256Hash channelId) {
                                if (!channelId.equals(broadcastMultiSig.getValue().getHash()))
                                    fail.set(true);
                                channelOpenFuture.set(null);
                            }

                            @Override
                            public void paymentIncrease(BigInteger by, BigInteger to) {
                                if (to.equals(Utils.CENT.shiftLeft(1)))
                                    twoCentsReceivedFuture.set(null);
                            }

                            @Override
                            public void channelClosed(CloseReason reason) {
                                serverCloseFuture.set(null);
                            }
                        };
                    }
                });
        server.bindAndStart(4243);

        PaymentChannelClientConnection client = new PaymentChannelClientConnection(new InetSocketAddress("localhost", 4243), 1, wallet, myKey, Utils.COIN, "");

        while (!broadcastMultiSig.hasCaptured())
            Thread.sleep(100);
        multiSigFuture.set(broadcastMultiSig.getValue());

        client.getChannelOpenFuture().get();
        assertTrue(channelOpenFuture.isDone());

        // Set up an autosave listener to make sure the server is saving the wallet after each payment increase
        final AtomicInteger autoSaveCount = new AtomicInteger(0);
        File tempFile = File.createTempFile("channel_connection_test", ".wallet");
        tempFile.deleteOnExit();
        serverWallet.autosaveToFile(tempFile, 0, TimeUnit.SECONDS, new Wallet.AutosaveEventListener() {
            @Override
            public boolean caughtException(Throwable t) {
                fail.set(true);
                return false;
            }

            @Override
            public void onBeforeAutoSave(File tempFile) {
                autoSaveCount.incrementAndGet();
            }

            @Override public void onAfterAutoSave(File newlySavedFile) { }
        });
        assertEquals(0, autoSaveCount.get());

        Thread.sleep(1250); // No timeouts once the channel is open
        client.incrementPayment(Utils.CENT);
        while (autoSaveCount.get() != 1)
            Thread.sleep(100);
        client.incrementPayment(Utils.CENT);
        while (autoSaveCount.get() != 2)
            Thread.sleep(100);
        twoCentsReceivedFuture.get();
        client.incrementPayment(Utils.CENT);
        while (autoSaveCount.get() != 3)
            Thread.sleep(100);

        StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)serverWallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
        StoredServerChannel storedServerChannel = channels.getChannel(broadcastMultiSig.getValue().getHash());
        PaymentChannelServerState serverState;
        synchronized (storedServerChannel) {
            serverState = storedServerChannel.getState(serverWallet, mockPeerGroup);
        }

        client.close();
        client.close();

        while (serverState.getState() != PaymentChannelServerState.State.CLOSING)
            Thread.sleep(100);

        client.close();

        closeFuture.set(broadcastClose.getValue());

        if (!serverState.getBestValueToMe().equals(Utils.CENT.multiply(BigInteger.valueOf(3))) || !serverState.getFeePaid().equals(BigInteger.ZERO))
            fail();

        assertTrue(channels.mapChannels.isEmpty());

        control.verify();
        server.close();
        server.close();
    }

    @Test
    public void testServerErrorHandling() throws Exception {
        // Gives the server crap and checks proper error responses are sent

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        control.replay();

        final PaymentChannelServer server = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        sendClient.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        if (reason != CloseReason.NO_ACCEPTABLE_VERSION)
                            fail.set(true);
                        sendClient.connectionClosed();
                    }

                    @Override public void channelOpen(Sha256Hash contractHash) { fail.set(true); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail.set(true); }
                });

        // Make sure we get back NO_ACCEPTABLE_VERSION if we send a version message that is very high
        final SettableFuture<Void> inactiveFuture = SettableFuture.create();
        sendClient = new PaymentChannelClientReceiver() {
            @Override
            public void receiveMessage(Protos.TwoWayChannelMessage msg) {
                if (msg.getType() != Protos.TwoWayChannelMessage.MessageType.ERROR ||
                        !msg.hasError() || msg.getError().getCode() != Protos.Error.ErrorCode.NO_ACCEPTABLE_VERSION)
                    fail.set(true);
                inactiveFuture.set(null);
            }

            @Override
            public void connectionOpen() {
                Protos.ClientVersion.Builder versionNegotiationBuilder = Protos.ClientVersion.newBuilder();
                versionNegotiationBuilder.setMajor(10);
                versionNegotiationBuilder.setMinor(42);
                server.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                        .setClientVersion(versionNegotiationBuilder)
                        .build());
            }

            @Override public void connectionClosed() { }
            @Override public void close() { }
        };
        server.connectionOpen();
        sendClient.connectionOpen();
        inactiveFuture.get();

        // Make sure we get back SYNTAX_ERROR if we send messages in the wrong order
        final SettableFuture<Void> inactiveFuture2 = SettableFuture.create();
        final PaymentChannelServer server2 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        sendClient.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        if (reason != CloseReason.REMOTE_SENT_INVALID_MESSAGE)
                            fail.set(true);
                        sendClient.connectionClosed();
                    }

                    @Override public void channelOpen(Sha256Hash contractHash) { fail.set(true); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail.set(true); }
                });
        sendClient = new PaymentChannelClientReceiver() {
            int step = 0;
            @Override
            public void receiveMessage(Protos.TwoWayChannelMessage msg) {
                if ((step != 0 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION) &&
                        (step != 1 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.INITIATE) &&
                        (step != 2 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.ERROR || msg.getError().getCode() != Protos.Error.ErrorCode.SYNTAX_ERROR))
                    fail.set(true);
                step++;
                if (step == 2) {
                    Protos.UpdatePayment.Builder updatePaymentBuilder = Protos.UpdatePayment.newBuilder()
                            .setClientChangeValue(0).setSignature(ByteString.EMPTY);
                    server2.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                            .setType(Protos.TwoWayChannelMessage.MessageType.UPDATE_PAYMENT)
                            .setUpdatePayment(updatePaymentBuilder)
                            .build());
                } else if (step == 3)
                    inactiveFuture2.set(null);
            }

            @Override
            public void connectionOpen() {
                Protos.ClientVersion.Builder versionNegotiationBuilder = Protos.ClientVersion.newBuilder()
                        .setMajor(0).setMinor(42);
                server2.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                        .setClientVersion(versionNegotiationBuilder)
                        .build());
            }
            @Override public void connectionClosed() { }
            @Override public void close() { }
        };
        server2.connectionOpen();
        sendClient.connectionOpen();
        inactiveFuture2.get();

        // Make sure we get back a BAD_TRANSACTION if we send crap for a refund transaction
        final SettableFuture<Void> inactiveFuture3 = SettableFuture.create();
        final PaymentChannelServer server3 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        sendClient.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        if (reason != CloseReason.REMOTE_SENT_INVALID_MESSAGE)
                            fail.set(true);
                        sendClient.connectionClosed();
                    }

                    @Override public void channelOpen(Sha256Hash contractHash) { fail.set(true); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail.set(true); }
                });
        sendClient = new PaymentChannelClientReceiver() {
            int step = 0;
            @Override
            public void receiveMessage(Protos.TwoWayChannelMessage msg) {
                if ((step != 0 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION) &&
                        (step != 1 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.INITIATE) &&
                        (step != 2 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.ERROR || msg.getError().getCode() != Protos.Error.ErrorCode.BAD_TRANSACTION))
                    fail.set(true);
                step++;
                if (step == 2) {
                    Protos.ProvideRefund.Builder provideRefundBuilder = Protos.ProvideRefund.newBuilder()
                            .setMultisigKey(ByteString.EMPTY).setTx(ByteString.EMPTY);
                    server3.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                            .setType(Protos.TwoWayChannelMessage.MessageType.PROVIDE_REFUND)
                            .setProvideRefund(provideRefundBuilder)
                            .build());
                } else if (step == 3)
                    inactiveFuture3.set(null);
            }

            @Override
            public void connectionOpen() {
                Protos.ClientVersion.Builder versionNegotiationBuilder = Protos.ClientVersion.newBuilder()
                        .setMajor(0).setMinor(42);
                server3.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                        .setClientVersion(versionNegotiationBuilder)
                        .build());
            }
            @Override public void connectionClosed() { }
            @Override public void close() { }
        };
        server3.connectionOpen();
        sendClient.connectionOpen();
        inactiveFuture3.get();

        // Make sure the server closes the socket on CLOSE
        final SettableFuture<Void> inactiveFuture4 = SettableFuture.create();
        final PaymentChannelServer server4 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        sendClient.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        if (reason != CloseReason.CLIENT_REQUESTED_CLOSE)
                            fail.set(true);
                        sendClient.connectionClosed();
                    }

                    @Override public void channelOpen(Sha256Hash contractHash) { fail.set(true); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail.set(true); }
                });
        sendClient = new PaymentChannelClientReceiver() {
            int step = 0;
            @Override
            public void receiveMessage(Protos.TwoWayChannelMessage msg) {
                // Server may send SERVER_VERSION + INITIATE in one go, so we could get both
                if ((step != 0 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION) &&
                        (step != 1 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.INITIATE))
                    fail.set(true);
                step++;
                server4.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.CLOSE)
                        .build());
            }

            @Override
            public void connectionOpen() {
                Protos.ClientVersion.Builder versionNegotiationBuilder = Protos.ClientVersion.newBuilder()
                        .setMajor(0).setMinor(42);
                server4.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                        .setClientVersion(versionNegotiationBuilder)
                        .build());
            }

            @Override
            public void connectionClosed() {
                inactiveFuture4.set(null);
            }
            @Override public void close() { }
        };
        server4.connectionOpen();
        sendClient.connectionOpen();
        inactiveFuture4.get();

        // Make sure the server closes the socket on ERROR
        final SettableFuture<Void> inactiveFuture5 = SettableFuture.create();
        final PaymentChannelServer server5 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        sendClient.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        if (reason != CloseReason.REMOTE_SENT_ERROR)
                            fail.set(true);
                        sendClient.connectionClosed();
                    }

                    @Override public void channelOpen(Sha256Hash contractHash) { fail.set(true); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail.set(true); }
                });
        sendClient = new PaymentChannelClientReceiver() {
            int step = 0;
            @Override
            public void receiveMessage(Protos.TwoWayChannelMessage msg) {
                // Server may send SERVER_VERSION + INITIATE in one go, so we could get both
                if ((step != 0 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION) &&
                        (step != 1 || msg.getType() != Protos.TwoWayChannelMessage.MessageType.INITIATE))
                    fail.set(true);
                server5.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.ERROR)
                        .setError(Protos.Error.newBuilder().setCode(Protos.Error.ErrorCode.TIMEOUT))
                        .build());
                step++;
            }

            @Override
            public void connectionOpen() {
                Protos.ClientVersion.Builder versionNegotiationBuilder = Protos.ClientVersion.newBuilder()
                        .setMajor(0).setMinor(42);
                server5.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                        .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                        .setClientVersion(versionNegotiationBuilder)
                        .build());
            }

            @Override
            public void connectionClosed() {
                inactiveFuture5.set(null);
            }
            @Override public void close() { }
        };
        server5.connectionOpen();
        sendClient.connectionOpen();
        inactiveFuture5.get();

        control.verify();
    }

    @Test
    public void testChannelResume() throws Exception {
        // Tests various aspects of channel resuming

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        final PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        final SettableFuture<Transaction> multiSigFuture = SettableFuture.create();
        final SettableFuture<Transaction> multiSigFuture2 = SettableFuture.create();
        SettableFuture<Transaction> closeFuture = SettableFuture.create();
        SettableFuture<Transaction> closeFuture2 = SettableFuture.create();
        final Capture<Transaction> broadcastMultiSig = new Capture<Transaction>();
        final Capture<Transaction> broadcastMultiSig2 = new Capture<Transaction>();
        Capture<Transaction> broadcastClose = new Capture<Transaction>();
        Capture<Transaction> broadcastClose2 = new Capture<Transaction>();
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig))).andReturn(multiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig2))).andReturn(multiSigFuture2);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastClose))).andReturn(closeFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastClose2))).andReturn(closeFuture2);
        control.replay();

        // Use a mock clock
        Utils.rollMockClock(0);

        StoredPaymentChannelClientStates clientStoredChannels = (StoredPaymentChannelClientStates)wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);


        // Check that server-side will reject incorrectly formatted hashes
        final SettableFuture<Void> server1VersionSent = SettableFuture.create();
        final SettableFuture<Void> server1InitiateSent = SettableFuture.create();
        PaymentChannelServer server1 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        if (!server1VersionSent.isDone()) {
                            assertEquals(Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION, msg.getType());
                            server1VersionSent.set(null);
                            return;
                        }
                        assertTrue(!server1InitiateSent.isDone() && msg.getType() == Protos.TwoWayChannelMessage.MessageType.INITIATE);
                        server1InitiateSent.set(null);
                    }
                    @Override public void destroyConnection(CloseReason reason) { fail(); }
                    @Override public void channelOpen(Sha256Hash contractHash) { fail(); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail(); }
                });
        server1.connectionOpen();
        server1.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setPreviousChannelContractHash(ByteString.copyFrom(new byte[]{0x00, 0x01}))
                        .setMajor(0).setMinor(42))
                .build());

        assertTrue(server1InitiateSent.isDone());

        // Now open a normal channel
        final SettableFuture<Void> client2OpenFuture = SettableFuture.create();
        final SettableFuture<Void> client2CloseFuture = SettableFuture.create();
        final SettableFuture<Void> server2PaymentFuture = SettableFuture.create();
        final SettableFuture<Sha256Hash> server2ContractHashFuture = SettableFuture.create();
        final PaymentChannelServer server2 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN, new PaymentChannelServer.ServerConnection() {
            @Override public void sendToClient(Protos.TwoWayChannelMessage msg) { sendClient.receiveMessage(msg); }

            @Override
            public void destroyConnection(CloseReason reason) {
                assertEquals(CloseReason.SERVER_REQUESTED_CLOSE, reason);
            }

            @Override
            public void channelOpen(Sha256Hash contractHash) {
                server2ContractHashFuture.set(contractHash);
            }

            @Override
            public void paymentIncrease(BigInteger by, BigInteger to) {
                assertTrue(by.equals(Utils.CENT) && to.equals(Utils.CENT));
                server2PaymentFuture.set(null);
            }
        });

        PaymentChannelClient client2 = new PaymentChannelClient(wallet, myKey, Utils.COIN, Sha256Hash.create(new byte[] {}),
                new PaymentChannelClient.ClientConnection() {
                    @Override public void sendToServer(Protos.TwoWayChannelMessage msg) { server2.receiveMessage(msg); }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        assertEquals(CloseReason.SERVER_REQUESTED_CLOSE, reason);
                        client2CloseFuture.set(null);
                        sendClient.connectionClosed();
                    }

                    @Override
                    public void channelOpen() {
                        client2OpenFuture.set(null);
                    }
                });
        sendClient = new PaymentChannelClientReceiverImpl(client2);
        server2.connectionOpen();
        client2.connectionOpen();

        multiSigFuture.set(broadcastMultiSig.getValue());
        assertTrue(client2OpenFuture.isDone() && server2ContractHashFuture.isDone());
        assertEquals(broadcastMultiSig.getValue().getHash(), server2ContractHashFuture.get());

        client2.incrementPayment(Utils.CENT);
        assertTrue(server2PaymentFuture.isDone());

        server2.close();
        server2.connectionClosed();
        assertFalse(client2.connectionOpen);
        assertTrue(client2CloseFuture.isDone());
        // There is now an open channel worth COIN-CENT with id Sha256.create(new byte[] {})

        assertEquals(1, clientStoredChannels.mapChannels.size());

        // Check that server-side won't attempt to reopen a nonexistent channel
        final SettableFuture<Void> server3VersionSent = SettableFuture.create();
        final SettableFuture<Void> server3InitiateSent = SettableFuture.create();
        PaymentChannelServer server3 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        if (!server3VersionSent.isDone()) {
                            assertTrue(msg.getType() == Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION);
                            server3VersionSent.set(null);
                            return;
                        }
                        assertTrue(!server3InitiateSent.isDone() && msg.getType() == Protos.TwoWayChannelMessage.MessageType.INITIATE);
                        server3InitiateSent.set(null);
                    }
                    @Override public void destroyConnection(CloseReason reason) { fail(); }
                    @Override public void channelOpen(Sha256Hash contractHash) { fail(); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail(); }
                });
        server3.connectionOpen();
        server3.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setPreviousChannelContractHash(ByteString.copyFrom(Sha256Hash.create(new byte[]{0x03}).getBytes()))
                        .setMajor(0).setMinor(42))
                .build());

        assertTrue(server3InitiateSent.isDone());


        // Now reopen channel 2
        final SettableFuture<Void> client4OpenFuture = SettableFuture.create();
        final SettableFuture<Void> client4CloseFuture = SettableFuture.create();
        final SettableFuture<Void> server4CloseFuture = SettableFuture.create();
        final SettableFuture<Void> server4PaymentFuture = SettableFuture.create();
        final PaymentChannelServer server4 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN, new PaymentChannelServer.ServerConnection() {
            @Override public void sendToClient(Protos.TwoWayChannelMessage msg) { sendClient.receiveMessage(msg); }

            @Override
            public void destroyConnection(CloseReason reason) {
                assertEquals(CloseReason.CLIENT_REQUESTED_CLOSE, reason);
                server4CloseFuture.set(null);
            }

            @Override
            public void channelOpen(Sha256Hash contractHash) {
                try {
                    assertEquals(server2ContractHashFuture.get(), contractHash);
                } catch (Exception e) { fail(); }
            }

            @Override
            public void paymentIncrease(BigInteger by, BigInteger to) {
                assertTrue(by.equals(Utils.CENT) && to.equals(Utils.CENT.shiftLeft(1)));
                server4PaymentFuture.set(null);
            }
        });

        PaymentChannelClient client4 = new PaymentChannelClient(wallet, myKey, Utils.COIN, Sha256Hash.create(new byte[] {}),
                new PaymentChannelClient.ClientConnection() {
                    @Override public void sendToServer(Protos.TwoWayChannelMessage msg) { server4.receiveMessage(msg); }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        assertEquals(CloseReason.CLIENT_REQUESTED_CLOSE, reason);
                        client4CloseFuture.set(null);
                    }

                    @Override
                    public void channelOpen() {
                        client4OpenFuture.set(null);
                    }
                });
        sendClient = new PaymentChannelClientReceiverImpl(client4);
        server4.connectionOpen();
        client4.connectionOpen();

        assertTrue(client4OpenFuture.isDone());

        client4.incrementPayment(Utils.CENT);
        assertTrue(server4PaymentFuture.isDone());

        // Now open up a new client with the same id and make sure it doesnt attempt to reopen the channel
        final SettableFuture<Void> client5OpenFuture = SettableFuture.create();
        final SettableFuture<Void> client5CloseFuture = SettableFuture.create();
        final SettableFuture<Void> server5PaymentFuture = SettableFuture.create();
        final SettableFuture<Sha256Hash> server5ContractHashFuture = SettableFuture.create();
        final PaymentChannelServer server5 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN, new PaymentChannelServer.ServerConnection() {
            @Override public void sendToClient(Protos.TwoWayChannelMessage msg) { sendClient.receiveMessage(msg); }

            @Override
            public void destroyConnection(CloseReason reason) {
                assertEquals(CloseReason.SERVER_REQUESTED_CLOSE, reason);
                sendClient.connectionClosed();
            }

            @Override
            public void channelOpen(Sha256Hash contractHash) {
                try {
                    assertFalse(server2ContractHashFuture.get().equals(contractHash));
                } catch (Exception e) { fail(); }
                server5ContractHashFuture.set(contractHash);
            }

            @Override
            public void paymentIncrease(BigInteger by, BigInteger to) {
                assertTrue(by.equals(Utils.CENT.shiftLeft(1)) && to.equals(Utils.CENT.shiftLeft(1)));
                server5PaymentFuture.set(null);
            }
        });
        PaymentChannelClient client5 = new PaymentChannelClient(wallet, myKey, Utils.COIN, Sha256Hash.create(new byte[] {}),
                new PaymentChannelClient.ClientConnection() {
                    @Override public void sendToServer(Protos.TwoWayChannelMessage msg) {
                        if(msg.getType() == Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                            assertFalse(msg.getClientVersion().hasPreviousChannelContractHash());
                        server5.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        assertEquals(CloseReason.SERVER_REQUESTED_CLOSE, reason);
                        client5CloseFuture.set(null);
                    }

                    @Override
                    public void channelOpen() {
                        client5OpenFuture.set(null);
                    }
                });
        sendClient = new PaymentChannelClientReceiverImpl(client5);
        server5.connectionOpen();
        client5.connectionOpen();

        multiSigFuture2.set(broadcastMultiSig2.getValue());
        assertTrue(client5OpenFuture.isDone() && server5ContractHashFuture.isDone());
        assertEquals(broadcastMultiSig2.getValue().getHash(), server5ContractHashFuture.get());

        client5.incrementPayment(Utils.CENT.shiftLeft(1));
        assertTrue(server5PaymentFuture.isDone());

        assertEquals(2, clientStoredChannels.mapChannels.size());

        // Make sure the server won't allow the reopen either
        // Check that server-side will reject incorrectly formatted hashes
        final SettableFuture<Void> server6VersionSent = SettableFuture.create();
        final SettableFuture<Void> server6InitiateSent = SettableFuture.create();
        PaymentChannelServer server6 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        if (!server6VersionSent.isDone()) {
                            assertTrue(msg.getType() == Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION);
                            server6VersionSent.set(null);
                            return;
                        }
                        assertTrue(!server6InitiateSent.isDone() && msg.getType() == Protos.TwoWayChannelMessage.MessageType.INITIATE);
                        server6InitiateSent.set(null);
                    }
                    @Override public void destroyConnection(CloseReason reason) { fail(); }
                    @Override public void channelOpen(Sha256Hash contractHash) { fail(); }
                    @Override public void paymentIncrease(BigInteger by, BigInteger to) { fail(); }
                });
        server6.connectionOpen();
        server6.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setPreviousChannelContractHash(ByteString.copyFrom(broadcastMultiSig2.getValue().getHash().getBytes()))
                        .setMajor(0).setMinor(42))
                .build());

        assertTrue(server6InitiateSent.isDone());

        // Now close connection 5
        server5.close();
        server5.connectionClosed();
        assertFalse(client5.connectionOpen);
        assertTrue(client5CloseFuture.isDone());

        // Now open a 4th channel with the same id and make sure it reopens the second (because the 1st is still open)
        final SettableFuture<Void> client7OpenFuture = SettableFuture.create();
        final SettableFuture<Void> client7CloseFuture = SettableFuture.create();
        final SettableFuture<Void> server7CloseFuture = SettableFuture.create();
        final SettableFuture<Void> server7PaymentFuture = SettableFuture.create();
        final PaymentChannelServer server7 = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN, new PaymentChannelServer.ServerConnection() {
            @Override public void sendToClient(Protos.TwoWayChannelMessage msg) { sendClient.receiveMessage(msg); }

            @Override
            public void destroyConnection(CloseReason reason) {
                assertEquals(CloseReason.CLIENT_REQUESTED_CLOSE, reason);
                server7CloseFuture.set(null);
            }

            @Override
            public void channelOpen(Sha256Hash contractHash) {
                try {
                    assertEquals(server5ContractHashFuture.get(), contractHash);
                } catch (Exception e) { fail(); }
            }

            @Override
            public void paymentIncrease(BigInteger by, BigInteger to) {
                assertTrue(by.equals(Utils.CENT.shiftLeft(1)) && to.equals(Utils.CENT.shiftLeft(2)));
                server7PaymentFuture.set(null);
            }
        });

        PaymentChannelClient client7 = new PaymentChannelClient(wallet, myKey, Utils.COIN, Sha256Hash.create(new byte[] {}),
                new PaymentChannelClient.ClientConnection() {
                    @Override public void sendToServer(Protos.TwoWayChannelMessage msg) { server7.receiveMessage(msg); }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        assertEquals(CloseReason.CLIENT_REQUESTED_CLOSE, reason);
                        client7CloseFuture.set(null);
                    }

                    @Override
                    public void channelOpen() {
                        client7OpenFuture.set(null);
                    }
                });
        sendClient = new PaymentChannelClientReceiverImpl(client7);
        server7.connectionOpen();
        client7.connectionOpen();

        assertTrue(client7OpenFuture.isDone());

        client7.incrementPayment(Utils.CENT.shiftLeft(1));
        assertTrue(server7PaymentFuture.isDone());

        assertEquals(2, clientStoredChannels.mapChannels.size());

        client7.close(); // Client-side close to broadcast close tx
        assertTrue(client7CloseFuture.isDone() && server7CloseFuture.isDone());
        client7.connectionClosed();
        server7.connectionClosed();
        assertFalse(client7.connectionOpen);

        assertFalse(clientStoredChannels.getChannel(Sha256Hash.create(new byte[]{}), broadcastMultiSig2.getValue().getHash()).active);
        assertTrue(clientStoredChannels.getChannel(Sha256Hash.create(new byte[]{}), broadcastMultiSig.getValue().getHash()).active);

        // Now, finally, close 4
        sendClient = new PaymentChannelClientReceiverImpl(client4);
        client4.close(); // Client-side close to broadcast close tx
        assertTrue(client4CloseFuture.isDone() && server4CloseFuture.isDone());
        client4.connectionClosed();
        server4.connectionClosed();
        assertFalse(client4.connectionOpen);

        assertFalse(clientStoredChannels.getChannel(Sha256Hash.create(new byte[]{}), broadcastMultiSig2.getValue().getHash()).active);
        assertFalse(clientStoredChannels.getChannel(Sha256Hash.create(new byte[]{}), broadcastMultiSig.getValue().getHash()).active);

        // Now roll the mock clock and recreate the client object so that it removes the channels
        Utils.rollMockClock(60 * 60 * 24 + 60*5); // Client announces refund 5 minutes after expire time
        final AtomicInteger broadcastCount = new AtomicInteger();
        StoredPaymentChannelClientStates newClientStates = new StoredPaymentChannelClientStates(new TransactionBroadcaster() {
            @Override
            public ListenableFuture<Transaction> broadcastTransaction(Transaction tx) {
                broadcastCount.incrementAndGet();
                return null;
            }
        }, wallet);
        newClientStates.deserializeWalletExtension(wallet, clientStoredChannels.serializeWalletExtension());

        while (broadcastCount.get() < 4)
            Thread.sleep(100);

        assertTrue(newClientStates.mapChannels.isEmpty());

        StoredPaymentChannelServerStates serverStoredChannels = (StoredPaymentChannelServerStates)serverWallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
        assertTrue(serverStoredChannels.mapChannels.isEmpty());

        control.verify();
    }

    @Test
    public void testChannelExpire() throws Exception {
        // Test that channels get properly closed when they expire

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        final PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        // We'll broadcast two txns: multisig contract and close transaction.
        SettableFuture<Transaction> multiSigFuture = SettableFuture.create();
        SettableFuture<Transaction> paymentFuture = SettableFuture.create();
        SettableFuture<Transaction> clientMultisigFuture = SettableFuture.create();
        SettableFuture<Transaction> refundFuture = SettableFuture.create();

        Capture<Transaction> broadcastMultiSig = new Capture<Transaction>();
        Capture<Transaction> broadcastPayment = new Capture<Transaction>();
        Capture<Transaction> broadcastClientMultisig = new Capture<Transaction>();
        Capture<Transaction> broadcastRefund = new Capture<Transaction>();

        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig))).andReturn(multiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastPayment))).andReturn(paymentFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastClientMultisig))).andReturn(clientMultisigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastRefund))).andReturn(refundFuture);
        control.replay();

        // Use a mock clock
        Utils.rollMockClock(0);

        final SettableFuture<Void> serverSecondPaymentProcessedFuture = SettableFuture.create();
        final SettableFuture<Void> serverCloseFuture = SettableFuture.create();
        final SettableFuture<Sha256Hash> contractHashFuture = SettableFuture.create();
        final PaymentChannelServer server = new PaymentChannelServer(mockPeerGroup, serverWallet, Utils.COIN,
                new PaymentChannelServer.ServerConnection() {
                    @Override
                    public void sendToClient(Protos.TwoWayChannelMessage msg) {
                        sendClient.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        serverCloseFuture.set(null);
                        sendClient.connectionClosed();
                    }

                    @Override
                    public void channelOpen(Sha256Hash contractHash) {
                        contractHashFuture.set(contractHash);
                    }

                    @Override
                    public void paymentIncrease(BigInteger by, BigInteger to) {
                        if (to.equals(Utils.CENT.shiftLeft(1)))
                            serverSecondPaymentProcessedFuture.set(null);
                    }
                });

        final SettableFuture<Void> clientChannelOpenFuture = SettableFuture.create();
        PaymentChannelClient clientConnection = new PaymentChannelClient(wallet, myKey, Utils.COIN, Sha256Hash.create(new byte[] {}),
                new PaymentChannelClient.ClientConnection() {
                    @Override
                    public void sendToServer(Protos.TwoWayChannelMessage msg) {
                        server.receiveMessage(msg);
                    }

                    @Override
                    public void destroyConnection(CloseReason reason) {
                        assertEquals(CloseReason.SERVER_REQUESTED_CLOSE, reason);
                    }

                    @Override
                    public void channelOpen() {
                        clientChannelOpenFuture.set(null);
                    }
                });
        sendClient = new PaymentChannelClientReceiverImpl(clientConnection);
        server.connectionOpen();
        clientConnection.connectionOpen(); // Recurses until channel is open

        multiSigFuture.set(broadcastMultiSig.getValue());
        assertEquals(contractHashFuture.get(), broadcastMultiSig.getValue().getHash());
        assertTrue(clientChannelOpenFuture.isDone());

        clientConnection.incrementPayment(Utils.CENT);
        clientConnection.incrementPayment(Utils.CENT);
        assertTrue(serverSecondPaymentProcessedFuture.isDone());

        StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)serverWallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
        StoredServerChannel storedServerChannel = channels.getChannel(broadcastMultiSig.getValue().getHash());
        PaymentChannelServerState serverState;
        synchronized (storedServerChannel) {
            serverState = storedServerChannel.getState(serverWallet, mockPeerGroup);
        }
        assertNotNull(serverState);

        server.close(); // Does not close channels themselves
        assertTrue(serverCloseFuture.isDone());
        server.connectionClosed();
        assertNull(storedServerChannel.connectedHandler);
        assertFalse(clientConnection.connectionOpen);

        // Now make the channel expire (in the server's eyes)
        Utils.rollMockClock(60 * 60 * 22 + 60); // Server gives 60 seconds of extra time in the lock time calculation so
        // that client can have their clock off a bit, and then announces payment
        // 2 hours before the expire time

        // And make sure the server broadcasts the payment transaction
        StoredPaymentChannelServerStates newManager = new StoredPaymentChannelServerStates(serverWallet, mockPeerGroup);
        newManager.deserializeWalletExtension(serverWallet, channels.serializeWalletExtension());

        while (!broadcastPayment.hasCaptured())
            Thread.sleep(100);
        paymentFuture.set(broadcastPayment.getValue());
        assertEquals(Utils.COIN.subtract(Utils.CENT.shiftLeft(1)), broadcastPayment.getValue().getOutput(0).getValue());

        // Now do the same with the client side
        StoredPaymentChannelClientStates clientChannels = (StoredPaymentChannelClientStates)wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        clientChannels.channelTimeoutHandler.cancel();
        StoredClientChannel storedClientChannel = clientChannels.getChannel(Sha256Hash.create(new byte[]{}), broadcastMultiSig.getValue().getHash());
        assertFalse(storedClientChannel.active);

        Utils.rollMockClock(60 * 60 * 2 + 60*4); // Client announces refund 5 minutes after expire time
        StoredPaymentChannelClientStates newClientStates = new StoredPaymentChannelClientStates(new TransactionBroadcaster() {
            @Override
            public ListenableFuture<Transaction> broadcastTransaction(Transaction tx) {
                return mockPeerGroup.broadcastTransaction(tx);
            }
        }, wallet);
        newClientStates.deserializeWalletExtension(wallet, clientChannels.serializeWalletExtension());
        while (!broadcastRefund.hasCaptured())
            Thread.sleep(100);
        clientMultisigFuture.set(broadcastClientMultisig.getValue());
        refundFuture.set(broadcastRefund.getValue());

        assertEquals(broadcastMultiSig.getValue().getHash(), broadcastClientMultisig.getValue().getHash());
        assertEquals(1, broadcastRefund.getValue().getOutputs().size());
        assertTrue(broadcastRefund.getValue().isTimeLocked());
        assertEquals(0, newClientStates.mapChannels.size());

        control.verify();
    }

    @Test
    public void testClientUnknownVersion() throws Exception {
        // Tests client rejects unknown version
        final SettableFuture<Void> serverReceivedError = SettableFuture.create();

        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Nullable
            @Override
            public ProtobufParser<Protos.TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(
                        new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                            @Override
                            public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> parser, Protos.TwoWayChannelMessage msg) {
                                if (msg.getType() != Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION &&
                                        msg.getType() != Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    fail.set(true);

                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR &&
                                        (!msg.hasError() || msg.getError().getCode() != Protos.Error.ErrorCode.NO_ACCEPTABLE_VERSION))
                                    fail.set(true);
                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    serverReceivedError.set(null);
                                else
                                    parser.write(Protos.TwoWayChannelMessage.newBuilder()
                                            .setServerVersion(Protos.ServerVersion.newBuilder().setMajor(2))
                                            .setType(Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION).build());
                            }

                            @Override public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) { }
                            @Override public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) { }
                        }, Protos.TwoWayChannelMessage.getDefaultInstance(), Short.MAX_VALUE, 1000);
            }
        });
        server.start(new InetSocketAddress("localhost", 4243));

        PaymentChannelClientConnection clientConnection = new PaymentChannelClientConnection(new InetSocketAddress("localhost", 4243), 1, wallet, myKey, Utils.COIN, "");
        try {
            clientConnection.getChannelOpenFuture().get();
            fail();
        } catch (ExecutionException e) {
            assertEquals(CloseReason.NO_ACCEPTABLE_VERSION, ((PaymentChannelCloseException)e.getCause()).getCloseReason());
        }
        serverReceivedError.get();

        // Double-check that we cant do anything that requires an open channel
        try {
            clientConnection.incrementPayment(BigInteger.ONE);
        } catch (IllegalStateException e) { }

        server.stop();
    }

    @Test
    public void testClientTimeWindowTooLarge() throws Exception {
        // Tests that clients reject too large time windows
        final SettableFuture<Void> serverReceivedError = SettableFuture.create();

        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Nullable
            @Override
            public ProtobufParser<Protos.TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(
                        new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                            @Override
                            public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> parser, Protos.TwoWayChannelMessage msg) {
                                if (msg.getType() != Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION &&
                                        msg.getType() != Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    fail.set(true);

                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR &&
                                        (!msg.hasError() || msg.getError().getCode() != Protos.Error.ErrorCode.TIME_WINDOW_TOO_LARGE))
                                    fail.set(true);
                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    serverReceivedError.set(null);

                                parser.write(Protos.TwoWayChannelMessage.newBuilder()
                                        .setServerVersion(Protos.ServerVersion.newBuilder().setMajor(0))
                                        .setType(Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION).build());
                                parser.write(Protos.TwoWayChannelMessage.newBuilder()
                                        .setInitiate(Protos.Initiate.newBuilder().setExpireTimeSecs(Utils.now().getTime() / 1000 + 60 * 60 * 48)
                                                .setMinAcceptedChannelSize(100)
                                                .setMultisigKey(ByteString.copyFrom(new ECKey().getPubKey())))
                                        .setType(Protos.TwoWayChannelMessage.MessageType.INITIATE).build());
                            }

                            @Override public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) { }
                            @Override public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) { }
                        }, Protos.TwoWayChannelMessage.getDefaultInstance(), Short.MAX_VALUE, 1000);
            }
        });
        server.start(new InetSocketAddress("localhost", 4243));

        PaymentChannelClientConnection clientConnection = new PaymentChannelClientConnection(new InetSocketAddress("localhost", 4243), 1, wallet, myKey, Utils.COIN, "");
        try {
            clientConnection.getChannelOpenFuture().get();
            fail();
        } catch (ExecutionException e) {
            assertEquals(CloseReason.TIME_WINDOW_TOO_LARGE, ((PaymentChannelCloseException)e.getCause()).getCloseReason());
        }
        serverReceivedError.get();

        server.stop();
    }

    @Test
    public void testClientValueTooLarge() throws Exception {
        // Tests that clients reject too high minimum channel value
        final SettableFuture<Void> serverReceivedError = SettableFuture.create();

        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Nullable
            @Override
            public ProtobufParser<Protos.TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(
                        new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                            @Override
                            public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> parser, Protos.TwoWayChannelMessage msg) {
                                if (msg.getType() != Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION &&
                                        msg.getType() != Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    fail.set(true);

                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR &&
                                        (!msg.hasError() || msg.getError().getCode() != Protos.Error.ErrorCode.CHANNEL_VALUE_TOO_LARGE))
                                    fail.set(true);
                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    serverReceivedError.set(null);

                                parser.write(Protos.TwoWayChannelMessage.newBuilder()
                                        .setServerVersion(Protos.ServerVersion.newBuilder().setMajor(0))
                                        .setType(Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION).build());
                                parser.write(Protos.TwoWayChannelMessage.newBuilder()
                                        .setInitiate(Protos.Initiate.newBuilder().setExpireTimeSecs(Utils.now().getTime() / 1000)
                                                .setMinAcceptedChannelSize(Utils.COIN.add(BigInteger.ONE).longValue())
                                                .setMultisigKey(ByteString.copyFrom(new ECKey().getPubKey())))
                                        .setType(Protos.TwoWayChannelMessage.MessageType.INITIATE).build());
                            }
                            @Override public void connectionOpen(ProtobufParser<Protos.TwoWayChannelMessage> handler) { }
                            @Override public void connectionClosed(ProtobufParser<Protos.TwoWayChannelMessage> handler) { }
                        }, Protos.TwoWayChannelMessage.getDefaultInstance(), Short.MAX_VALUE, 1000);
            }
        });
        server.start(new InetSocketAddress("localhost", 4243));

        PaymentChannelClientConnection clientConnection = new PaymentChannelClientConnection(new InetSocketAddress("localhost", 4243), 1, wallet, myKey, Utils.COIN, "");
        try {
            clientConnection.getChannelOpenFuture().get();
            fail();
        } catch (ExecutionException e) {
            assertEquals(CloseReason.SERVER_REQUESTED_TOO_MUCH_VALUE, ((PaymentChannelCloseException) e.getCause()).getCloseReason());
        }
        serverReceivedError.get();

        server.stop();
    }

    @Test
    public void testClientResumeNothing() throws Exception {
        // Tests that clients rejects channels where the server attempts to resume a channel when the client didn't
        // request one be resumed
        final SettableFuture<Void> serverReceivedError = SettableFuture.create();

        ProtobufServer server = new ProtobufServer(new ProtobufParserFactory() {
            @Nullable
            @Override
            public ProtobufParser<Protos.TwoWayChannelMessage> getNewParser(InetAddress inetAddress, int port) {
                return new ProtobufParser<Protos.TwoWayChannelMessage>(
                        new ProtobufParser.Listener<Protos.TwoWayChannelMessage>() {
                            @Override
                            public void messageReceived(ProtobufParser<Protos.TwoWayChannelMessage> parser, Protos.TwoWayChannelMessage msg) {
                                if (msg.getType() != Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION &&
                                        msg.getType() != Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    fail.set(true);

                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR &&
                                        (!msg.hasError() || msg.getError().getCode() != Protos.Error.ErrorCode.SYNTAX_ERROR))
                                    fail.set(true);
                                if (msg.getType() == Protos.TwoWayChannelMessage.MessageType.ERROR)
                                    serverReceivedError.set(null);

                                parser.write(Protos.TwoWayChannelMessage.newBuilder()
                                        .setServerVersion(Protos.ServerVersion.newBuilder().setMajor(0))
                                        .setType(Protos.TwoWayChannelMessage.MessageType.SERVER_VERSION).build());
                                parser.write(Protos.TwoWayChannelMessage.newBuilder()
                                        .setType(Protos.TwoWayChannelMessage.MessageType.CHANNEL_OPEN).build());
                            }

                            @Override public void connectionOpen(ProtobufParser handler) { }
                            @Override public void connectionClosed(ProtobufParser handler) { }
                        }, Protos.TwoWayChannelMessage.getDefaultInstance(), Short.MAX_VALUE, 1000);
            }
        });
        server.start(new InetSocketAddress("localhost", 4243));

        InetSocketAddress client = new InetSocketAddress("localhost", 4243);
        PaymentChannelClientConnection clientConnection = new PaymentChannelClientConnection(client, 1, wallet, myKey, Utils.COIN, "");
        try {
            clientConnection.getChannelOpenFuture().get();
            fail();
        } catch (ExecutionException e) {
            assertEquals(CloseReason.REMOTE_SENT_INVALID_MESSAGE, ((PaymentChannelCloseException) e.getCause()).getCloseReason());
        }
        serverReceivedError.get();

        server.stop();
    }

    private Protos.TwoWayChannelMessage nextMsg;
    @Test
    public void testClientRandomMessage() throws Exception {
        // Tests that clients rejects messages it has no idea how to handle
        final SettableFuture<Void> clientReceivedError = SettableFuture.create();

        PaymentChannelClient clientConnection = new PaymentChannelClient(wallet, myKey, Utils.COIN, Sha256Hash.create(new byte[] {}), new PaymentChannelClient.ClientConnection() {
            @Override
            public void sendToServer(Protos.TwoWayChannelMessage msg) {
                nextMsg = msg;
            }

            @Override
            public void destroyConnection(CloseReason reason) {
                clientReceivedError.set(null);
            }

            @Override
            public void channelOpen() {
                fail.set(true);
            }
        });
        clientConnection.connectionOpen();
        assertEquals(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION, nextMsg.getType());

        clientConnection.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(Protos.TwoWayChannelMessage.MessageType.CLIENT_VERSION).build());
        assertEquals(Protos.TwoWayChannelMessage.MessageType.ERROR, nextMsg.getType());
        assertTrue(nextMsg.hasError());
        assertEquals(Protos.Error.ErrorCode.SYNTAX_ERROR, nextMsg.getError().getCode());

        clientReceivedError.get();
    }
}
