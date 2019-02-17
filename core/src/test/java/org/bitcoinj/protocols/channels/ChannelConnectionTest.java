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

import org.bitcoinj.core.*;
import org.bitcoinj.protocols.channels.PaymentChannelClient.VersionSelector;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.testing.TestWithWallet;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletExtension;
import org.bitcoinj.wallet.WalletFiles;
import org.bitcoinj.wallet.WalletProtobufSerializer;

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.bitcoinj.core.Coin.*;
import static org.bitcoinj.protocols.channels.PaymentChannelClient.VersionSelector.*;
import static org.bitcoinj.protocols.channels.PaymentChannelCloseException.CloseReason;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoin.paymentchannel.Protos.TwoWayChannelMessage.MessageType;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class ChannelConnectionTest extends TestWithWallet {
    private static final int CLIENT_MAJOR_VERSION = 1;
    private Wallet serverWallet;
    private AtomicBoolean fail;
    private BlockingQueue<Transaction> broadcasts;
    private TransactionBroadcaster mockBroadcaster;
    private Semaphore broadcastTxPause;

    private static final TransactionBroadcaster failBroadcaster = new TransactionBroadcaster() {
        @Override
        public TransactionBroadcast broadcastTransaction(Transaction tx) {
            fail();
            return null;
        }
    };

    /**
     * We use parameterized tests to run the channel connection tests with each
     * version of the channel.
     */
    @Parameterized.Parameters(name = "{index}: ChannelConnectionTest({0})")
    public static Collection<PaymentChannelClient.DefaultClientChannelProperties> data() {
        return Arrays.asList(
                new PaymentChannelClient.DefaultClientChannelProperties() {
                    @Override
                    public VersionSelector versionSelector() { return VERSION_1;}
                },
                new PaymentChannelClient.DefaultClientChannelProperties() {
                    @Override
                    public VersionSelector versionSelector() { return VERSION_2_ALLOW_1;}
                });
    }

    @Parameterized.Parameter
    public IPaymentChannelClient.ClientChannelProperties clientChannelProperties;

    /**
     * Returns {@code true} if we are using a protocol version that requires the exchange of refunds.
     */
    private boolean useRefunds() {
        return clientChannelProperties.versionSelector() == VERSION_1;
    }

    /**
     * Returns {@code true} if the contract being used is a multisig contract
     * @return
     */
    private boolean isMultiSigContract() {
        return clientChannelProperties.versionSelector() == VERSION_1;
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        Utils.setMockClock(); // Use mock clock
        Context.propagate(new Context(UNITTEST, 3, Coin.ZERO, false)); // Shorter event horizon for unit tests.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        wallet.addExtension(new StoredPaymentChannelClientStates(wallet, failBroadcaster));
        serverWallet = new Wallet(UNITTEST);
        serverWallet.addExtension(new StoredPaymentChannelServerStates(serverWallet, failBroadcaster));
        serverWallet.freshReceiveKey();
        // Use an atomic boolean to indicate failure because fail()/assert*() don't work in network threads
        fail = new AtomicBoolean(false);

        // Set up a way to monitor broadcast transactions. When you expect a broadcast, you must release a permit
        // to the broadcastTxPause semaphore so state can be queried in between.
        broadcasts = new LinkedBlockingQueue<>();
        broadcastTxPause = new Semaphore(0);
        mockBroadcaster = new TransactionBroadcaster() {
            @Override
            public TransactionBroadcast broadcastTransaction(Transaction tx) {
                broadcastTxPause.acquireUninterruptibly();
                SettableFuture<Transaction> future = SettableFuture.create();
                future.set(tx);
                broadcasts.add(tx);
                return TransactionBroadcast.createMockBroadcast(tx, future);
            }
        };

        // Because there are no separate threads in the tests here (we call back into client/server in server/client
        // handlers), we have lots of lock cycles. A normal user shouldn't have this issue as they are probably not both
        // client+server running in the same thread.
        Threading.warnOnLockCycles();

        ECKey.FAKE_SIGNATURES = true;
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        ECKey.FAKE_SIGNATURES = false;
    }

    @After
    public void checkFail() {
        assertFalse(fail.get());
        Threading.throwOnLockCycles();
    }

    @Test
    public void testSimpleChannel() throws Exception {
        exectuteSimpleChannelTest(null);
    }

    @Test
    public void testEncryptedClientWallet() throws Exception {
        // Encrypt the client wallet
        String mySecretPw = "MySecret";
        wallet.encrypt(mySecretPw);

        KeyParameter userKeySetup = wallet.getKeyCrypter().deriveKey(mySecretPw);
        exectuteSimpleChannelTest(userKeySetup);
    }

    private void exectuteSimpleChannelTest(KeyParameter userKeySetup) throws Exception {
        // Test with network code and without any issues. We'll broadcast two txns: multisig contract and settle transaction.
        final SettableFuture<ListenableFuture<PaymentChannelV1ServerState>> serverCloseFuture = SettableFuture.create();
        final SettableFuture<Sha256Hash> channelOpenFuture = SettableFuture.create();
        final BlockingQueue<ChannelTestUtils.UpdatePair> q = new LinkedBlockingQueue<>();
        final PaymentChannelServerListener server = new PaymentChannelServerListener(mockBroadcaster, serverWallet, 30, COIN,
                new PaymentChannelServerListener.HandlerFactory() {
                    @Nullable
                    @Override
                    public ServerConnectionEventHandler onNewConnection(SocketAddress clientAddress) {
                        return new ServerConnectionEventHandler() {
                            @Override
                            public void channelOpen(Sha256Hash channelId) {
                                channelOpenFuture.set(channelId);
                            }

                            @Override
                            public ListenableFuture<ByteString> paymentIncrease(Coin by, Coin to, ByteString info) {
                                q.add(new ChannelTestUtils.UpdatePair(to, info));
                                return Futures.immediateFuture(info);
                            }

                            @Override
                            public void channelClosed(CloseReason reason) {
                                serverCloseFuture.set(null);
                            }
                        };
                    }
                });
        server.bindAndStart(4243);

        PaymentChannelClientConnection client = new PaymentChannelClientConnection(
                new InetSocketAddress("localhost", 4243), 30, wallet, myKey, COIN, "", userKeySetup, clientChannelProperties);

        // Wait for the multi-sig tx to be transmitted.
        broadcastTxPause.release();
        Transaction broadcastMultiSig = broadcasts.take();
        // Wait for the channel to finish opening.
        client.getChannelOpenFuture().get();
        assertEquals(broadcastMultiSig.getTxId(), channelOpenFuture.get());
        assertEquals(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE, client.state().getValueSpent());

        // Set up an autosave listener to make sure the server is saving the wallet after each payment increase.
        final CountDownLatch latch = new CountDownLatch(3);  // Expect 3 calls.
        File tempFile = File.createTempFile("channel_connection_test", ".wallet");
        tempFile.deleteOnExit();
        serverWallet.autosaveToFile(tempFile, 0, TimeUnit.SECONDS, new WalletFiles.Listener() {
            @Override
            public void onBeforeAutoSave(File tempFile) {
                latch.countDown();
            }

            @Override
            public void onAfterAutoSave(File newlySavedFile) {
            }
        });

        Thread.sleep(1250); // No timeouts once the channel is open
        Coin amount = client.state().getValueSpent();
        q.take().assertPair(amount, null);
        for (String info : new String[] {null, "one", "two"} ) {
            final ByteString bytes = (info==null) ? null :ByteString.copyFromUtf8(info);
            final PaymentIncrementAck ack = client.incrementPayment(CENT, bytes, userKeySetup).get();
            if (info != null) {
                final ByteString ackInfo = ack.getInfo();
                assertNotNull("Ack info is null", ackInfo);
                assertEquals("Ack info differs ", info, ackInfo.toStringUtf8());
            }
            amount = amount.add(CENT);
            q.take().assertPair(amount, bytes);
        }
        latch.await();

        StoredPaymentChannelServerStates channels = (StoredPaymentChannelServerStates)serverWallet.getExtensions().get(StoredPaymentChannelServerStates.EXTENSION_ID);
        StoredServerChannel storedServerChannel = channels.getChannel(broadcastMultiSig.getTxId());
        PaymentChannelServerState serverState = storedServerChannel.getOrCreateState(serverWallet, mockBroadcaster);

        // Check that you can call settle multiple times with no exceptions.
        client.settle();
        client.settle();

        broadcastTxPause.release();
        Transaction settleTx = broadcasts.take();
        assertTrue(serverState.getState() == PaymentChannelServerState.State.CLOSING ||
                serverState.getState() == PaymentChannelServerState.State.CLOSED);
        // Wait for the server thread to catch up with closing
        serverState.close().get();
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
        assertEquals(amount, serverState.getBestValueToMe());
        assertEquals(ZERO, serverState.getFeePaid());
        assertTrue(channels.mapChannels.isEmpty());

        // Send the settle TX to the client wallet.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, settleTx);
        assertTrue(client.state().getState() == PaymentChannelClientState.State.CLOSED);

        server.close();
        server.close();

        // Now confirm the settle TX and see if the channel deletes itself from the wallet.
        assertEquals(1, StoredPaymentChannelClientStates.getFromWallet(wallet).mapChannels.size());
        wallet.notifyNewBestBlock(createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).storedBlock);
        assertEquals(1, StoredPaymentChannelClientStates.getFromWallet(wallet).mapChannels.size());
        wallet.notifyNewBestBlock(createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS + 1).storedBlock);
        assertEquals(0, StoredPaymentChannelClientStates.getFromWallet(wallet).mapChannels.size());
    }

    @Test
    public void testServerErrorHandling_badTransaction() throws Exception {
        if (!useRefunds()) {
            // This test only applies to versions with refunds
            return;
        }
        // Gives the server crap and checks proper error responses are sent.
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        PaymentChannelServer server = pair.server;
        server.connectionOpen();
        client.connectionOpen();

        // Make sure we get back a BAD_TRANSACTION if we send a bogus refund transaction.
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.INITIATE));
        Protos.TwoWayChannelMessage msg = pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_REFUND);
        server.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(MessageType.PROVIDE_REFUND)
                .setProvideRefund(
                        Protos.ProvideRefund.newBuilder(msg.getProvideRefund())
                                .setMultisigKey(ByteString.EMPTY)
                                .setTx(ByteString.EMPTY)
                ).build());
        final Protos.TwoWayChannelMessage errorMsg = pair.serverRecorder.checkNextMsg(MessageType.ERROR);
        assertEquals(Protos.Error.ErrorCode.BAD_TRANSACTION, errorMsg.getError().getCode());
    }

    @Test
    public void testServerErrorHandling_killSocketOnClose() throws Exception {
        // Make sure the server closes the socket on CLOSE
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        PaymentChannelServer server = pair.server;
        server.connectionOpen();
        client.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.settle();
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.INITIATE));
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLOSE));
        assertEquals(CloseReason.CLIENT_REQUESTED_CLOSE, pair.serverRecorder.q.take());


    }

    @Test
    public void testServerErrorHandling_killSocketOnError() throws Exception {
        // Make sure the server closes the socket on ERROR
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        PaymentChannelServer server = pair.server;
        server.connectionOpen();
        client.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.INITIATE));
        server.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(MessageType.ERROR)
                .setError(Protos.Error.newBuilder().setCode(Protos.Error.ErrorCode.TIMEOUT))
                .build());
        assertEquals(CloseReason.REMOTE_SENT_ERROR, pair.serverRecorder.q.take());
    }

    @Test
    public void testClientErrorHandlingIncreasePaymentError() throws Exception {
        // Tests various aspects of channel resuming.
        Utils.setMockClock();

        final Sha256Hash someServerId = Sha256Hash.of(new byte[]{});

        // Open up a normal channel.
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        pair.server.connectionOpen();
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
        PaymentChannelServer server = pair.server;
        client.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        final Protos.TwoWayChannelMessage initiateMsg = pair.serverRecorder.checkNextMsg(MessageType.INITIATE);
        Coin minPayment = Coin.valueOf(initiateMsg.getInitiate().getMinPayment());
        client.receiveMessage(initiateMsg);
        if (useRefunds()) {
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_REFUND));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.RETURN_REFUND));
        }
        broadcastTxPause.release();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_CONTRACT));
        broadcasts.take();
        pair.serverRecorder.checkTotalPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN));
        Sha256Hash contractHash = (Sha256Hash) pair.serverRecorder.q.take();
        pair.clientRecorder.checkInitiated();
        assertNull(pair.serverRecorder.q.poll());
        assertNull(pair.clientRecorder.q.poll());
        assertEquals(minPayment, client.state().getValueSpent());

        // Send a bitcent.
        Coin amount = minPayment.add(CENT);
        ListenableFuture<PaymentIncrementAck> ackFuture = client.incrementPayment(CENT);
        // We never pass this message to the server
        // Instead we pretend the server didn't like our increase
        client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(MessageType.ERROR)
                .setError(Protos.Error.newBuilder().setCode(Protos.Error.ErrorCode.CHANNEL_VALUE_TOO_LARGE)) // some random error
                .build());

        // Now we need the client to actually close the future and report this error
        try {
            ackFuture.get(1L, TimeUnit.SECONDS);
            fail("This should not work");
        } catch (ExecutionException ee) {
            PaymentChannelCloseException ce = (PaymentChannelCloseException) ee.getCause();
            assertEquals(CloseReason.REMOTE_SENT_ERROR, ce.getCloseReason());
        } catch (TimeoutException e) {
            fail("Should not time out");
        }
    }

    @Test
    public void testChannelResume() throws Exception {
        // Tests various aspects of channel resuming.
        Utils.setMockClock();

        final Sha256Hash someServerId = Sha256Hash.of(new byte[]{});

        // Open up a normal channel.
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        pair.server.connectionOpen();
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
        PaymentChannelServer server = pair.server;
        client.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        final Protos.TwoWayChannelMessage initiateMsg = pair.serverRecorder.checkNextMsg(MessageType.INITIATE);
        Coin minPayment = Coin.valueOf(initiateMsg.getInitiate().getMinPayment());
        client.receiveMessage(initiateMsg);
        if (useRefunds()) {
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_REFUND));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.RETURN_REFUND));
        }
        broadcastTxPause.release();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_CONTRACT));
        broadcasts.take();
        pair.serverRecorder.checkTotalPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN));
        Sha256Hash contractHash = (Sha256Hash) pair.serverRecorder.q.take();
        pair.clientRecorder.checkInitiated();
        assertNull(pair.serverRecorder.q.poll());
        assertNull(pair.clientRecorder.q.poll());
        assertEquals(minPayment, client.state().getValueSpent());
        // Send a bitcent.
        Coin amount = minPayment.add(CENT);
        client.incrementPayment(CENT);
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.UPDATE_PAYMENT));
        assertEquals(amount, ((ChannelTestUtils.UpdatePair)pair.serverRecorder.q.take()).amount);
        server.close();
        server.connectionClosed();
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.PAYMENT_ACK));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CLOSE));
        client.connectionClosed();
        assertFalse(client.connectionOpen);

        // There is now an inactive open channel worth COIN-CENT + minPayment with id Sha256.create(new byte[] {})
        StoredPaymentChannelClientStates clientStoredChannels =
                (StoredPaymentChannelClientStates) wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);
        assertEquals(1, clientStoredChannels.mapChannels.size());
        assertFalse(clientStoredChannels.mapChannels.values().iterator().next().active);

        // Check that server-side won't attempt to reopen a nonexistent channel (it will tell the client to re-initiate
        // instead).
        pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        pair.server.connectionOpen();
        pair.server.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
            .setType(MessageType.CLIENT_VERSION)
            .setClientVersion(Protos.ClientVersion.newBuilder()
                .setPreviousChannelContractHash(ByteString.copyFrom(Sha256Hash.hash(new byte[] { 0x03 })))
                .setMajor(CLIENT_MAJOR_VERSION).setMinor(42))
            .build());
        pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION);
        pair.serverRecorder.checkNextMsg(MessageType.INITIATE);

        // Now reopen/resume the channel after round-tripping the wallets.
        wallet = roundTripClientWallet(wallet);
        serverWallet = roundTripServerWallet(serverWallet);
        clientStoredChannels =
                (StoredPaymentChannelClientStates) wallet.getExtensions().get(StoredPaymentChannelClientStates.EXTENSION_ID);

        pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
        server = pair.server;
        client.connectionOpen();
        server.connectionOpen();
        // Check the contract hash is sent on the wire correctly.
        final Protos.TwoWayChannelMessage clientVersionMsg = pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION);
        assertTrue(clientVersionMsg.getClientVersion().hasPreviousChannelContractHash());
        assertEquals(contractHash, Sha256Hash.wrap(clientVersionMsg.getClientVersion().getPreviousChannelContractHash().toByteArray()));
        server.receiveMessage(clientVersionMsg);
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN));
        assertEquals(contractHash, pair.serverRecorder.q.take());
        pair.clientRecorder.checkOpened();
        assertNull(pair.serverRecorder.q.poll());
        assertNull(pair.clientRecorder.q.poll());
        // Send another bitcent and check 2 were received in total.
        client.incrementPayment(CENT);
        amount = amount.add(CENT);
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.UPDATE_PAYMENT));
        pair.serverRecorder.checkTotalPayment(amount);
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.PAYMENT_ACK));

        PaymentChannelClient openClient = client;
        ChannelTestUtils.RecordingPair openPair = pair;

        // Now open up a new client with the same id and make sure the server disconnects the previous client.
        pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
        server = pair.server;
        client.connectionOpen();
        server.connectionOpen();
        // Check that no prev contract hash is sent on the wire the client notices it's already in use by another
        // client attached to the same wallet and refuses to resume.
        {
            Protos.TwoWayChannelMessage msg = pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION);
            assertFalse(msg.getClientVersion().hasPreviousChannelContractHash());
        }
        // Make sure the server allows two simultaneous opens. It will close the first and allow resumption of the second.
        pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
        server = pair.server;
        client.connectionOpen();
        server.connectionOpen();
        // Swap out the clients version message for a custom one that tries to resume ...
        pair.clientRecorder.getNextMsg();
        server.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(MessageType.CLIENT_VERSION)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setPreviousChannelContractHash(ByteString.copyFrom(contractHash.getBytes()))
                        .setMajor(CLIENT_MAJOR_VERSION).setMinor(42))
                .build());
        // We get the usual resume sequence.
        pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION);
        pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN);
        // Verify the previous one was closed.
        openPair.serverRecorder.checkNextMsg(MessageType.CLOSE);

        assertTrue(clientStoredChannels.getChannel(someServerId, contractHash).active);

        // And finally close the first channel too.
        openClient.connectionClosed();
        assertFalse(clientStoredChannels.getChannel(someServerId, contractHash).active);

        // Now roll the mock clock and recreate the client object so that it removes the channels and announces refunds.
        assertEquals(86640, clientStoredChannels.getSecondsUntilExpiry(someServerId));
        Utils.rollMockClock(60 * 60 * 24 + 60 * 5);   // Client announces refund 5 minutes after expire time
        StoredPaymentChannelClientStates newClientStates = new StoredPaymentChannelClientStates(wallet, mockBroadcaster);
        newClientStates.deserializeWalletExtension(wallet, clientStoredChannels.serializeWalletExtension());
        broadcastTxPause.release();
        if (isMultiSigContract()) {
            assertTrue(ScriptPattern.isSentToMultisig(broadcasts.take().getOutput(0).getScriptPubKey()));
        } else {
            assertTrue(ScriptPattern.isP2SH(broadcasts.take().getOutput(0).getScriptPubKey()));
        }
        broadcastTxPause.release();
        assertEquals(TransactionConfidence.Source.SELF, broadcasts.take().getConfidence().getSource());
        assertTrue(broadcasts.isEmpty());
        assertTrue(newClientStates.mapChannels.isEmpty());
        // Server also knows it's too late.
        StoredPaymentChannelServerStates serverStoredChannels = new StoredPaymentChannelServerStates(serverWallet, mockBroadcaster);
        Thread.sleep(2000);   // TODO: Fix this stupid hack.
        assertTrue(serverStoredChannels.mapChannels.isEmpty());
    }

    private static Wallet roundTripClientWallet(Wallet wallet) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        new WalletProtobufSerializer().writeWallet(wallet, bos);
        org.bitcoinj.wallet.Protos.Wallet proto = WalletProtobufSerializer.parseToProto(new ByteArrayInputStream(bos.toByteArray()));
        StoredPaymentChannelClientStates state = new StoredPaymentChannelClientStates(null, failBroadcaster);
        return new WalletProtobufSerializer().readWallet(wallet.getParams(), new WalletExtension[] { state }, proto);
    }

    private static Wallet roundTripServerWallet(Wallet wallet) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        new WalletProtobufSerializer().writeWallet(wallet, bos);
        StoredPaymentChannelServerStates state = new StoredPaymentChannelServerStates(null, failBroadcaster);
        org.bitcoinj.wallet.Protos.Wallet proto = WalletProtobufSerializer.parseToProto(new ByteArrayInputStream(bos.toByteArray()));
        return new WalletProtobufSerializer().readWallet(wallet.getParams(), new WalletExtension[] { state }, proto);
    }

    @Test
    public void testBadResumeHash() throws InterruptedException {
        // Check that server-side will reject incorrectly formatted hashes. If anything goes wrong with session resume,
        // then the server will start the opening of a new channel automatically, so we expect to see INITIATE here.
        ChannelTestUtils.RecordingPair srv =
                ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        srv.server.connectionOpen();
        srv.server.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(MessageType.CLIENT_VERSION)
                .setClientVersion(Protos.ClientVersion.newBuilder()
                        .setPreviousChannelContractHash(ByteString.copyFrom(new byte[]{0x00, 0x01}))
                        .setMajor(CLIENT_MAJOR_VERSION).setMinor(42))
                .build());

        srv.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION);
        srv.serverRecorder.checkNextMsg(MessageType.INITIATE);
        assertTrue(srv.serverRecorder.q.isEmpty());
    }

    @Test
    public void testClientUnknownVersion() throws Exception {
        // Tests client rejects unknown version
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION);
        client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setServerVersion(Protos.ServerVersion.newBuilder().setMajor(-1))
                .setType(MessageType.SERVER_VERSION).build());
        pair.clientRecorder.checkNextMsg(MessageType.ERROR);
        assertEquals(CloseReason.NO_ACCEPTABLE_VERSION, pair.clientRecorder.q.take());
        // Double-check that we cant do anything that requires an open channel
        try {
            client.incrementPayment(Coin.SATOSHI);
            fail();
        } catch (IllegalStateException e) { }
    }

    @Test
    public void testClientTimeWindowUnacceptable() throws Exception {
        // Tests that clients reject too large time windows
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster, 100);
        PaymentChannelServer server = pair.server;
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        server.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setInitiate(Protos.Initiate.newBuilder().setExpireTimeSecs(Utils.currentTimeSeconds() + 60 * 60 * 48)
                        .setMinAcceptedChannelSize(100)
                        .setMultisigKey(ByteString.copyFrom(new ECKey().getPubKey()))
                        .setMinPayment(Transaction.MIN_NONDUST_OUTPUT.value))
                .setType(MessageType.INITIATE).build());

        pair.clientRecorder.checkNextMsg(MessageType.ERROR);
        assertEquals(CloseReason.TIME_WINDOW_UNACCEPTABLE, pair.clientRecorder.q.take());
        // Double-check that we cant do anything that requires an open channel
        try {
            client.incrementPayment(Coin.SATOSHI);
            fail();
        } catch (IllegalStateException e) { }
    }

    @Test
    public void testValuesAreRespected() throws Exception {
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelServer server = pair.server;
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        server.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setInitiate(Protos.Initiate.newBuilder().setExpireTimeSecs(Utils.currentTimeSeconds())
                        .setMinAcceptedChannelSize(COIN.add(SATOSHI).value)
                        .setMultisigKey(ByteString.copyFrom(new ECKey().getPubKey()))
                        .setMinPayment(Transaction.MIN_NONDUST_OUTPUT.value))
                .setType(MessageType.INITIATE).build());
        pair.clientRecorder.checkNextMsg(MessageType.ERROR);
        assertEquals(CloseReason.SERVER_REQUESTED_TOO_MUCH_VALUE, pair.clientRecorder.q.take());
        // Double-check that we cant do anything that requires an open channel
        try {
            client.incrementPayment(Coin.SATOSHI);
            fail();
        } catch (IllegalStateException e) { }

        // Now check that if the server has a lower min size than what we are willing to spend, we do actually open
        // a channel of that size.
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN.multiply(10));

        pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        server = pair.server;
        final Coin myValue = COIN.multiply(10);
        client = new PaymentChannelClient(wallet, myKey, myValue, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        server.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setInitiate(Protos.Initiate.newBuilder().setExpireTimeSecs(Utils.currentTimeSeconds())
                        .setMinAcceptedChannelSize(COIN.add(SATOSHI).value)
                        .setMultisigKey(ByteString.copyFrom(new ECKey().getPubKey()))
                        .setMinPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.value))
                .setType(MessageType.INITIATE).build());
        if (useRefunds()) {
            final Protos.TwoWayChannelMessage provideRefund = pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_REFUND);
            Transaction refund = new Transaction(UNITTEST, provideRefund.getProvideRefund().getTx().toByteArray());
            assertEquals(myValue, refund.getOutput(0).getValue());
        } else {
            assertEquals(2, client.state().getMajorVersion());
            PaymentChannelV2ClientState state = (PaymentChannelV2ClientState) client.state();
            assertEquals(myValue, state.refundTx.getOutput(0).getValue());
        }
    }

    @Test
    public void testEmptyWallet() throws Exception {
        Wallet emptyWallet = new Wallet(UNITTEST);
        emptyWallet.freshReceiveKey();
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelServer server = pair.server;
        PaymentChannelClient client = new PaymentChannelClient(emptyWallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        server.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        try {
            client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                    .setInitiate(Protos.Initiate.newBuilder().setExpireTimeSecs(Utils.currentTimeSeconds())
                            .setMinAcceptedChannelSize(CENT.value)
                            .setMultisigKey(ByteString.copyFrom(new ECKey().getPubKey()))
                            .setMinPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.value))
                    .setType(MessageType.INITIATE).build());
            fail();
        } catch (InsufficientMoneyException expected) {
            // This should be thrown.
        }
    }

    @Test
    public void testClientRefusesNonCanonicalKey() throws Exception {
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelServer server = pair.server;
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        server.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        Protos.TwoWayChannelMessage.Builder initiateMsg = Protos.TwoWayChannelMessage.newBuilder(pair.serverRecorder.checkNextMsg(MessageType.INITIATE));
        ByteString brokenKey = initiateMsg.getInitiate().getMultisigKey();
        brokenKey = ByteString.copyFrom(Arrays.copyOf(brokenKey.toByteArray(), brokenKey.size() + 1));
        initiateMsg.getInitiateBuilder().setMultisigKey(brokenKey);
        client.receiveMessage(initiateMsg.build());
        pair.clientRecorder.checkNextMsg(MessageType.ERROR);
        assertEquals(CloseReason.REMOTE_SENT_INVALID_MESSAGE, pair.clientRecorder.q.take());
    }

    @Test
    public void testClientResumeNothing() throws Exception {
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelServer server = pair.server;
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        server.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(MessageType.CHANNEL_OPEN).build());
        pair.clientRecorder.checkNextMsg(MessageType.ERROR);
        assertEquals(CloseReason.REMOTE_SENT_INVALID_MESSAGE, pair.clientRecorder.q.take());
    }

    @Test
    public void testClientRandomMessage() throws Exception {
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, Sha256Hash.ZERO_HASH, null, clientChannelProperties, pair.clientRecorder);

        client.connectionOpen();
        pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION);
        // Send a CLIENT_VERSION back to the client - ?!?!!
        client.receiveMessage(Protos.TwoWayChannelMessage.newBuilder()
                .setType(MessageType.CLIENT_VERSION).build());
        Protos.TwoWayChannelMessage error = pair.clientRecorder.checkNextMsg(MessageType.ERROR);
        assertEquals(Protos.Error.ErrorCode.SYNTAX_ERROR, error.getError().getCode());
        assertEquals(CloseReason.REMOTE_SENT_INVALID_MESSAGE, pair.clientRecorder.q.take());
   }

    @Test
    public void testDontResumeEmptyChannels() throws Exception {
        // Check that if the client has an empty channel that's being kept around in case we need to broadcast the
        // refund, we don't accidentally try to resume it).

        // Open up a normal channel.
        Sha256Hash someServerId = Sha256Hash.ZERO_HASH;
        ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
        pair.server.connectionOpen();
        PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
        PaymentChannelServer server = pair.server;
        client.connectionOpen();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.INITIATE));
        if (useRefunds()) {
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_REFUND));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.RETURN_REFUND));
        }
        broadcastTxPause.release();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_CONTRACT));
        broadcasts.take();
        pair.serverRecorder.checkTotalPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN));
        Sha256Hash contractHash = (Sha256Hash) pair.serverRecorder.q.take();
        pair.clientRecorder.checkInitiated();
        assertNull(pair.serverRecorder.q.poll());
        assertNull(pair.clientRecorder.q.poll());
        // Send the whole channel at once. The server will broadcast the final contract and settle the channel for us.
        client.incrementPayment(client.state().getValueRefunded());
        broadcastTxPause.release();
        server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.UPDATE_PAYMENT));
        broadcasts.take();
        // The channel is now empty.
        assertEquals(Coin.ZERO, client.state().getValueRefunded());
        pair.serverRecorder.q.take();  // Take the Coin.
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.PAYMENT_ACK));
        client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CLOSE));
        assertEquals(CloseReason.SERVER_REQUESTED_CLOSE, pair.clientRecorder.q.take());
        client.connectionClosed();

        // Now try opening a new channel with the same server ID and verify the client asks for a new channel.
        client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
        client.connectionOpen();
        Protos.TwoWayChannelMessage msg = pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION);
        assertFalse(msg.getClientVersion().hasPreviousChannelContractHash());
    }

    @Test
    public void repeatedChannels() throws Exception {
        // Ensures we're selecting channels correctly. Covers a bug in which we'd always try and fail to resume
        // the first channel due to lack of proper closing behaviour.
        // Open up a normal channel, but don't spend all of it, then settle it.
        {
            Sha256Hash someServerId = Sha256Hash.ZERO_HASH;
            ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
            pair.server.connectionOpen();
            PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
            PaymentChannelServer server = pair.server;
            client.connectionOpen();
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.INITIATE));
            if (useRefunds()) {
                server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_REFUND));
                client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.RETURN_REFUND));
            }
            broadcastTxPause.release();
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_CONTRACT));
            broadcasts.take();
            pair.serverRecorder.checkTotalPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN));
            Sha256Hash contractHash = (Sha256Hash) pair.serverRecorder.q.take();
            pair.clientRecorder.checkInitiated();
            assertNull(pair.serverRecorder.q.poll());
            assertNull(pair.clientRecorder.q.poll());
            for (int i = 0; i < 3; i++) {
                ListenableFuture<PaymentIncrementAck> future = client.incrementPayment(CENT);
                server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.UPDATE_PAYMENT));
                pair.serverRecorder.q.take();
                final Protos.TwoWayChannelMessage msg = pair.serverRecorder.checkNextMsg(MessageType.PAYMENT_ACK);
                final Protos.PaymentAck paymentAck = msg.getPaymentAck();
                assertTrue("No PaymentAck.Info", paymentAck.hasInfo());
                assertEquals("Wrong PaymentAck info", ByteString.copyFromUtf8(CENT.toPlainString()), paymentAck.getInfo());
                client.receiveMessage(msg);
                assertTrue(future.isDone());
                final PaymentIncrementAck paymentIncrementAck = future.get();
                assertEquals("Wrong value returned from increasePayment", CENT, paymentIncrementAck.getValue());
                assertEquals("Wrong info returned from increasePayment", ByteString.copyFromUtf8(CENT.toPlainString()), paymentIncrementAck.getInfo());
            }

            // Settle it and verify it's considered to be settled.
            broadcastTxPause.release();
            client.settle();
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLOSE));
            Transaction settlement1 = broadcasts.take();
            // Server sends back the settle TX it just broadcast.
            final Protos.TwoWayChannelMessage closeMsg = pair.serverRecorder.checkNextMsg(MessageType.CLOSE);
            final Transaction settlement2 = new Transaction(UNITTEST, closeMsg.getSettlement().getTx().toByteArray());
            assertEquals(settlement1, settlement2);
            client.receiveMessage(closeMsg);
            assertNotNull(wallet.getTransaction(settlement2.getTxId()));   // Close TX entered the wallet.
            sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, settlement1);
            client.connectionClosed();
            server.connectionClosed();
        }
        // Now open a second channel and don't spend all of it/don't settle it.
        {
            Sha256Hash someServerId = Sha256Hash.ZERO_HASH;
            ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
            pair.server.connectionOpen();
            PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
            PaymentChannelServer server = pair.server;
            client.connectionOpen();
            final Protos.TwoWayChannelMessage msg = pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION);
            assertFalse(msg.getClientVersion().hasPreviousChannelContractHash());
            server.receiveMessage(msg);
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.INITIATE));
            if (useRefunds()) {
                server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_REFUND));
                client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.RETURN_REFUND));
            }
            broadcastTxPause.release();
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.PROVIDE_CONTRACT));
            broadcasts.take();
            pair.serverRecorder.checkTotalPayment(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN));
            Sha256Hash contractHash = (Sha256Hash) pair.serverRecorder.q.take();
            pair.clientRecorder.checkInitiated();
            assertNull(pair.serverRecorder.q.poll());
            assertNull(pair.clientRecorder.q.poll());
            client.incrementPayment(CENT);
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.UPDATE_PAYMENT));
            client.connectionClosed();
            server.connectionClosed();
        }
        // Now connect again and check we resume the second channel.
        {
            Sha256Hash someServerId = Sha256Hash.ZERO_HASH;
            ChannelTestUtils.RecordingPair pair = ChannelTestUtils.makeRecorders(serverWallet, mockBroadcaster);
            pair.server.connectionOpen();
            PaymentChannelClient client = new PaymentChannelClient(wallet, myKey, COIN, someServerId, null, clientChannelProperties, pair.clientRecorder);
            PaymentChannelServer server = pair.server;
            client.connectionOpen();
            server.receiveMessage(pair.clientRecorder.checkNextMsg(MessageType.CLIENT_VERSION));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.SERVER_VERSION));
            client.receiveMessage(pair.serverRecorder.checkNextMsg(MessageType.CHANNEL_OPEN));
        }
        assertEquals(2, StoredPaymentChannelClientStates.getFromWallet(wallet).mapChannels.size());
    }
}
