/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.core;

import com.google.common.base.Stopwatch;
import com.google.common.collect.*;
import com.google.common.net.*;
import com.google.common.util.concurrent.*;
import org.bitcoinj.core.listeners.*;
import org.bitcoinj.net.discovery.*;
import org.bitcoinj.testing.*;
import org.bitcoinj.utils.*;
import org.bitcoinj.wallet.Wallet;
import org.junit.*;
import org.junit.runner.*;
import org.junit.runners.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static org.bitcoinj.core.Coin.*;
import static org.junit.Assert.*;


// TX announcement and broadcast is tested in TransactionBroadcastTest.

@RunWith(value = Parameterized.class)
public class PeerGroupTest extends TestWithPeerGroup {
    private static final int BLOCK_HEIGHT_GENESIS = 0;

    private BlockingQueue<Peer> connectedPeers;
    private BlockingQueue<Peer> disconnectedPeers;
    private PeerConnectedEventListener connectedListener = new PeerConnectedEventListener() {
        @Override
        public void onPeerConnected(Peer peer, int peerCount) {
            connectedPeers.add(peer);
        }
    };
    private PeerDisconnectedEventListener disconnectedListener = new PeerDisconnectedEventListener() {
        @Override
        public void onPeerDisconnected(Peer peer, int peerCount) {
            disconnectedPeers.add(peer);
        }
    };
    private PreMessageReceivedEventListener preMessageReceivedListener;
    private Map<Peer, AtomicInteger> peerToMessageCount;

    @Parameterized.Parameters
    public static Collection<ClientType[]> parameters() {
        return Arrays.asList(new ClientType[] {ClientType.NIO_CLIENT_MANAGER},
                             new ClientType[] {ClientType.BLOCKING_CLIENT_MANAGER});
    }

    public PeerGroupTest(ClientType clientType) {
        super(clientType);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        peerToMessageCount = new HashMap<>();
        connectedPeers = new LinkedBlockingQueue<>();
        disconnectedPeers = new LinkedBlockingQueue<>();
        preMessageReceivedListener = new PreMessageReceivedEventListener() {
            @Override
            public Message onPreMessageReceived(Peer peer, Message m) {
                AtomicInteger messageCount = peerToMessageCount.get(peer);
                if (messageCount == null) {
                    messageCount = new AtomicInteger(0);
                    peerToMessageCount.put(peer, messageCount);
                }
                messageCount.incrementAndGet();
                // Just pass the message right through for further processing.
                return m;
            }
        };
    }

    @Override
    @After
    public void tearDown() {
        super.tearDown();
    }

    @Test
    public void listener() throws Exception {
        peerGroup.addConnectedEventListener(connectedListener);
        peerGroup.addDisconnectedEventListener(disconnectedListener);
        peerGroup.addPreMessageReceivedEventListener(preMessageReceivedListener);
        peerGroup.start();

        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        connectedPeers.take();
        connectedPeers.take();

        pingAndWait(p1);
        pingAndWait(p2);
        Threading.waitForUserCode();
        assertEquals(0, disconnectedPeers.size());

        p1.close();
        disconnectedPeers.take();
        assertEquals(0, disconnectedPeers.size());
        p2.close();
        disconnectedPeers.take();
        assertEquals(0, disconnectedPeers.size());

        assertTrue(peerGroup.removeConnectedEventListener(connectedListener));
        assertFalse(peerGroup.removeConnectedEventListener(connectedListener));
        assertTrue(peerGroup.removeDisconnectedEventListener(disconnectedListener));
        assertFalse(peerGroup.removeDisconnectedEventListener(disconnectedListener));
        assertTrue(peerGroup.removePreMessageReceivedEventListener(preMessageReceivedListener));
        assertFalse(peerGroup.removePreMessageReceivedEventListener(preMessageReceivedListener));
    }

    @Test
    public void peerDiscoveryPolling() throws InterruptedException {
        // Check that if peer discovery fails, we keep trying until we have some nodes to talk with.
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicBoolean result = new AtomicBoolean();
        peerGroup.addPeerDiscovery(new PeerDiscovery() {
            @Override
            public InetSocketAddress[] getPeers(long services, long unused, TimeUnit unused2) throws PeerDiscoveryException {
                if (!result.getAndSet(true)) {
                    // Pretend we are not connected to the internet.
                    throw new PeerDiscoveryException("test failure");
                } else {
                    // Return a bogus address.
                    latch.countDown();
                    return new InetSocketAddress[]{new InetSocketAddress("localhost", 1)};
                }
            }

            @Override
            public void shutdown() {
            }
        });
        peerGroup.start();
        latch.await();
        // Check that we did indeed throw an exception. If we got here it means we threw and then PeerGroup tried
        // again a bit later.
        assertTrue(result.get());
    }

    // Utility method to create a PeerDiscovery with a certain number of addresses.
    private PeerDiscovery createPeerDiscovery(int nrOfAddressesWanted, int port) {
        final InetSocketAddress[] addresses = new InetSocketAddress[nrOfAddressesWanted];
        for (int addressNr = 0; addressNr < nrOfAddressesWanted; addressNr++) {
            // make each address unique by using the counter to increment the port.
            addresses[addressNr] = new InetSocketAddress("localhost", port + addressNr);
        }
        return new PeerDiscovery() {
            public InetSocketAddress[] getPeers(long services, long unused, TimeUnit unused2) throws PeerDiscoveryException {
                return addresses;
            }
            public void shutdown() {
            }
        };
    }

    @Test
    public void multiplePeerDiscovery() throws InterruptedException {
        peerGroup.setMaxPeersToDiscoverCount(98);
        peerGroup.addPeerDiscovery(createPeerDiscovery(1, 0));
        peerGroup.addPeerDiscovery(createPeerDiscovery(2, 100));
        peerGroup.addPeerDiscovery(createPeerDiscovery(96, 200));
        peerGroup.addPeerDiscovery(createPeerDiscovery(3, 300));
        peerGroup.addPeerDiscovery(createPeerDiscovery(1, 400));
        peerGroup.addDiscoveredEventListener(new PeerDiscoveredEventListener() {
            @Override
            public void onPeersDiscovered(Set<PeerAddress> peerAddresses) {
                assertEquals(99, peerAddresses.size());
            }
        });
        peerGroup.start();
    }

    @Test
    public void receiveTxBroadcast() throws Exception {
        // Check that when we receive transactions on all our peers, we do the right thing.
        peerGroup.start();

        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        
        // Check the peer accessors.
        assertEquals(2, peerGroup.numConnectedPeers());
        Set<Peer> tmp = new HashSet<>(peerGroup.getConnectedPeers());
        Set<Peer> expectedPeers = new HashSet<>();
        expectedPeers.add(peerOf(p1));
        expectedPeers.add(peerOf(p2));
        assertEquals(tmp, expectedPeers);

        Coin value = COIN;
        Transaction t1 = FakeTxBuilder.createFakeTx(PARAMS, value, address);
        InventoryMessage inv = new InventoryMessage(PARAMS);
        inv.addTransaction(t1);

        // Note: we start with p2 here to verify that transactions are downloaded from whichever peer announces first
        // which does not have to be the same as the download peer (which is really the "block download peer").
        inbound(p2, inv);
        assertTrue(outbound(p2) instanceof GetDataMessage);
        inbound(p1, inv);
        assertNull(outbound(p1));  // Only one peer is used to download.
        inbound(p2, t1);
        assertNull(outbound(p1));
        // Asks for dependency.
        GetDataMessage getdata = (GetDataMessage) outbound(p2);
        assertNotNull(getdata);
        inbound(p2, new NotFoundMessage(PARAMS, getdata.getItems()));
        pingAndWait(p2);
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    
    @Test
    public void receiveTxBroadcastOnAddedWallet() throws Exception {
        // Check that when we receive transactions on all our peers, we do the right thing.
        peerGroup.start();

        // Create a peer.
        InboundMessageQueuer p1 = connectPeer(1);
        
        Wallet wallet2 = new Wallet(PARAMS);
        ECKey key2 = wallet2.freshReceiveKey();
        Address address2 = key2.toAddress(PARAMS);
        
        peerGroup.addWallet(wallet2);
        blockChain.addWallet(wallet2);

        assertEquals(BloomFilter.class, waitForOutbound(p1).getClass());
        assertEquals(MemoryPoolMessage.class, waitForOutbound(p1).getClass());

        Coin value = COIN;
        Transaction t1 = FakeTxBuilder.createFakeTx(PARAMS, value, address2);
        InventoryMessage inv = new InventoryMessage(PARAMS);
        inv.addTransaction(t1);

        inbound(p1, inv);
        assertTrue(outbound(p1) instanceof GetDataMessage);
        inbound(p1, t1);
        // Asks for dependency.
        GetDataMessage getdata = (GetDataMessage) outbound(p1);
        assertNotNull(getdata);
        inbound(p1, new NotFoundMessage(PARAMS, getdata.getItems()));
        pingAndWait(p1);
        assertEquals(value, wallet2.getBalance(Wallet.BalanceType.ESTIMATED));
    }
    
    @Test
    public void singleDownloadPeer1() throws Exception {
        // Check that we don't attempt to retrieve blocks on multiple peers.
        peerGroup.start();

        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        assertEquals(2, peerGroup.numConnectedPeers());

        // Set up a little block chain. We heard about b1 but not b2 (it is pending download). b3 is solved whilst we
        // are downloading the chain.
        Block b1 = FakeTxBuilder.createFakeBlock(blockStore, BLOCK_HEIGHT_GENESIS).block;
        blockChain.add(b1);
        Block b2 = FakeTxBuilder.makeSolvedTestBlock(b1);
        Block b3 = FakeTxBuilder.makeSolvedTestBlock(b2);

        // Peer 1 and 2 receives an inv advertising a newly solved block.
        InventoryMessage inv = new InventoryMessage(PARAMS);
        inv.addBlock(b3);
        // Only peer 1 tries to download it.
        inbound(p1, inv);
        pingAndWait(p1);
        
        assertTrue(outbound(p1) instanceof GetDataMessage);
        assertNull(outbound(p2));
        // Peer 1 goes away, peer 2 becomes the download peer and thus queries the remote mempool.
        final SettableFuture<Void> p1CloseFuture = SettableFuture.create();
        peerOf(p1).addDisconnectedEventListener(new PeerDisconnectedEventListener() {
            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                p1CloseFuture.set(null);
            }
        });
        closePeer(peerOf(p1));
        p1CloseFuture.get();
        // Peer 2 fetches it next time it hears an inv (should it fetch immediately?).
        inbound(p2, inv);
        assertTrue(outbound(p2) instanceof GetDataMessage);
    }

    @Test
    public void singleDownloadPeer2() throws Exception {
        // Check that we don't attempt multiple simultaneous block chain downloads, when adding a new peer in the
        // middle of an existing chain download.
        // Create a couple of peers.
        peerGroup.start();

        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);

        // Set up a little block chain.
        Block b1 = FakeTxBuilder.createFakeBlock(blockStore, BLOCK_HEIGHT_GENESIS).block;
        Block b2 = FakeTxBuilder.makeSolvedTestBlock(b1);
        Block b3 = FakeTxBuilder.makeSolvedTestBlock(b2);

        // Expect a zero hash getblocks on p1. This is how the process starts.
        peerGroup.startBlockChainDownload(new AbstractPeerDataEventListener() {
        });
        GetBlocksMessage getblocks = (GetBlocksMessage) outbound(p1);
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // We give back an inv with some blocks in it.
        InventoryMessage inv = new InventoryMessage(PARAMS);
        inv.addBlock(b1);
        inv.addBlock(b2);
        inv.addBlock(b3);
        
        inbound(p1, inv);
        assertTrue(outbound(p1) instanceof GetDataMessage);
        // We hand back the first block.
        inbound(p1, b1);
        // Now we successfully connect to another peer. There should be no messages sent.
        InboundMessageQueuer p2 = connectPeer(2);
        Message message = outbound(p2);
        assertNull(message == null ? "" : message.toString(), message);
    }

    @Test
    public void transactionConfidence() throws Exception {
        // Checks that we correctly count how many peers broadcast a transaction, so we can establish some measure of
        // its trustworthyness assuming an untampered with internet connection.
        peerGroup.start();

        final Transaction[] event = new Transaction[1];
        final TransactionConfidence[] confEvent = new TransactionConfidence[1];
        peerGroup.addOnTransactionBroadcastListener(Threading.SAME_THREAD, new OnTransactionBroadcastListener() {
            @Override
            public void onTransaction(Peer peer, Transaction t) {
                event[0] = t;
            }
        });

        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        InboundMessageQueuer p3 = connectPeer(3);

        Transaction tx = FakeTxBuilder.createFakeTx(PARAMS, valueOf(20, 0), address);
        InventoryMessage inv = new InventoryMessage(PARAMS);
        inv.addTransaction(tx);

        assertEquals(0, tx.getConfidence().numBroadcastPeers());
        assertNull(tx.getConfidence().getLastBroadcastedAt());

        // Peer 2 advertises the tx but does not receive it yet.
        inbound(p2, inv);
        assertTrue(outbound(p2) instanceof GetDataMessage);
        assertEquals(1, tx.getConfidence().numBroadcastPeers());
        assertNull(event[0]);
        // Peer 1 advertises the tx, we don't do anything as it's already been requested.
        inbound(p1, inv);
        assertNull(outbound(p1));
        // Peer 2 gets sent the tx and requests the dependency.
        inbound(p2, tx);
        assertTrue(outbound(p2) instanceof GetDataMessage);
        tx = event[0];  // We want to use the canonical copy delivered by the PeerGroup from now on.
        assertNotNull(tx);
        event[0] = null;

        // Peer 1 (the download peer) advertises the tx, we download it.
        inbound(p1, inv);  // returns getdata
        inbound(p1, tx);   // returns nothing after a queue drain.
        // Two peers saw this tx hash.
        assertEquals(2, tx.getConfidence().numBroadcastPeers());
        assertTrue(tx.getConfidence().wasBroadcastBy(peerOf(p1).getAddress()));
        assertTrue(tx.getConfidence().wasBroadcastBy(peerOf(p2).getAddress()));
        assertNotNull(tx.getConfidence().getLastBroadcastedAt());

        tx.getConfidence().addEventListener(new TransactionConfidence.Listener() {
            @Override
            public void onConfidenceChanged(TransactionConfidence confidence, TransactionConfidence.Listener.ChangeReason reason) {
                confEvent[0] = confidence;
            }
        });
        // A straggler reports in.
        inbound(p3, inv);
        pingAndWait(p3);
        Threading.waitForUserCode();
        assertEquals(tx.getHash(), confEvent[0].getTransactionHash());
        assertEquals(3, tx.getConfidence().numBroadcastPeers());
        assertTrue(tx.getConfidence().wasBroadcastBy(peerOf(p3).getAddress()));
    }

    @Test
    public void testWalletCatchupTime() throws Exception {
        // Check the fast catchup time was initialized to something around the current runtime minus a week.
        // The wallet was already added to the peer in setup.
        final int WEEK = 86400 * 7;
        final long now = Utils.currentTimeSeconds();
        peerGroup.start();
        assertTrue(peerGroup.getFastCatchupTimeSecs() > now - WEEK - 10000);
        Wallet w2 = new Wallet(PARAMS);
        ECKey key1 = new ECKey();
        key1.setCreationTimeSeconds(now - 86400);  // One day ago.
        w2.importKey(key1);
        peerGroup.addWallet(w2);
        peerGroup.waitForJobQueue();
        assertEquals(peerGroup.getFastCatchupTimeSecs(), now - 86400 - WEEK);
        // Adding a key to the wallet should update the fast catchup time, but asynchronously and in the background
        // due to the need to avoid complicated lock inversions.
        ECKey key2 = new ECKey();
        key2.setCreationTimeSeconds(now - 100000);
        w2.importKey(key2);
        peerGroup.waitForJobQueue();
        assertEquals(peerGroup.getFastCatchupTimeSecs(), now - WEEK - 100000);
    }

    @Test
    public void noPings() throws Exception {
        peerGroup.start();
        peerGroup.setPingIntervalMsec(0);
        VersionMessage versionMessage = new VersionMessage(PARAMS, 2);
        versionMessage.clientVersion = NetworkParameters.ProtocolVersion.BLOOM_FILTER.getBitcoinProtocolVersion();
        versionMessage.localServices = VersionMessage.NODE_NETWORK;
        connectPeer(1, versionMessage);
        peerGroup.waitForPeers(1).get();
        assertFalse(peerGroup.getConnectedPeers().get(0).getLastPingTime() < Long.MAX_VALUE);
    }

    @Test
    public void pings() throws Exception {
        peerGroup.start();
        peerGroup.setPingIntervalMsec(100);
        VersionMessage versionMessage = new VersionMessage(PARAMS, 2);
        versionMessage.clientVersion = NetworkParameters.ProtocolVersion.BLOOM_FILTER.getBitcoinProtocolVersion();
        versionMessage.localServices = VersionMessage.NODE_NETWORK;
        InboundMessageQueuer p1 = connectPeer(1, versionMessage);
        Ping ping = (Ping) waitForOutbound(p1);
        inbound(p1, new Pong(ping.getNonce()));
        pingAndWait(p1);
        assertTrue(peerGroup.getConnectedPeers().get(0).getLastPingTime() < Long.MAX_VALUE);
        // The call to outbound should block until a ping arrives.
        ping = (Ping) waitForOutbound(p1);
        inbound(p1, new Pong(ping.getNonce()));
        assertTrue(peerGroup.getConnectedPeers().get(0).getLastPingTime() < Long.MAX_VALUE);
    }

    @Test
    public void downloadPeerSelection() throws Exception {
        peerGroup.start();
        VersionMessage versionMessage2 = new VersionMessage(PARAMS, 2);
        versionMessage2.clientVersion = NetworkParameters.ProtocolVersion.BLOOM_FILTER.getBitcoinProtocolVersion();
        versionMessage2.localServices = VersionMessage.NODE_NETWORK;
        VersionMessage versionMessage3 = new VersionMessage(PARAMS, 3);
        versionMessage3.clientVersion = NetworkParameters.ProtocolVersion.BLOOM_FILTER.getBitcoinProtocolVersion();
        versionMessage3.localServices = VersionMessage.NODE_NETWORK;
        assertNull(peerGroup.getDownloadPeer());
        Peer a = connectPeer(1, versionMessage2).peer;
        assertEquals(2, peerGroup.getMostCommonChainHeight());
        assertEquals(a, peerGroup.getDownloadPeer());
        connectPeer(2, versionMessage2);
        assertEquals(2, peerGroup.getMostCommonChainHeight());
        assertEquals(a, peerGroup.getDownloadPeer());  // No change.
        Peer c = connectPeer(3, versionMessage3).peer;
        assertEquals(2, peerGroup.getMostCommonChainHeight());
        assertEquals(a, peerGroup.getDownloadPeer());  // No change yet.
        connectPeer(4, versionMessage3);
        assertEquals(3, peerGroup.getMostCommonChainHeight());
        assertEquals(a, peerGroup.getDownloadPeer());  // Still no change.

        // New peer with a higher protocol version but same chain height.
        // TODO: When PeerGroup.selectDownloadPeer.PREFERRED_VERSION is not equal to vMinRequiredProtocolVersion,
        // reenable this test
        /*VersionMessage versionMessage4 = new VersionMessage(PARAMS, 3);
        versionMessage4.clientVersion = 100000;
        versionMessage4.localServices = VersionMessage.NODE_NETWORK;
        InboundMessageQueuer d = connectPeer(5, versionMessage4);
        assertEquals(d.peer, peerGroup.getDownloadPeer());*/
    }

    @Test
    public void peerTimeoutTest() throws Exception {
        final int timeout = 100;
        peerGroup.start();
        peerGroup.setConnectTimeoutMillis(timeout);

        final SettableFuture<Void> peerConnectedFuture = SettableFuture.create();
        final SettableFuture<Void> peerDisconnectedFuture = SettableFuture.create();
        peerGroup.addConnectedEventListener(Threading.SAME_THREAD, new PeerConnectedEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                peerConnectedFuture.set(null);
            }
        });
        peerGroup.addDisconnectedEventListener(Threading.SAME_THREAD, new PeerDisconnectedEventListener() {
            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                peerDisconnectedFuture.set(null);
            }
        });
        // connect to peer but don't do handshake
        final Stopwatch watch = Stopwatch.createStarted(); // before connection so we don't get elapsed < timeout
        connectPeerWithoutVersionExchange(0);
        // wait for disconnect (plus a bit more, in case test server is overloaded)
        try {
            peerDisconnectedFuture.get(timeout + 200, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            // the checks below suffice for this case too
        }
        // check things after disconnect
        watch.stop();
        assertFalse(peerConnectedFuture.isDone()); // should never have connected
        assertTrue(watch.elapsed(TimeUnit.MILLISECONDS) >= timeout); // should not disconnect before timeout
        assertTrue(peerDisconnectedFuture.isDone()); // but should disconnect eventually
    }

    @Test
    @Ignore("disabled for now as this test is too flaky")
    public void peerPriority() throws Exception {
        final List<InetSocketAddress> addresses = Lists.newArrayList(
                new InetSocketAddress("localhost", 2000),
                new InetSocketAddress("localhost", 2001),
                new InetSocketAddress("localhost", 2002)
        );
        peerGroup.addConnectedEventListener(connectedListener);
        peerGroup.addDisconnectedEventListener(disconnectedListener);
        peerGroup.addPreMessageReceivedEventListener(preMessageReceivedListener);
        peerGroup.addPeerDiscovery(new PeerDiscovery() {
            @Override
            public InetSocketAddress[] getPeers(long services, long unused, TimeUnit unused2) throws PeerDiscoveryException {
                return addresses.toArray(new InetSocketAddress[addresses.size()]);
            }

            @Override
            public void shutdown() {
            }
        });
        peerGroup.setMaxConnections(3);

        Utils.setMockSleep(true);
        blockJobs = true;

        jobBlocks.release(2);   // startup + first peer discovery
        peerGroup.start();

        jobBlocks.release(3);  // One for each peer.
        handleConnectToPeer(0);
        handleConnectToPeer(1);
        handleConnectToPeer(2);
        connectedPeers.take();
        connectedPeers.take();
        connectedPeers.take();
        addresses.clear();
        addresses.addAll(Lists.newArrayList(new InetSocketAddress("localhost", 2003)));
        stopPeerServer(2);
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort()); // peer died

        // discovers, connects to new peer
        jobBlocks.release(1);
        handleConnectToPeer(3);
        assertEquals(2003, connectedPeers.take().getAddress().getPort());

        stopPeerServer(1);
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort()); // peer died

        // Alternates trying two offline peers
        jobBlocks.release(10);
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort());
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort());
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());

        // Peer 2 comes online
        startPeerServer(2);
        jobBlocks.release(1);
        handleConnectToPeer(2);
        assertEquals(2002, connectedPeers.take().getAddress().getPort());

        jobBlocks.release(6);
        stopPeerServer(2);
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort()); // peer died

        // Peer 2 is tried before peer 1, since it has a lower backoff due to recent success
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort());
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());
    }

    @Test
    public void testBloomOnP2Pubkey() throws Exception {
        // Cover bug 513. When a relevant transaction with a p2pubkey output is found, the Bloom filter should be
        // recalculated to include that transaction hash but not re-broadcast as the remote nodes should have followed
        // the same procedure. However a new node that's connected should get the fresh filter.
        peerGroup.start();
        final ECKey key = wallet.currentReceiveKey();
        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        // Create a pay to pubkey tx.
        Transaction tx = FakeTxBuilder.createFakeTx(PARAMS, COIN, key);
        Transaction tx2 = new Transaction(PARAMS);
        tx2.addInput(tx.getOutput(0));
        TransactionOutPoint outpoint = tx2.getInput(0).getOutpoint();
        assertTrue(p1.lastReceivedFilter.contains(key.getPubKey()));
        assertFalse(p1.lastReceivedFilter.contains(tx.getHash().getBytes()));
        inbound(p1, tx);
        // p1 requests dep resolution, p2 is quiet.
        assertTrue(outbound(p1) instanceof GetDataMessage);
        final Sha256Hash dephash = tx.getInput(0).getOutpoint().getHash();
        final InventoryItem inv = new InventoryItem(InventoryItem.Type.Transaction, dephash);
        inbound(p1, new NotFoundMessage(PARAMS, ImmutableList.of(inv)));
        assertNull(outbound(p1));
        assertNull(outbound(p2));
        peerGroup.waitForJobQueue();
        // Now we connect p3 and there is a new bloom filter sent, that DOES match the relevant outpoint.
        InboundMessageQueuer p3 = connectPeer(3);
        assertTrue(p3.lastReceivedFilter.contains(key.getPubKey()));
        assertTrue(p3.lastReceivedFilter.contains(outpoint.unsafeBitcoinSerialize()));
    }

    @Test
    public void testBloomResendOnNewKey() throws Exception {
        // Check that when we add a new key to the wallet, the Bloom filter is re-calculated and re-sent but only once
        // we exceed the lookahead threshold.
        wallet.setKeyChainGroupLookaheadSize(5);
        wallet.setKeyChainGroupLookaheadThreshold(4);
        peerGroup.start();
        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        peerGroup.waitForJobQueue();
        BloomFilter f1 = p1.lastReceivedFilter;
        ECKey key = null;
        // We have to run ahead of the lookahead zone for this test. There should only be one bloom filter recalc.
        for (int i = 0; i < wallet.getKeyChainGroupLookaheadSize() + wallet.getKeyChainGroupLookaheadThreshold() + 1; i++) {
            key = wallet.freshReceiveKey();
        }
        peerGroup.waitForJobQueue();
        BloomFilter bf, f2 = null;
        while ((bf = (BloomFilter) outbound(p1)) != null) {
            assertEquals(MemoryPoolMessage.class, outbound(p1).getClass());
            f2 = bf;
        }
        assertNotNull(key);
        assertNotNull(f2);
        assertNull(outbound(p1));
        // Check the last filter received.
        assertNotEquals(f1, f2);
        assertTrue(f2.contains(key.getPubKey()));
        assertTrue(f2.contains(key.getPubKeyHash()));
        assertFalse(f1.contains(key.getPubKey()));
        assertFalse(f1.contains(key.getPubKeyHash()));
    }

    @Test
    public void waitForNumPeers1() throws Exception {
        ListenableFuture<List<Peer>> future = peerGroup.waitForPeers(3);
        peerGroup.start();
        assertFalse(future.isDone());
        connectPeer(1);
        assertFalse(future.isDone());
        connectPeer(2);
        assertFalse(future.isDone());
        assertTrue(peerGroup.waitForPeers(2).isDone());   // Immediate completion.
        connectPeer(3);
        future.get();
        assertTrue(future.isDone());
    }

    @Test
    public void waitForPeersOfVersion() throws Exception {
        final int baseVer = peerGroup.getMinRequiredProtocolVersion() + 3000;
        final int newVer = baseVer + 1000;

        ListenableFuture<List<Peer>> future = peerGroup.waitForPeersOfVersion(2, newVer);

        VersionMessage ver1 = new VersionMessage(PARAMS, 10);
        ver1.clientVersion = baseVer;
        ver1.localServices = VersionMessage.NODE_NETWORK;
        VersionMessage ver2 = new VersionMessage(PARAMS, 10);
        ver2.clientVersion = newVer;
        ver2.localServices = VersionMessage.NODE_NETWORK;
        peerGroup.start();
        assertFalse(future.isDone());
        connectPeer(1, ver1);
        assertFalse(future.isDone());
        connectPeer(2, ver2);
        assertFalse(future.isDone());
        assertTrue(peerGroup.waitForPeersOfVersion(1, newVer).isDone());   // Immediate completion.
        connectPeer(3, ver2);
        future.get();
        assertTrue(future.isDone());
    }

    @Test
    public void waitForPeersWithServiceFlags() throws Exception {
        ListenableFuture<List<Peer>> future = peerGroup.waitForPeersWithServiceMask(2, 3);

        VersionMessage ver1 = new VersionMessage(PARAMS, 10);
        ver1.clientVersion = 70000;
        ver1.localServices = VersionMessage.NODE_NETWORK;
        VersionMessage ver2 = new VersionMessage(PARAMS, 10);
        ver2.clientVersion = 70000;
        ver2.localServices = VersionMessage.NODE_NETWORK | 2;
        peerGroup.start();
        assertFalse(future.isDone());
        connectPeer(1, ver1);
        assertTrue(peerGroup.findPeersWithServiceMask(3).isEmpty());
        assertFalse(future.isDone());
        connectPeer(2, ver2);
        assertFalse(future.isDone());
        assertEquals(1, peerGroup.findPeersWithServiceMask(3).size());
        assertTrue(peerGroup.waitForPeersWithServiceMask(1, 0x3).isDone());   // Immediate completion.
        connectPeer(3, ver2);
        future.get();
        assertTrue(future.isDone());
        peerGroup.stop();
    }

    @Test
    public void preferLocalPeer() throws IOException {
        // Because we are using the same port (8333 or 18333) that is used by Bitcoin Core
        // We have to consider 2 cases:
        // 1. Test are executed on the same machine that is running a full node
        // 2. Test are executed without any full node running locally
        // We have to avoid to connecting to real and external services in unit tests
        // So we skip this test in case we have already something running on port PARAMS.getPort()

        // Check that if we have a localhost port 8333 or 18333 then it's used instead of the p2p network.
        ServerSocket local = null;
        try {
            local = new ServerSocket(PARAMS.getPort(), 100, InetAddresses.forString("127.0.0.1"));
        }
        catch(BindException e) { // Port already in use, skipping this test.
            return;
        }

        try {
            peerGroup.setUseLocalhostPeerWhenPossible(true);
            peerGroup.start();
            local.accept().close();   // Probe connect
            local.accept();   // Real connect
            // If we get here it used the local peer. Check no others are in use.
            assertEquals(1, peerGroup.getMaxConnections());
            assertEquals(PeerAddress.localhost(PARAMS), peerGroup.getPendingPeers().get(0).getAddress());
        } finally {
            local.close();
        }
    }

    private <T extends Message> T assertNextMessageIs(InboundMessageQueuer q, Class<T> klass) throws Exception {
        Message outbound = waitForOutbound(q);
        assertEquals(klass, outbound.getClass());
        return (T) outbound;
    }

    @Test
    public void autoRescanOnKeyExhaustion() throws Exception {
        // Check that if the last key that was inserted into the bloom filter is seen in some requested blocks,
        // that the exhausting block is discarded, a new filter is calculated and sent, and then the download resumes.

        final int NUM_KEYS = 9;

        // First, grab a load of keys from the wallet, and then recreate it so it forgets that those keys were issued.
        Wallet shadow = Wallet.fromSeed(wallet.getParams(), wallet.getKeyChainSeed());
        List<ECKey> keys = new ArrayList<>(NUM_KEYS);
        for (int i = 0; i < NUM_KEYS; i++) {
            keys.add(shadow.freshReceiveKey());
        }
        // Reduce the number of keys we need to work with to speed up this test.
        wallet.setKeyChainGroupLookaheadSize(4);
        wallet.setKeyChainGroupLookaheadThreshold(2);

        peerGroup.start();
        InboundMessageQueuer p1 = connectPeer(1);
        assertTrue(p1.lastReceivedFilter.contains(keys.get(0).getPubKey()));
        assertTrue(p1.lastReceivedFilter.contains(keys.get(5).getPubKeyHash()));
        assertFalse(p1.lastReceivedFilter.contains(keys.get(keys.size() - 1).getPubKey()));
        peerGroup.startBlockChainDownload(null);
        assertNextMessageIs(p1, GetBlocksMessage.class);

        // Make some transactions and blocks that send money to the wallet thus using up all the keys.
        List<Block> blocks = Lists.newArrayList();
        Coin expectedBalance = Coin.ZERO;
        Block prev = blockStore.getChainHead().getHeader();
        for (ECKey key1 : keys) {
            Address addr = key1.toAddress(PARAMS);
            Block next = FakeTxBuilder.makeSolvedTestBlock(prev, FakeTxBuilder.createFakeTx(PARAMS, Coin.FIFTY_COINS, addr));
            expectedBalance = expectedBalance.add(next.getTransactions().get(2).getOutput(0).getValue());
            blocks.add(next);
            prev = next;
        }

        // Send the chain that doesn't have all the transactions in it. The blocks after the exhaustion point should all
        // be ignored.
        int epoch = wallet.getKeyChainGroupCombinedKeyLookaheadEpochs();
        BloomFilter filter = new BloomFilter(PARAMS, p1.lastReceivedFilter.bitcoinSerialize());
        filterAndSend(p1, blocks, filter);
        Block exhaustionPoint = blocks.get(3);
        pingAndWait(p1);

        assertNotEquals(epoch, wallet.getKeyChainGroupCombinedKeyLookaheadEpochs());
        // 4th block was end of the lookahead zone and thus was discarded, so we got 3 blocks worth of money (50 each).
        assertEquals(Coin.FIFTY_COINS.multiply(3), wallet.getBalance());
        assertEquals(exhaustionPoint.getPrevBlockHash(), blockChain.getChainHead().getHeader().getHash());

        // Await the new filter.
        peerGroup.waitForJobQueue();
        BloomFilter newFilter = assertNextMessageIs(p1, BloomFilter.class);
        assertNotEquals(filter, newFilter);
        assertNextMessageIs(p1, MemoryPoolMessage.class);
        Ping ping = assertNextMessageIs(p1, Ping.class);
        inbound(p1, new Pong(ping.getNonce()));

        // Await restart of the chain download.
        GetDataMessage getdata = assertNextMessageIs(p1, GetDataMessage.class);
        assertEquals(exhaustionPoint.getHash(), getdata.getHashOf(0));
        assertEquals(InventoryItem.Type.FilteredBlock, getdata.getItems().get(0).type);
        List<Block> newBlocks = blocks.subList(3, blocks.size());
        filterAndSend(p1, newBlocks, newFilter);
        assertNextMessageIs(p1, Ping.class);

        // It happened again.
        peerGroup.waitForJobQueue();
        newFilter = assertNextMessageIs(p1, BloomFilter.class);
        assertNextMessageIs(p1, MemoryPoolMessage.class);
        inbound(p1, new Pong(assertNextMessageIs(p1, Ping.class).getNonce()));
        assertNextMessageIs(p1, GetDataMessage.class);
        newBlocks = blocks.subList(6, blocks.size());
        filterAndSend(p1, newBlocks, newFilter);
        // Send a non-tx message so the peer knows the filtered block is over and force processing.
        inbound(p1, new Ping());
        pingAndWait(p1);

        assertEquals(expectedBalance, wallet.getBalance());
        assertEquals(blocks.get(blocks.size() - 1).getHash(), blockChain.getChainHead().getHeader().getHash());
    }

    private void filterAndSend(InboundMessageQueuer p1, List<Block> blocks, BloomFilter filter) {
        for (Block block : blocks) {
            FilteredBlock fb = filter.applyAndUpdate(block);
            inbound(p1, fb);
            for (Transaction tx : fb.getAssociatedTransactions().values())
                inbound(p1, tx);
        }
    }
}
