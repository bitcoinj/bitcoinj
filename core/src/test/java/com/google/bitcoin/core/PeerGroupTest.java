/*
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;

import com.google.bitcoin.net.discovery.PeerDiscovery;
import com.google.bitcoin.net.discovery.PeerDiscoveryException;
import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.store.MemoryBlockStore;
import com.google.bitcoin.utils.TestUtils;
import com.google.bitcoin.utils.Threading;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.SettableFuture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;


// TX announcement and broadcast is tested in TransactionBroadcastTest.

@RunWith(value = Parameterized.class)
public class PeerGroupTest extends TestWithPeerGroup {
    static final NetworkParameters params = UnitTestParams.get();
    private BlockingQueue<Peer> connectedPeers;
    private BlockingQueue<Peer> disconnectedPeers;
    private PeerEventListener listener;
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
        peerToMessageCount = new HashMap<Peer, AtomicInteger>();
        connectedPeers = new LinkedBlockingQueue<Peer>();
        disconnectedPeers = new LinkedBlockingQueue<Peer>();
        listener = new AbstractPeerEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                connectedPeers.add(peer);
            }

            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                disconnectedPeers.add(peer);
            }

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
        super.setUp(new MemoryBlockStore(UnitTestParams.get()));
        peerGroup.addWallet(wallet);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        Utils.finishMockSleep();
        peerGroup.stopAndWait();
    }

    @Test
    public void listener() throws Exception {
        peerGroup.startAndWait();
        peerGroup.addEventListener(listener);

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

        assertTrue(peerGroup.removeEventListener(listener));
        assertFalse(peerGroup.removeEventListener(listener));
    }

    @Test
    public void peerDiscoveryPolling() throws InterruptedException {
        // Check that if peer discovery fails, we keep trying until we have some nodes to talk with.
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicBoolean result = new AtomicBoolean();
        peerGroup.addPeerDiscovery(new PeerDiscovery() {
            public InetSocketAddress[] getPeers(long unused, TimeUnit unused2) throws PeerDiscoveryException {
                if (!result.getAndSet(true)) {
                    // Pretend we are not connected to the internet.
                    throw new PeerDiscoveryException("test failure");
                } else {
                    // Return a bogus address.
                    latch.countDown();
                    return new InetSocketAddress[]{new InetSocketAddress("localhost", 1)};
                }
            }
            public void shutdown() {
            }
        });
        peerGroup.startAndWait();
        latch.await();
        // Check that we did indeed throw an exception. If we got here it means we threw and then PeerGroup tried
        // again a bit later.
        assertTrue(result.get());
    }

    @Test
    public void receiveTxBroadcast() throws Exception {
        // Check that when we receive transactions on all our peers, we do the right thing.
        peerGroup.startAndWait();

        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        
        // Check the peer accessors.
        assertEquals(2, peerGroup.numConnectedPeers());
        Set<Peer> tmp = new HashSet<Peer>(peerGroup.getConnectedPeers());
        Set<Peer> expectedPeers = new HashSet<Peer>();
        expectedPeers.add(peerOf(p1));
        expectedPeers.add(peerOf(p2));
        assertEquals(tmp, expectedPeers);

        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction t1 = TestUtils.createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
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
        inbound(p2, new NotFoundMessage(unitTestParams, getdata.getItems()));
        pingAndWait(p2);
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        peerGroup.stopAndWait();
    }

    @Test
    public void singleDownloadPeer1() throws Exception {
        // Check that we don't attempt to retrieve blocks on multiple peers.
        peerGroup.startAndWait();

        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        assertEquals(2, peerGroup.numConnectedPeers());

        // Set up a little block chain. We heard about b1 but not b2 (it is pending download). b3 is solved whilst we
        // are downloading the chain.
        Block b1 = TestUtils.createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(b1);
        Block b3 = TestUtils.makeSolvedTestBlock(b2);

        // Peer 1 and 2 receives an inv advertising a newly solved block.
        InventoryMessage inv = new InventoryMessage(params);
        inv.addBlock(b3);
        // Only peer 1 tries to download it.
        inbound(p1, inv);
        pingAndWait(p1);
        
        assertTrue(outbound(p1) instanceof GetDataMessage);
        assertNull(outbound(p2));
        // Peer 1 goes away, peer 2 becomes the download peer and thus queries the remote mempool.
        final SettableFuture<Void> p1CloseFuture = SettableFuture.create();
        peerOf(p1).addEventListener(new AbstractPeerEventListener() {
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
        peerGroup.stop();
    }

    @Test
    public void singleDownloadPeer2() throws Exception {
        // Check that we don't attempt multiple simultaneous block chain downloads, when adding a new peer in the
        // middle of an existing chain download.
        // Create a couple of peers.
        peerGroup.startAndWait();

        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);

        // Set up a little block chain.
        Block b1 = TestUtils.createFakeBlock(blockStore).block;
        Block b2 = TestUtils.makeSolvedTestBlock(b1);
        Block b3 = TestUtils.makeSolvedTestBlock(b2);

        // Expect a zero hash getblocks on p1. This is how the process starts.
        peerGroup.startBlockChainDownload(new AbstractPeerEventListener() {
        });
        GetBlocksMessage getblocks = (GetBlocksMessage) outbound(p1);
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // We give back an inv with some blocks in it.
        InventoryMessage inv = new InventoryMessage(params);
        inv.addBlock(b1);
        inv.addBlock(b2);
        inv.addBlock(b3);
        
        inbound(p1, inv);
        assertTrue(outbound(p1) instanceof GetDataMessage);
        // We hand back the first block.
        inbound(p1, b1);
        // Now we successfully connect to another peer. There should be no messages sent.
        InboundMessageQueuer p2 = connectPeer(2);
        Message message = (Message)outbound(p2);
        assertNull(message == null ? "" : message.toString(), message);
        peerGroup.stop();
    }

    @Test
    public void transactionConfidence() throws Exception {
        // Checks that we correctly count how many peers broadcast a transaction, so we can establish some measure of
        // its trustworthyness assuming an untampered with internet connection.
        peerGroup.startAndWait();

        final Transaction[] event = new Transaction[2];
        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onTransaction(Peer peer, Transaction t) {
                event[0] = t;
            }
        }, Threading.SAME_THREAD);

        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        InboundMessageQueuer p3 = connectPeer(3);

        Transaction tx = TestUtils.createFakeTx(params, Utils.toNanoCoins(20, 0), address);
        InventoryMessage inv = new InventoryMessage(params);
        inv.addTransaction(tx);
        
        // Peer 2 advertises the tx but does not receive it yet.
        inbound(p2, inv);
        assertTrue(outbound(p2) instanceof GetDataMessage);
        assertEquals(0, tx.getConfidence().numBroadcastPeers());
        assertTrue(peerGroup.getMemoryPool().maybeWasSeen(tx.getHash()));
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

        tx.getConfidence().addEventListener(new TransactionConfidence.Listener() {
            public void onConfidenceChanged(Transaction tx, TransactionConfidence.Listener.ChangeReason reason) {
                event[1] = tx;
            }
        });
        // A straggler reports in.
        inbound(p3, inv);
        pingAndWait(p3);
        Threading.waitForUserCode();
        assertEquals(tx, event[1]);
        assertEquals(3, tx.getConfidence().numBroadcastPeers());
        assertTrue(tx.getConfidence().wasBroadcastBy(peerOf(p3).getAddress()));
    }

    @Test
    public void testWalletCatchupTime() throws Exception {
        // Check the fast catchup time was initialized to something around the current runtime minus a week.
        // The wallet was already added to the peer in setup.
        final int WEEK = 86400 * 7;
        final long now = Utils.currentTimeMillis() / 1000;
        peerGroup.startAndWait();
        assertTrue(peerGroup.getFastCatchupTimeSecs() > now - WEEK - 10000);
        Wallet w2 = new Wallet(params);
        ECKey key1 = new ECKey();
        key1.setCreationTimeSeconds(now - 86400);  // One day ago.
        w2.addKey(key1);
        peerGroup.addWallet(w2);
        peerGroup.waitForJobQueue();
        assertEquals(peerGroup.getFastCatchupTimeSecs(), now - 86400 - WEEK);
        // Adding a key to the wallet should update the fast catchup time, but asynchronously and in the background
        // due to the need to avoid complicated lock inversions.
        ECKey key2 = new ECKey();
        key2.setCreationTimeSeconds(now - 100000);
        w2.addKey(key2);
        peerGroup.waitForJobQueue();
        assertEquals(peerGroup.getFastCatchupTimeSecs(), now - WEEK - 100000);
    }

    @Test
    public void noPings() throws Exception {
        peerGroup.startAndWait();
        peerGroup.setPingIntervalMsec(0);
        VersionMessage versionMessage = new VersionMessage(params, 2);
        versionMessage.clientVersion = FilteredBlock.MIN_PROTOCOL_VERSION;
        versionMessage.localServices = VersionMessage.NODE_NETWORK;
        connectPeer(1, versionMessage);
        peerGroup.waitForPeers(1).get();
        assertFalse(peerGroup.getConnectedPeers().get(0).getLastPingTime() < Long.MAX_VALUE);
    }

    @Test
    public void pings() throws Exception {
        peerGroup.startAndWait();
        peerGroup.setPingIntervalMsec(100);
        VersionMessage versionMessage = new VersionMessage(params, 2);
        versionMessage.clientVersion = FilteredBlock.MIN_PROTOCOL_VERSION;
        versionMessage.localServices = VersionMessage.NODE_NETWORK;
        InboundMessageQueuer p1 = connectPeer(1, versionMessage);
        Ping ping = (Ping) outbound(p1);
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
        peerGroup.startAndWait();
        VersionMessage versionMessage2 = new VersionMessage(params, 2);
        versionMessage2.clientVersion = FilteredBlock.MIN_PROTOCOL_VERSION;
        versionMessage2.localServices = VersionMessage.NODE_NETWORK;
        VersionMessage versionMessage3 = new VersionMessage(params, 3);
        versionMessage3.clientVersion = FilteredBlock.MIN_PROTOCOL_VERSION;
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
        assertEquals(c, peerGroup.getDownloadPeer());  // Switch to first peer advertising new height.
        // New peer with a higher protocol version but same chain height.
        //TODO: When PeerGroup.selectDownloadPeer.PREFERRED_VERSION is not equal to vMinRequiredProtocolVersion,
        // reenable this test
        /*VersionMessage versionMessage4 = new VersionMessage(params, 3);
        versionMessage4.clientVersion = 100000;
        versionMessage4.localServices = VersionMessage.NODE_NETWORK;
        InboundMessageQueuer d = connectPeer(5, versionMessage4);
        assertEquals(d.peer, peerGroup.getDownloadPeer());*/
    }

    @Test
    public void peerTimeoutTest() throws Exception {
        peerGroup.startAndWait();
        peerGroup.setConnectTimeoutMillis(100);

        final SettableFuture<Void> peerConnectedFuture = SettableFuture.create();
        final SettableFuture<Void> peerDisconnectedFuture = SettableFuture.create();
        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override public void onPeerConnected(Peer peer, int peerCount) {
                peerConnectedFuture.set(null);
            }
            @Override public void onPeerDisconnected(Peer peer, int peerCount) {
                peerDisconnectedFuture.set(null);
            }
        }, Threading.SAME_THREAD);
        connectPeerWithoutVersionExchange(0);
        Thread.sleep(50);
        assertFalse(peerConnectedFuture.isDone() || peerDisconnectedFuture.isDone());
        Thread.sleep(60);
        assertTrue(!peerConnectedFuture.isDone());
        assertTrue(!peerConnectedFuture.isDone() && peerDisconnectedFuture.isDone());
    }

    @Test
    public void peerPriority() throws Exception {
        final List<InetSocketAddress> addresses = Lists.newArrayList(
                new InetSocketAddress("localhost", 2000),
                new InetSocketAddress("localhost", 2001),
                new InetSocketAddress("localhost", 2002)
        );
        peerGroup.addEventListener(listener);
        peerGroup.addPeerDiscovery(new PeerDiscovery() {
            public InetSocketAddress[] getPeers(long unused, TimeUnit unused2) throws PeerDiscoveryException {
                return addresses.toArray(new InetSocketAddress[addresses.size()]);
            }

            public void shutdown() {
            }
        });
        peerGroup.setMaxConnections(3);
        Utils.setMockSleep(true);
        peerGroup.startAndWait();

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
        handleConnectToPeer(3);
        assertEquals(2003, connectedPeers.take().getAddress().getPort());

        stopPeerServer(1);
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort()); // peer died

        // Alternates trying two offline peers
        Utils.passMockSleep();
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());
        Utils.passMockSleep();
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort());
        Utils.passMockSleep();
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());
        Utils.passMockSleep();
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort());
        Utils.passMockSleep();
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());

        // Peer 2 comes online
        startPeerServer(2);
        Utils.passMockSleep();
        handleConnectToPeer(2);
        assertEquals(2002, connectedPeers.take().getAddress().getPort());

        stopPeerServer(2);
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort()); // peer died

        // Peer 2 is tried before peer 1, since it has a lower backoff due to recent success
        Utils.passMockSleep();
        assertEquals(2002, disconnectedPeers.take().getAddress().getPort());
        Utils.passMockSleep();
        assertEquals(2001, disconnectedPeers.take().getAddress().getPort());
    }

    @Test
    public void testBloomOnP2Pubkey() throws Exception {
        // Cover bug 513. When a relevant transaction with a p2pubkey output is found, the Bloom filter should be
        // recalculated to include that transaction hash but not re-broadcast as the remote nodes should have followed
        // the same procedure. However a new node that's connected should get the fresh filter.
        peerGroup.startAndWait();
        final ECKey key = wallet.getKeys().get(0);
        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        // Create a pay to pubkey tx.
        Transaction tx = TestUtils.createFakeTx(params, Utils.COIN, key);
        Transaction tx2 = new Transaction(params);
        tx2.addInput(tx.getOutput(0));
        TransactionOutPoint outpoint = tx2.getInput(0).getOutpoint();
        assertTrue(p1.lastReceivedFilter.contains(key.getPubKey()));
        assertFalse(p1.lastReceivedFilter.contains(tx.getHash().getBytes()));
        inbound(p1, tx);
        // p1 requests dep resolution, p2 is quiet.
        assertTrue(outbound(p1) instanceof GetDataMessage);
        final Sha256Hash dephash = tx.getInput(0).getOutpoint().getHash();
        final InventoryItem inv = new InventoryItem(InventoryItem.Type.Transaction, dephash);
        inbound(p1, new NotFoundMessage(params, ImmutableList.of(inv)));
        assertNull(outbound(p1));
        assertNull(outbound(p2));
        peerGroup.waitForJobQueue();
        // Now we connect p3 and there is a new bloom filter sent, that DOES match the relevant outpoint.
        InboundMessageQueuer p3 = connectPeer(3);
        assertTrue(p3.lastReceivedFilter.contains(key.getPubKey()));
        assertTrue(p3.lastReceivedFilter.contains(outpoint.bitcoinSerialize()));
    }

    @Test
    public void testBloomResendOnNewKey() throws Exception {
        // Check that when we add a new key to the wallet, the Bloom filter is re-calculated and re-sent.
        peerGroup.startAndWait();
        // Create a couple of peers.
        InboundMessageQueuer p1 = connectPeer(1);
        InboundMessageQueuer p2 = connectPeer(2);
        BloomFilter f1 = p1.lastReceivedFilter;
        BloomFilter f2 = p2.lastReceivedFilter;
        final ECKey key = new ECKey();
        wallet.addKey(key);
        peerGroup.waitForJobQueue();
        BloomFilter f3 = (BloomFilter) outbound(p1);
        BloomFilter f4 = (BloomFilter) outbound(p2);
        assertTrue(outbound(p1) instanceof MemoryPoolMessage);
        assertTrue(outbound(p2) instanceof MemoryPoolMessage);
        assertNotEquals(f1, f3);
        assertNotEquals(f2, f4);
        assertEquals(f3, f4);
        assertTrue(f3.contains(key.getPubKey()));
        assertTrue(f3.contains(key.getPubKeyHash()));
        assertFalse(f1.contains(key.getPubKey()));
        assertFalse(f1.contains(key.getPubKeyHash()));
    }
}
