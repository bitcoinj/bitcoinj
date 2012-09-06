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

import com.google.bitcoin.core.PeerGroup.PeerGroupThread;
import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import org.easymock.EasyMock;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.channel.*;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Semaphore;

import static org.junit.Assert.*;

public class PeerGroupTest extends TestWithNetworkConnections {
    static final NetworkParameters params = NetworkParameters.unitTests();

    private PeerGroup peerGroup;

    private VersionMessage remoteVersionMessage;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        remoteVersionMessage = new VersionMessage(params, 1);
        
        ClientBootstrap bootstrap = new ClientBootstrap(new ChannelFactory() {
            public void releaseExternalResources() {}
            public Channel newChannel(ChannelPipeline pipeline) {
                ChannelSink sink = new FakeChannelSink();
                return new FakeChannel(this, pipeline, sink);
            }
        });
        bootstrap.setPipelineFactory(new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                VersionMessage ver = new VersionMessage(params, 1);
                ChannelPipeline p = Channels.pipeline();
                
                Peer peer = new Peer(params, blockChain, ver);
                peer.addLifecycleListener(peerGroup.startupListener);
                p.addLast("peer", peer.getHandler());
                return p;
            }

        });
        peerGroup = new PeerGroup(params, blockChain, 1, bootstrap);
        peerGroup.addWallet(wallet);
    }

    @Test
    public void listener() throws Exception {
        AbstractPeerEventListener listener = new AbstractPeerEventListener() {
        };
        peerGroup.addEventListener(listener);
        assertTrue(peerGroup.removeEventListener(listener));
    }

    @Test
    public void peerDiscoveryPolling() throws Exception {
        // Check that if peer discovery fails, we keep trying until we have some nodes to talk with.
        final Semaphore sem = new Semaphore(0);
        final boolean[] result = new boolean[1];
        result[0] = false;
        peerGroup.addPeerDiscovery(new PeerDiscovery() {
            public InetSocketAddress[] getPeers() throws PeerDiscoveryException {
                if (result[0] == false) {
                    // Pretend we are not connected to the internet.
                    result[0] = true;
                    throw new PeerDiscoveryException("test failure");
                } else {
                    // Return a bogus address.
                    sem.release();
                    return new InetSocketAddress[]{new InetSocketAddress("localhost", 0)};
                }
            }
            public void shutdown() {
            }
        });
        peerGroup.start();
        sem.acquire();
        // Check that we did indeed throw an exception. If we got here it means we threw and then PeerGroup tried
        // again a bit later.
        assertTrue(result[0]);
        peerGroup.stop();
    }

    @Test
    public void receiveTxBroadcast() throws Exception {
        // Check that when we receive transactions on all our peers, we do the right thing.
        peerGroup.start();

        // Create a couple of peers.
        peerGroup.addWallet(wallet);
        FakeChannel p1 = connectPeer(1);
        FakeChannel p2 = connectPeer(2);
        
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

        inbound(p1, inv);
        assertTrue(outbound(p1) instanceof GetDataMessage);
        inbound(p2, inv);
        assertNull(outbound(p2));  // Only one peer is used to download.
        inbound(p1, t1);
        assertNull(outbound(p2));
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        peerGroup.stop();
    }

    private FakeChannel connectPeer(int id) {
        return connectPeer(id, remoteVersionMessage);
    }

    private FakeChannel connectPeer(int id, VersionMessage versionMessage) {
        InetSocketAddress remoteAddress = new InetSocketAddress("127.0.0.1", 2000 + id);
        FakeChannel p =
            (FakeChannel) peerGroup.connectTo(remoteAddress).getChannel();
        assertTrue(p.nextEvent() instanceof ChannelStateEvent);
        inbound(p, versionMessage);
        return p;
    }

    @Test
    public void singleDownloadPeer1() throws Exception {
        // Check that we don't attempt to retrieve blocks on multiple peers.
        peerGroup.start();

        // Create a couple of peers.
        FakeChannel p1 = connectPeer(1);
        FakeChannel p2 = connectPeer(2);
        assertEquals(2, peerGroup.numConnectedPeers());

        // Set up a little block chain. We heard about b1 but not b2 (it is pending download). b3 is solved whilst we
        // are downloading the chain.
        Block b1 = TestUtils.createFakeBlock(params, blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(params, b1);
        Block b3 = TestUtils.makeSolvedTestBlock(params, b2);

        // Peer 1 and 2 receives an inv advertising a newly solved block.
        InventoryMessage inv = new InventoryMessage(params);
        inv.addBlock(b3);
        // Only peer 1 tries to download it.
        inbound(p1, inv);
        
        assertTrue(outbound(p1) instanceof GetDataMessage);
        assertNull(outbound(p2));
        // Peer 1 goes away.
        closePeer(peerOf(p1));
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
        peerGroup.start();

        // Create a couple of peers.
        FakeChannel p1 = connectPeer(1);

        // Set up a little block chain.
        Block b1 = TestUtils.createFakeBlock(params, blockStore).block;
        Block b2 = TestUtils.makeSolvedTestBlock(params, b1);
        Block b3 = TestUtils.makeSolvedTestBlock(params, b2);

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
        FakeChannel p2 = connectPeer(2);
        Message message = (Message)outbound(p2);
        assertNull(message == null ? "" : message.toString(), message);
        peerGroup.stop();
    }

    @Test
    public void transactionConfidence() throws Exception {
        // Checks that we correctly count how many peers broadcast a transaction, so we can establish some measure of
        // its trustworthyness assuming an untampered with internet connection.
        final Transaction[] event = new Transaction[2];
        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onTransaction(Peer peer, Transaction t) {
                event[0] = t;
            }
        });

        FakeChannel p1 = connectPeer(1);
        FakeChannel p2 = connectPeer(2);
        FakeChannel p3 = connectPeer(3);

        Transaction tx = TestUtils.createFakeTx(params, Utils.toNanoCoins(20, 0), address);
        InventoryMessage inv = new InventoryMessage(params);
        inv.addTransaction(tx);
        
        // Peer 2 advertises the tx but does not download it.
        inbound(p2, inv);
        assertTrue(outbound(p2) instanceof GetDataMessage);
        assertEquals(0, tx.getConfidence().numBroadcastPeers());
        assertTrue(peerGroup.getMemoryPool().maybeWasSeen(tx.getHash()));
        assertNull(event[0]);
                // Peer 1 advertises the tx, we don't do anything as it's already been requested.
        inbound(p1, inv);
        assertNull(outbound(p1));
        inbound(p2, tx);
        assertNull(outbound(p2));
        tx = event[0];  // We want to use the canonical copy delivered by the PeerGroup from now on.
        assertNotNull(tx);
        event[0] = null;

        // Peer 1 (the download peer) advertises the tx, we download it.
        inbound(p1, inv);  // returns getdata
        inbound(p1, tx);   // returns nothing after a queue drain.
        // Two peers saw this tx hash.
        assertEquals(2, tx.getConfidence().numBroadcastPeers());
        assertTrue(tx.getConfidence().getBroadcastBy().contains(peerOf(p1).getAddress()));
        assertTrue(tx.getConfidence().getBroadcastBy().contains(peerOf(p2).getAddress()));

        tx.getConfidence().addEventListener(new TransactionConfidence.Listener() {
            public void onConfidenceChanged(Transaction tx) {
                event[1] = tx;
            }
        });
        // A straggler reports in.
        inbound(p3, inv);
        assertEquals(tx, event[1]);
        assertEquals(3, tx.getConfidence().numBroadcastPeers());
        assertTrue(tx.getConfidence().getBroadcastBy().contains(peerOf(p3).getAddress()));
    }

    @Test
    public void announce() throws Exception {
        // Make sure we can create spends, and that they are announced. Then do the same with offline mode.

        // Set up connections and block chain.
        FakeChannel p1 = connectPeer(1, new VersionMessage(params, 2));
        FakeChannel p2 = connectPeer(2);
        
        PeerGroupThread peerGroupThread = control.createMock(PeerGroupThread.class);
        peerGroup.mockStart(peerGroupThread);
        peerGroupThread.interrupt();
        EasyMock.expectLastCall();
        
        control.replay();

        peerGroup.setMinBroadcastConnections(2);

        // Send ourselves a bit of money.
        Block b1 = TestUtils.makeSolvedTestBlock(params, blockStore, address);
        inbound(p1, b1);
        assertNull(outbound(p1));

        assertEquals(Utils.toNanoCoins(50, 0), wallet.getBalance());

        // Check that the wallet informs us of changes in confidence as the transaction ripples across the network.
        final Transaction[] transactions = new Transaction[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
                transactions[0] = tx;
            }
        });

        // Now create a spend, and expect the announcement on p1.
        Address dest = new ECKey().toAddress(params);
        Wallet.SendResult sendResult = wallet.sendCoins(peerGroup, dest, Utils.toNanoCoins(1, 0));
        assertNotNull(sendResult.tx);
        assertFalse(sendResult.broadcastComplete.isDone());
        assertEquals(transactions[0], sendResult.tx);
        assertEquals(transactions[0].getConfidence().numBroadcastPeers(), 1);
        transactions[0] = null;
        Transaction t1 = (Transaction) outbound(p1);
        assertNotNull(t1);
        // 49 BTC in change.
        assertEquals(Utils.toNanoCoins(49, 0), t1.getValueSentToMe(wallet));
        // The future won't complete until it's heard back from the network on p2.
        InventoryMessage inv = new InventoryMessage(params);
        inv.addTransaction(t1);
        inbound(p2, inv);
        assertTrue(sendResult.broadcastComplete.isDone());
        assertEquals(transactions[0], sendResult.tx);
        assertEquals(transactions[0].getConfidence().numBroadcastPeers(), 2);
        // Confirm it.
        Block b2 = TestUtils.createFakeBlock(params, blockStore, t1).block;
        inbound(p1, b2);
        assertNull(outbound(p1));
        
        // Do the same thing with an offline transaction.
        peerGroup.removeWallet(wallet);
        Transaction t3 = wallet.sendCoinsOffline(Wallet.SendRequest.to(dest, Utils.toNanoCoins(2, 0)));
        assertNull(outbound(p1));  // Nothing sent.
        // Add the wallet to the peer group (simulate initialization). Transactions should be announced.
        peerGroup.addWallet(wallet);
        // Transaction announced to the first peer.
        InventoryMessage inv1 = (InventoryMessage) outbound(p1);
        assertEquals(t3.getHash(), inv1.getItems().get(0).hash);
        // Peer asks for the transaction, and get it.
        GetDataMessage getdata = new GetDataMessage(params);
        getdata.addItem(inv1.getItems().get(0));
        inbound(p1, getdata);
        Transaction t4 = (Transaction) outbound(p1);
        assertEquals(t3, t4);

        FakeChannel p3 = connectPeer(3);
        assertTrue(outbound(p3) instanceof InventoryMessage);
        peerGroup.stop();
        control.verify();
    }

    @Test
    public void testWalletCatchupTime() throws Exception {
        // Check the fast catchup time was initialized to something around the current runtime. The wallet was
        // already added to the peer in setup.
        long time = new Date().getTime() / 1000;
        assertTrue(peerGroup.getFastCatchupTimeSecs() > time - 10000);
        Wallet w2 = new Wallet(params);
        ECKey key1 = new ECKey();
        key1.setCreationTimeSeconds(time - 86400);  // One day ago.
        w2.addKey(key1);
        peerGroup.addWallet(w2);
        assertEquals(peerGroup.getFastCatchupTimeSecs(), time - 86400);
        // Adding a key to the wallet should update the fast catchup time.
        ECKey key2 = new ECKey();
        key2.setCreationTimeSeconds(time - 100000);
        w2.addKey(key2);
        assertEquals(peerGroup.getFastCatchupTimeSecs(), time - 100000);
    }
    
    @Test
    public void testSetMaximumConnections() {
        peerGroup.setMaxConnections(1);
        peerGroup.setMaxConnections(4);
        peerGroup.setMaxConnections(10);
        peerGroup.setMaxConnections(1);
    }
}
