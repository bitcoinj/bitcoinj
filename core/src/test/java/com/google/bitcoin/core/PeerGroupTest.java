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

import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;

import static org.junit.Assert.*;

public class PeerGroupTest extends TestWithNetworkConnections {
    static final NetworkParameters params = NetworkParameters.unitTests();

    private PeerGroup peerGroup;
    private final BlockingQueue<Peer> disconnectedPeers = new LinkedBlockingQueue<Peer>();

    // FIXME Some tests here are non-deterministic due to the peers running on a separate thread.
    // FIXME Fix this by having exchangeAndWait and inboundAndWait methods in MockNetworkConnection. 
    
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        peerGroup = new PeerGroup(params, blockChain, 1000);
        peerGroup.addWallet(wallet);

        // Support for testing disconnect events in a non-racy manner.
        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                super.onPeerDisconnected(peer, peerCount);
                try {
                    disconnectedPeers.put(peer);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        });
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

        // Create a couple of peers.
        MockNetworkConnection n1 = createMockNetworkConnection();
        Peer p1 = new Peer(params, blockChain, n1);
        MockNetworkConnection n2 = createMockNetworkConnection();
        Peer p2 = new Peer(params, blockChain, n2);
        peerGroup.start();
        peerGroup.addPeer(p1);
        peerGroup.addPeer(p2);
        
        // Check the peer accessors.
        assertEquals(2, peerGroup.numConnectedPeers());
        Set<Peer> tmp = new HashSet<Peer>(peerGroup.getConnectedPeers());
        Set<Peer> expectedPeers = new HashSet<Peer>();
        expectedPeers.add(p1);
        expectedPeers.add(p2);
        assertEquals(tmp, expectedPeers);

        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction t1 = TestUtils.createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addTransaction(t1);
        assertTrue(n1.exchange(inv) instanceof GetDataMessage);
        assertNull(n2.exchange(inv));  // Only one peer is used to download.
        assertNull(n1.exchange(t1));
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
        peerGroup.stop();
    }

    @Test
    public void singleDownloadPeer1() throws Exception {
        // Check that we don't attempt to retrieve blocks on multiple peers.

        // Create a couple of peers.
        MockNetworkConnection n1 = createMockNetworkConnection();
        Peer p1 = new Peer(params, blockChain, n1);
        MockNetworkConnection n2 = createMockNetworkConnection();
        Peer p2 = new Peer(params, blockChain, n2);
        peerGroup.start();
        peerGroup.addPeer(p1);
        peerGroup.addPeer(p2);
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
        assertTrue(n1.exchange(inv) instanceof GetDataMessage);
        assertNull(n2.exchange(inv));
        // Peer 1 goes away.
        disconnectAndWait(n1);
        // Peer 2 fetches it next time it hears an inv (should it fetch immediately?).
        assertTrue(n2.exchange(inv) instanceof GetDataMessage);
        peerGroup.stop();
    }

    @Test
    public void singleDownloadPeer2() throws Exception {
        // Check that we don't attempt multiple simultaneous block chain downloads, when adding a new peer in the
        // middle of an existing chain download.
        // Create a couple of peers.
        MockNetworkConnection n1 = createMockNetworkConnection();
        Peer p1 = new Peer(params, blockChain, n1);
        MockNetworkConnection n2 = createMockNetworkConnection();
        Peer p2 = new Peer(params, blockChain, n2);
        peerGroup.start();
        peerGroup.addPeer(p1);

        // Set up a little block chain.
        Block b1 = TestUtils.createFakeBlock(params, blockStore).block;
        Block b2 = TestUtils.makeSolvedTestBlock(params, b1);
        Block b3 = TestUtils.makeSolvedTestBlock(params, b2);
        n1.setVersionMessageForHeight(params, 3);
        n2.setVersionMessageForHeight(params, 3);

        // Expect a zero hash getblocks on p1. This is how the process starts.
        peerGroup.startBlockChainDownload(new AbstractPeerEventListener() {
        });
        GetBlocksMessage getblocks = (GetBlocksMessage) n1.outbound();
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // We give back an inv with some blocks in it.
        InventoryMessage inv = new InventoryMessage(params);
        inv.addBlock(b1);
        inv.addBlock(b2);
        inv.addBlock(b3);
        assertTrue(n1.exchange(inv) instanceof GetDataMessage);
        // We hand back the first block.
        n1.inbound(b1);
        // Now we successfully connect to another peer. There should be no messages sent.
        peerGroup.addPeer(p2);
        Message message = n2.outbound();
        assertNull(message == null ? "" : message.toString(), message);
        peerGroup.stop();
    }
    
    @Test
    public void transactionConfidence() throws Exception {
        // Checks that we correctly count how many peers broadcast a transaction, so we can establish some measure of
        // its trustworthyness assuming an untampered with internet connection. This is done via the MemoryPool class.
        MockNetworkConnection n1 = createMockNetworkConnection();
        Peer p1 = new Peer(params, blockChain, n1);
        MockNetworkConnection n2 = createMockNetworkConnection();
        Peer p2 = new Peer(params, blockChain, n2);
        MockNetworkConnection n3 = createMockNetworkConnection();
        Peer p3 = new Peer(params, blockChain, n3);

        final Transaction[] event = new Transaction[2];
        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onTransaction(Peer peer, Transaction t) {
                event[0] = t;
            }
        });

        peerGroup.start();
        peerGroup.addPeer(p1);
        peerGroup.addPeer(p2);
        peerGroup.addPeer(p3);

        Transaction tx = TestUtils.createFakeTx(params, Utils.toNanoCoins(20, 0), address);
        InventoryMessage inv = new InventoryMessage(params);
        inv.addTransaction(tx);
        
        // Peer 2 advertises the tx and requests a download of it, because it came first.
        assertTrue(n2.exchange(inv) instanceof GetDataMessage);
        assertTrue(peerGroup.getMemoryPool().maybeWasSeen(tx.getHash()));
        assertEquals(null, event[0]);
        // Peer 1 advertises the tx, we don't do anything as it's already been requested.
        assertNull(n1.exchange(inv));
        assertNull(n2.exchange(tx));
        tx = event[0];  // We want to use the canonical copy delivered by the PeerGroup from now on.
        event[0] = null;
        // Two peers saw this tx hash.
        assertEquals(2, tx.getConfidence().numBroadcastPeers());
        assertTrue(tx.getConfidence().getBroadcastBy().contains(n1.getPeerAddress()));
        assertTrue(tx.getConfidence().getBroadcastBy().contains(n2.getPeerAddress()));
        tx.getConfidence().addEventListener(new TransactionConfidence.Listener() {
            public void onConfidenceChanged(Transaction tx) {
                event[1] = tx;
            }
        });
        // A straggler reports in.
        n3.exchange(inv);
        assertEquals(tx, event[1]);
        assertEquals(3, tx.getConfidence().numBroadcastPeers());
        assertTrue(tx.getConfidence().getBroadcastBy().contains(n3.getPeerAddress()));
    }

    @Test
    public void announce() throws Exception {
        // Make sure we can create spends, and that they are announced. Then do the same with offline mode.

        // Set up connections and block chain.
        MockNetworkConnection n1 = createMockNetworkConnection();
        Peer p1 = new Peer(params, blockChain, n1);
        MockNetworkConnection n2 = createMockNetworkConnection();
        Peer p2 = new Peer(params, blockChain, n2);
        peerGroup.start();
        peerGroup.addPeer(p1);
        peerGroup.addPeer(p2);

        // Send ourselves a bit of money.
        Block b1 = TestUtils.makeSolvedTestBlock(params, blockStore, address);
        n1.setVersionMessageForHeight(params, 2);
        n1.exchange(b1);
        assertEquals(Utils.toNanoCoins(50, 0), wallet.getBalance());

        // Now create a spend, and expect the announcement.
        Address dest = new ECKey().toAddress(params);
        assertNotNull(wallet.sendCoins(peerGroup, dest, Utils.toNanoCoins(1, 0)));
        Transaction t1 = (Transaction) n1.outbound();
        assertNotNull(t1);
        // 49 BTC in change.
        assertEquals(Utils.toNanoCoins(49, 0), t1.getValueSentToMe(wallet));
        Transaction t2 = (Transaction) n2.outbound();
        assertEquals(t1, t2);
        Block b2 = TestUtils.createFakeBlock(params, blockStore, t1).block;
        n1.exchange(b2);
        
        // Do the same thing with an offline transaction.
        peerGroup.removeWallet(wallet);
        Transaction t3 = wallet.sendCoinsOffline(dest, Utils.toNanoCoins(2, 0));
        assertNull(n1.outbound());  // Nothing sent.
        // Add the wallet to the peer group (simulate initialization). Transactions should be announced.
        peerGroup.addWallet(wallet);
        // Transaction announced on the peers.
        InventoryMessage inv1 = (InventoryMessage) n1.outbound();
        InventoryMessage inv2 = (InventoryMessage) n2.outbound();
        assertEquals(t3.getHash(), inv1.getItems().get(0).hash);
        assertEquals(t3.getHash(), inv2.getItems().get(0).hash);
        // Peers ask for the transaction, and get it.
        GetDataMessage getdata = new GetDataMessage(params);
        getdata.addItem(inv1.getItems().get(0));
        Transaction t4 = (Transaction) n1.exchange(getdata);
        assertEquals(t3, t4);
        assertEquals(t3, n2.exchange(getdata));
        MockNetworkConnection n3 = createMockNetworkConnection();
        Peer p3 = new Peer(params, blockChain, n3);
        peerGroup.addPeer(p3);
        assertTrue(n3.outbound() instanceof InventoryMessage);
        peerGroup.stop();
    }
    
    private void disconnectAndWait(MockNetworkConnection conn) throws IOException, InterruptedException {
        conn.disconnect();
        disconnectedPeers.take();
    }
    
    @Test
    public void testSetMaximumConnections() {
        peerGroup.setMaxConnections(1);
        peerGroup.setMaxConnections(4);
        peerGroup.setMaxConnections(10);
        peerGroup.setMaxConnections(1);
    }
}
