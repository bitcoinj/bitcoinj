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
import com.google.bitcoin.store.MemoryBlockStore;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;

import static org.junit.Assert.*;

public class PeerGroupTest extends TestWithNetworkConnections {
    static final NetworkParameters params = NetworkParameters.unitTests();

    private PeerGroup peerGroup;
    private final BlockingQueue<Peer> disconnectedPeers = new LinkedBlockingQueue<Peer>();

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        blockStore = new MemoryBlockStore(params);
        BlockChain chain = new BlockChain(params, wallet, blockStore);
        peerGroup = new PeerGroup(params, chain, 1000);

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
        peerGroup.addWallet(wallet);
        MockNetworkConnection n1 = createMockNetworkConnection();
        Peer p1 = new Peer(params, blockChain, n1);
        MockNetworkConnection n2 = createMockNetworkConnection();
        Peer p2 = new Peer(params, blockChain, n2);
        peerGroup.start();
        peerGroup.addPeer(p1);
        peerGroup.addPeer(p2);

        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction t1 = TestUtils.createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addItem(new InventoryItem(InventoryItem.Type.Transaction, t1.getHash()));
        n1.inbound(inv);
        n2.inbound(inv);
        GetDataMessage getdata = (GetDataMessage) n1.outbound();
        assertNull(n2.outbound());  // Only one peer is used to download.
        n1.inbound(t1);
        n1.outbound();  // Wait for processing to complete.
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
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
        assertEquals(2, peerGroup.numPeers());

        // Set up a little block chain. We heard about b1 but not b2 (it is pending download). b3 is solved whilst we
        // are downloading the chain.
        Block b1 = TestUtils.createFakeBlock(params, blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(params, b1);
        Block b3 = TestUtils.makeSolvedTestBlock(params, b2);

        // Peer 1 and 2 receives an inv advertising a newly solved block.
        InventoryMessage inv = new InventoryMessage(params);
        inv.addItem(new InventoryItem(InventoryItem.Type.Block, b3.getHash()));
        n1.inbound(inv);
        n2.inbound(inv);

        // Only peer 1 tries to download it.
        assertTrue(n1.outbound() instanceof GetDataMessage);
        assertNull(n2.outbound());
        // Peer 1 goes away.
        disconnectAndWait(n1);
        // Peer 2 fetches it next time it hears an inv (should it fetch immediately?).
        n2.inbound(inv);
        assertTrue(n2.outbound() instanceof GetDataMessage);
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
        inv.addItem(new InventoryItem(InventoryItem.Type.Block, b1.getHash()));
        inv.addItem(new InventoryItem(InventoryItem.Type.Block, b2.getHash()));
        inv.addItem(new InventoryItem(InventoryItem.Type.Block, b3.getHash()));
        n1.inbound(inv);
        // Peer creates a getdata message.
        @SuppressWarnings("unused")
        GetDataMessage getdata = (GetDataMessage) n1.outbound();
        // We hand back the first block.
        n1.inbound(b1);

        // Now we successfully connect to another peer. There should be no messages sent.
        peerGroup.addPeer(p2);
        Message message = n2.outbound();
        assertNull(message == null ? "" : message.toString(), message);
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
