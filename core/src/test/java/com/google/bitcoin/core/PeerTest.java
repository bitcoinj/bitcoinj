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

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

public class PeerTest extends TestWithNetworkConnections {
    private Peer peer;
    private MockNetworkConnection conn;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        conn = createMockNetworkConnection();
        peer = new Peer(unitTestParams, blockChain, conn);
        peer.addWallet(wallet);
    }

    @Test
    public void testAddEventListener() {
        PeerEventListener listener = new AbstractPeerEventListener();
        peer.addEventListener(listener);
        assertTrue(peer.removeEventListener(listener));
        assertFalse(peer.removeEventListener(listener));
    }
    
    // Check that the connection is shut down if there's a read error and that the exception is propagated.
    @Test
    public void testRun_exception() throws Exception {
        conn.exceptionOnRead(new IOException("done"));
        try {
            peer.run();
            fail("did not throw");
        } catch (PeerException e) {
            assertTrue(e.getCause() instanceof IOException);
        }
    }
    
    @Test
    public void testRun_protocolException() throws Exception {
        conn.exceptionOnRead(new ProtocolException("proto"));
        try {
            peer.run();
            fail("did not throw");
        } catch (PeerException e) {
            // expected
            assertTrue(e.toString(), e.getCause() instanceof ProtocolException);
        }
    }

    // Check that it runs through the event loop and shut down correctly
    @Test
    public void shutdown() throws Exception {
        runPeer(peer, conn);
    }

    // Check that when we receive a block that does not connect to our chain, we send a getblocks to fetch
    // the intermediates.
    @Test
    public void unconnectedBlock() throws Exception {
        Block b1 = TestUtils.createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(unitTestParams, b1);
        blockChain.add(b2);  // b2 is top block.
        Block b3 = TestUtils.makeSolvedTestBlock(unitTestParams, b2);
        Block b4 = TestUtils.makeSolvedTestBlock(unitTestParams, b3);
        conn.inbound(b4);
        runPeer(peer, conn);
        GetBlocksMessage getblocks = (GetBlocksMessage) conn.popOutbound();
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        // Locator contains top block (b2), prev hash (b1), the genesis block.
        expectedLocator.add(b2.getHash());
        expectedLocator.add(b2.getPrevBlockHash());
        expectedLocator.add(unitTestParams.genesisBlock.getHash());
        assertEquals(expectedLocator, getblocks.getLocator());
        assertEquals(b4.getHash(), getblocks.getStopHash());
    }

    // Check that an inventory tickle is processed correctly when downloading missing blocks is active.
    @Test
    public void invTickle() throws Exception {
        Block b1 = TestUtils.createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        // Make a missing block.
        Block b2 = TestUtils.makeSolvedTestBlock(unitTestParams, b1);
        Block b3 = TestUtils.makeSolvedTestBlock(unitTestParams, b2);
        conn.inbound(b3);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b3.getHash());
        inv.addItem(item);
        conn.inbound(inv);
        runPeer(peer, conn);
        GetBlocksMessage getblocks = (GetBlocksMessage) conn.popOutbound();
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.genesisBlock.getHash());
        
        assertEquals(getblocks.getLocator(), expectedLocator);
        assertEquals(getblocks.getStopHash(), b3.getHash());
    }

    // Check that an inv to a peer that is not set to download missing blocks does nothing.
    @Test
    public void invNoDownload() throws Exception {
        // Don't download missing blocks.
        peer.setDownloadData(false);

        // Make a missing block that we receive.
        Block b1 = TestUtils.createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(unitTestParams, b1);

        // Receive an inv.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b2.getHash());
        inv.addItem(item);
        conn.inbound(inv);
        // Peer does nothing with it.
        runPeer(peer, conn);
        Message message = conn.popOutbound();
        assertNull(message != null ? message.toString() : "", message);
    }

    @Test
    public void invDownloadTx() throws Exception {
        peer.setDownloadData(true);
        // Make a transaction and tell the peer we have it.
        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction tx = TestUtils.createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Transaction, tx.getHash());
        inv.addItem(item);
        conn.inbound(inv);
        // Peer hasn't seen it before, so will ask for it.
        runPeer(peer, conn);
        conn.popInbound(); // Pop the disconnect marker so we can reuse
        
        GetDataMessage message = (GetDataMessage) conn.popOutbound();
        assertEquals(1, message.getItems().size());
        assertEquals(tx.getHash(), message.getItems().get(0).hash);
        conn.inbound(tx);
        runPeer(peer, conn);
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void invDownloadTxMultiPeer() throws Exception {
        // Check co-ordination of which peer to download via the memory pool.
        MemoryPool pool = new MemoryPool();
        peer.setMemoryPool(pool);

        MockNetworkConnection conn2 = createMockNetworkConnection();
        Peer peer2 = new Peer(unitTestParams, blockChain, conn2);
        peer2.addWallet(wallet);
        peer2.setMemoryPool(pool);

        // Make a tx and advertise it to one of the peers.
        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction tx = TestUtils.createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Transaction, tx.getHash());
        inv.addItem(item);

        conn.inbound(inv);
        runPeer(peer, conn);
        conn.popInbound();  // Remove the disconnect marker.

        // We got a getdata message.
        GetDataMessage message = (GetDataMessage) conn.popOutbound();
        assertEquals(1, message.getItems().size());
        assertEquals(tx.getHash(), message.getItems().get(0).hash);
        assertTrue(pool.maybeWasSeen(tx.getHash()));

        // Advertising to peer2 results in no getdata message.
        conn2.inbound(inv);
        runPeer(peer2, conn2);
        assertNull(conn.popOutbound());
    }

    // Check that inventory message containing blocks we want is processed correctly.
    @Test
    public void newBlock() throws Exception {
        PeerEventListener listener = control.createMock(PeerEventListener.class);
        peer.addEventListener(listener);

        Block b1 = TestUtils.createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(unitTestParams, b1);
        conn.setVersionMessageForHeight(unitTestParams, 100);
        // Receive notification of a new block.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b2.getHash());
        inv.addItem(item);
        conn.inbound(inv);
        // Response to the getdata message.
        conn.inbound(b2);

        expect(listener.onPreMessageReceived(eq(peer), eq(inv))).andReturn(inv);
        expect(listener.onPreMessageReceived(eq(peer), eq(b2))).andReturn(b2);
        listener.onBlocksDownloaded(eq(peer), anyObject(Block.class), eq(98));
        expectLastCall();

        control.replay();
        runPeer(peer, conn);
        control.verify();
        
        GetDataMessage getdata = (GetDataMessage) conn.popOutbound();
        List<InventoryItem> items = getdata.getItems();
        assertEquals(1, items.size());
        assertEquals(b2.getHash(), items.get(0).hash);
        assertEquals(InventoryItem.Type.Block, items.get(0).type);
    }

    // Check that it starts downloading the block chain correctly on request.
    @Test
    public void startBlockChainDownload() throws Exception {
        PeerEventListener listener = control.createMock(PeerEventListener.class);
        peer.addEventListener(listener);

        Block b1 = TestUtils.createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(unitTestParams, b1);
        blockChain.add(b2);
        conn.setVersionMessageForHeight(unitTestParams, 100);

        listener.onChainDownloadStarted(peer, 98);
        expectLastCall();

        control.replay();
        peer.startBlockChainDownload();
        runPeer(peer, conn);
        control.verify();
        
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b2.getHash());
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.genesisBlock.getHash());

        GetBlocksMessage message = (GetBlocksMessage) conn.popOutbound();
        assertEquals(message.getLocator(), expectedLocator);
        assertEquals(message.getStopHash(), Sha256Hash.ZERO_HASH);
    }

    @Test
    public void getBlock() throws Exception {
        Block b1 = TestUtils.createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = TestUtils.makeSolvedTestBlock(unitTestParams, b1);
        Block b3 = TestUtils.makeSolvedTestBlock(unitTestParams, b2);
        conn.setVersionMessageForHeight(unitTestParams, 100);
        runPeerAsync(peer, conn);
        // Request the block.
        Future<Block> resultFuture = peer.getBlock(b3.getHash());
        assertFalse(resultFuture.isDone());
        // Peer asks for it.
        GetDataMessage message = (GetDataMessage) conn.outbound();
        assertEquals(message.getItems().get(0).hash, b3.getHash());
        assertFalse(resultFuture.isDone());
        // Peer receives it.
        conn.inbound(b3);
        Block b = resultFuture.get();
        assertEquals(b, b3);
        conn.disconnect();
    }

    @Test
    public void fastCatchup() throws Exception {
        // Check that blocks before the fast catchup point are retrieved using getheaders, and after using getblocks.
        // This test is INCOMPLETE because it does not check we handle >2000 blocks correctly.
        Block b1 = TestUtils.createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b2 = TestUtils.makeSolvedTestBlock(unitTestParams, b1);
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b3 = TestUtils.makeSolvedTestBlock(unitTestParams, b2);
        Utils.rollMockClock(60 * 10);
        Block b4 = TestUtils.makeSolvedTestBlock(unitTestParams, b3);
        conn.setVersionMessageForHeight(unitTestParams, 4);
        // Request headers until the last 2 blocks.
        peer.setFastCatchupTime((Utils.now().getTime() / 1000) - (600*2) + 1);
        runPeerAsync(peer, conn);
        peer.startBlockChainDownload();
        GetHeadersMessage getheaders = (GetHeadersMessage) conn.outbound();
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.genesisBlock.getHash());
        assertEquals(getheaders.getLocator(), expectedLocator);
        assertEquals(getheaders.getStopHash(), Sha256Hash.ZERO_HASH);
        // Now send all the headers.
        HeadersMessage headers = new HeadersMessage(unitTestParams, b2.cloneAsHeader(),
                b3.cloneAsHeader(), b4.cloneAsHeader());
        // We expect to be asked for b3 and b4 again, but this time, with a body.
        expectedLocator.clear();
        expectedLocator.add(b2.getHash());
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.genesisBlock.getHash());
        GetBlocksMessage getblocks = (GetBlocksMessage) conn.exchange(headers);
        assertEquals(expectedLocator, getblocks.getLocator());
        assertEquals(b3.getHash(), getblocks.getStopHash());
        // We're supposed to get an inv here.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addItem(new InventoryItem(InventoryItem.Type.Block, b3.getHash()));
        GetDataMessage getdata = (GetDataMessage) conn.exchange(inv);
        assertEquals(b3.getHash(), getdata.getItems().get(0).hash);
        // All done.
        assertEquals(null, conn.exchange(b3));
    }
}
