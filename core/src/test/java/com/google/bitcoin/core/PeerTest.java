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

import com.google.bitcoin.core.Peer.PeerHandler;
import org.easymock.Capture;
import org.jboss.netty.channel.*;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;

import static com.google.bitcoin.core.TestUtils.*;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

public class PeerTest extends TestWithNetworkConnections {
    private Peer peer;
    private Capture<DownstreamMessageEvent> event;
    private PeerHandler handler;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        VersionMessage ver = new VersionMessage(unitTestParams, 100);
        peer = new Peer(unitTestParams, blockChain, ver);
        peer.addWallet(wallet);
        handler = peer.getHandler();
        event = new Capture<DownstreamMessageEvent>(); 
        pipeline.sendDownstream(capture(event));
        expectLastCall().anyTimes();
    }

    private void connect() throws Exception {
        connect(handler, channel, ctx);
    }
    
    private void connect(PeerHandler handler, Channel channel, ChannelHandlerContext ctx) throws Exception {
        handler.connectRequested(ctx, new UpstreamChannelStateEvent(channel, ChannelState.CONNECTED, socketAddress));
        VersionMessage peerVersion = new VersionMessage(unitTestParams, 110);
        DownstreamMessageEvent versionEvent = 
            new DownstreamMessageEvent(channel, Channels.future(channel), peerVersion, null);
        handler.messageReceived(ctx, versionEvent);
    }

    @Test
    public void testAddEventListener() throws Exception {
        control.replay();

        connect();
        PeerEventListener listener = new AbstractPeerEventListener();
        peer.addEventListener(listener);
        assertTrue(peer.removeEventListener(listener));
        assertFalse(peer.removeEventListener(listener));
    }
    
    // Check that the connection is shut down if there's a read error and that the exception is propagated.
    @Test
    public void testRun_exception() throws Exception {
        expect(channel.close()).andReturn(null);
        control.replay();
        
        handler.exceptionCaught(ctx,
                new DefaultExceptionEvent(channel, new IOException("proto")));

        control.verify();
    }
    
    @Test
    public void testRun_protocolException() throws Exception {
        expect(channel.close()).andReturn(null);
        replay(channel);
        handler.exceptionCaught(ctx,
                new DefaultExceptionEvent(channel, new ProtocolException("proto")));
        verify(channel);
    }

    // Check that it runs through the event loop and shut down correctly
    @Test
    public void shutdown() throws Exception {
        closePeer(peer);
    }

    @Test
    public void chainDownloadEnd2End() throws Exception {
        // A full end-to-end test of the chain download process, with a new block being solved in the middle.
        Block b1 = createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(unitTestParams, b1);
        Block b3 = makeSolvedTestBlock(unitTestParams, b2);
        Block b4 = makeSolvedTestBlock(unitTestParams, b3);
        Block b5 = makeSolvedTestBlock(unitTestParams, b4);

        control.replay();
        
        connect();
        
        peer.startBlockChainDownload();
        GetBlocksMessage getblocks = (GetBlocksMessage)outbound();
        assertEquals(blockStore.getChainHead().getHeader().getHash(), getblocks.getLocator().get(0));
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // Remote peer sends us an inv with some blocks.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addBlock(b2);
        inv.addBlock(b3);
        // We do a getdata on them.
        inbound(peer, inv);
        GetDataMessage getdata = (GetDataMessage)outbound();
        assertEquals(b2.getHash(), getdata.getItems().get(0).hash);
        assertEquals(b3.getHash(), getdata.getItems().get(1).hash);
        assertEquals(2, getdata.getItems().size());
        // Remote peer sends us the blocks. The act of doing a getdata for b3 results in getting an inv with just the
        // best chain head in it.
        inbound(peer, b2);
        inbound(peer, b3);

        inv = new InventoryMessage(unitTestParams);
        inv.addBlock(b5);
        // We request the head block.
        inbound(peer, inv);
        getdata = (GetDataMessage)outbound();
        assertEquals(b5.getHash(), getdata.getItems().get(0).hash);
        assertEquals(1, getdata.getItems().size());
        // Peer sends us the head block. The act of receiving the orphan block triggers a getblocks to fill in the
        // rest of the chain.
        inbound(peer, b5);
        getblocks = (GetBlocksMessage)outbound();
        assertEquals(b5.getHash(), getblocks.getStopHash());
        assertEquals(b3.getHash(), getblocks.getLocator().get(0));
        // At this point another block is solved and broadcast. The inv triggers a getdata but we do NOT send another
        // getblocks afterwards, because that would result in us receiving the same set of blocks twice which is a
        // timewaste. The getblocks message that would have been generated is set to be the same as the previous
        // because we walk backwards down the orphan chain and then discover we already asked for those blocks, so
        // nothing is done.
        Block b6 = makeSolvedTestBlock(unitTestParams, b5);
        inv = new InventoryMessage(unitTestParams);
        inv.addBlock(b6);
        inbound(peer, inv);
        getdata = (GetDataMessage)outbound();
        assertEquals(1, getdata.getItems().size());
        assertEquals(b6.getHash(), getdata.getItems().get(0).hash);
        inbound(peer, b6);
        assertFalse(event.hasCaptured());  // Nothing is sent at this point.
        // We're still waiting for the response to the getblocks (b3,b5) sent above.
        inv = new InventoryMessage(unitTestParams);
        inv.addBlock(b4);
        inv.addBlock(b5);
        inbound(peer, inv);
        getdata = (GetDataMessage)outbound();
        assertEquals(1, getdata.getItems().size());
        assertEquals(b4.getHash(), getdata.getItems().get(0).hash);
        // We already have b5 from before, so it's not requested again.
        inbound(peer, b4);
        assertFalse(event.hasCaptured());
        // b5 and b6 are now connected by the block chain and we're done.
        closePeer(peer);
        control.verify();
    }

    // Check that an inventory tickle is processed correctly when downloading missing blocks is active.
    @Test
    public void invTickle() throws Exception {
        control.replay();

        connect();

        Block b1 = createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        // Make a missing block.
        Block b2 = makeSolvedTestBlock(unitTestParams, b1);
        Block b3 = makeSolvedTestBlock(unitTestParams, b2);
        inbound(peer, b3);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b3.getHash());
        inv.addItem(item);
        inbound(peer, inv);

        GetBlocksMessage getblocks = (GetBlocksMessage)outbound();
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.genesisBlock.getHash());
        
        assertEquals(getblocks.getLocator(), expectedLocator);
        assertEquals(getblocks.getStopHash(), b3.getHash());
        control.verify();
    }

    // Check that an inv to a peer that is not set to download missing blocks does nothing.
    @Test
    public void invNoDownload() throws Exception {
        // Don't download missing blocks.
        peer.setDownloadData(false);
        
        control.replay();
        
        connect();

        // Make a missing block that we receive.
        Block b1 = createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(unitTestParams, b1);

        // Receive an inv.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b2.getHash());
        inv.addItem(item);
        inbound(peer, inv);

        // Peer does nothing with it.
        control.verify();
    }

    @Test
    public void invDownloadTx() throws Exception {
        control.replay();
        
        connect();

        peer.setDownloadData(true);
        // Make a transaction and tell the peer we have it.
        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction tx = createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Transaction, tx.getHash());
        inv.addItem(item);
        inbound(peer, inv);
        // Peer hasn't seen it before, so will ask for it.
        
        GetDataMessage message = (GetDataMessage) event.getValue().getMessage();
        assertEquals(1, message.getItems().size());
        assertEquals(tx.getHash(), message.getItems().get(0).hash);
        inbound(peer, tx);
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void invDownloadTxMultiPeer() throws Exception {
        ChannelHandlerContext ctx2 = createChannelHandlerContext();
        Channel channel2 = createChannel();
        createPipeline(channel2);

        control.replay();

        // Check co-ordination of which peer to download via the memory pool.
        MemoryPool pool = new MemoryPool();
        peer.setMemoryPool(pool);

        MockNetworkConnection conn2 = createMockNetworkConnection();
        VersionMessage ver = new VersionMessage(unitTestParams, 100);
        Peer peer2 = new Peer(unitTestParams, blockChain, ver);
        peer2.addWallet(wallet);
        peer2.setMemoryPool(pool);

        connect();
        connect(peer2.getHandler(), channel2, ctx2);

        // Make a tx and advertise it to one of the peers.
        BigInteger value = Utils.toNanoCoins(1, 0);
        Transaction tx = createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Transaction, tx.getHash());
        inv.addItem(item);

        inbound(peer, inv);

        // We got a getdata message.
        GetDataMessage message = (GetDataMessage)outbound();
        assertEquals(1, message.getItems().size());
        assertEquals(tx.getHash(), message.getItems().get(0).hash);
        assertTrue(pool.maybeWasSeen(tx.getHash()));

        // Advertising to peer2 results in no getdata message.
        conn2.inbound(inv);
        assertFalse(event.hasCaptured());
    }

    // Check that inventory message containing blocks we want is processed correctly.
    @Test
    public void newBlock() throws Exception {
        PeerEventListener listener = control.createMock(PeerEventListener.class);

        Block b1 = createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(unitTestParams, b1);
        // Receive notification of a new block.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b2.getHash());
        inv.addItem(item);
        expect(listener.onPreMessageReceived(eq(peer), eq(inv))).andReturn(inv);
        expect(listener.onPreMessageReceived(eq(peer), eq(b2))).andReturn(b2);
        listener.onBlocksDownloaded(eq(peer), anyObject(Block.class), eq(108));
        expectLastCall();

        control.replay();

        connect();
        peer.addEventListener(listener);
        
        inbound(peer, inv);
        // Response to the getdata message.
        inbound(peer, b2);

        control.verify();
        
        GetDataMessage getdata = (GetDataMessage) event.getValue().getMessage();
        List<InventoryItem> items = getdata.getItems();
        assertEquals(1, items.size());
        assertEquals(b2.getHash(), items.get(0).hash);
        assertEquals(InventoryItem.Type.Block, items.get(0).type);
    }

    // Check that it starts downloading the block chain correctly on request.
    @Test
    public void startBlockChainDownload() throws Exception {
        PeerEventListener listener = control.createMock(PeerEventListener.class);

        Block b1 = createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(unitTestParams, b1);
        blockChain.add(b2);

        listener.onChainDownloadStarted(peer, 108);
        expectLastCall();

        control.replay();
        
        connect();
        peer.addEventListener(listener);

        peer.startBlockChainDownload();
        control.verify();
        
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b2.getHash());
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.genesisBlock.getHash());

        GetBlocksMessage message = (GetBlocksMessage) event.getValue().getMessage();
        assertEquals(message.getLocator(), expectedLocator);
        assertEquals(message.getStopHash(), Sha256Hash.ZERO_HASH);
    }

    @Test
    public void getBlock() throws Exception {
        control.replay();
        
        connect();

        Block b1 = createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(unitTestParams, b1);
        Block b3 = makeSolvedTestBlock(unitTestParams, b2);

        // Request the block.
        Future<Block> resultFuture = peer.getBlock(b3.getHash());
        assertFalse(resultFuture.isDone());
        // Peer asks for it.
        GetDataMessage message = (GetDataMessage) event.getValue().getMessage();
        assertEquals(message.getItems().get(0).hash, b3.getHash());
        assertFalse(resultFuture.isDone());
        // Peer receives it.
        inbound(peer, b3);
        Block b = resultFuture.get();
        assertEquals(b, b3);
    }

    @Test
    public void fastCatchup() throws Exception {
        control.replay();
        
        connect();
        
        // Check that blocks before the fast catchup point are retrieved using getheaders, and after using getblocks.
        // This test is INCOMPLETE because it does not check we handle >2000 blocks correctly.
        Block b1 = createFakeBlock(unitTestParams, blockStore).block;
        blockChain.add(b1);
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b2 = makeSolvedTestBlock(unitTestParams, b1);
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b3 = makeSolvedTestBlock(unitTestParams, b2);
        Utils.rollMockClock(60 * 10);
        Block b4 = makeSolvedTestBlock(unitTestParams, b3);

        // Request headers until the last 2 blocks.
        peer.setFastCatchupTime((Utils.now().getTime() / 1000) - (600*2) + 1);
        peer.startBlockChainDownload();
        GetHeadersMessage getheaders = (GetHeadersMessage) event.getValue().getMessage();
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
        inbound(peer, headers);
        GetBlocksMessage getblocks = (GetBlocksMessage) event.getValue().getMessage();
        assertEquals(expectedLocator, getblocks.getLocator());
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // We're supposed to get an inv here.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addItem(new InventoryItem(InventoryItem.Type.Block, b3.getHash()));
        inbound(peer, inv);
        GetDataMessage getdata = (GetDataMessage) event.getValue().getMessage();
        assertEquals(b3.getHash(), getdata.getItems().get(0).hash);
        // All done.
        inbound(peer, b3);
    }
    
    private Message outbound() {
        Message message = (Message)event.getValue().getMessage();
        event.reset();
        return message;
    }
}
