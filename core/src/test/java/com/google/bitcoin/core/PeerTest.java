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
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.ListenableFuture;
import org.easymock.Capture;
import org.easymock.CaptureType;
import org.jboss.netty.channel.*;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
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
    private static final int OTHER_PEER_CHAIN_HEIGHT = 110;
    private MemoryPool memoryPool;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        memoryPool = new MemoryPool();
        VersionMessage ver = new VersionMessage(unitTestParams, 100);
        peer = new Peer(unitTestParams, blockChain, ver, memoryPool);
        peer.addWallet(wallet);
        handler = peer.getHandler();
        event = new Capture<DownstreamMessageEvent>(CaptureType.ALL);
        pipeline.sendDownstream(capture(event));
        expectLastCall().anyTimes();
    }

    private void connect() throws Exception {
        connect(handler, channel, ctx, 70001);
    }

    private void connectWithVersion(int version) throws Exception {
        connect(handler, channel, ctx, version);
    }
    
    private void connect(PeerHandler handler, Channel channel, ChannelHandlerContext ctx, int version) throws Exception {
        handler.connectRequested(ctx, new UpstreamChannelStateEvent(channel, ChannelState.CONNECTED, socketAddress));
        VersionMessage peerVersion = new VersionMessage(unitTestParams, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = version;
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
        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        Block b3 = makeSolvedTestBlock(b2);
        Block b4 = makeSolvedTestBlock(b3);
        Block b5 = makeSolvedTestBlock(b4);

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
        Block b6 = makeSolvedTestBlock(b5);
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

        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        // Make a missing block.
        Block b2 = makeSolvedTestBlock(b1);
        Block b3 = makeSolvedTestBlock(b2);
        inbound(peer, b3);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b3.getHash());
        inv.addItem(item);
        inbound(peer, inv);

        GetBlocksMessage getblocks = (GetBlocksMessage)outbound();
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.getGenesisBlock().getHash());
        
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
        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);

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
        GetDataMessage getdata = (GetDataMessage) outbound();
        assertEquals(1, getdata.getItems().size());
        assertEquals(tx.getHash(), getdata.getItems().get(0).hash);
        inbound(peer, tx);
        // Ask for the dependency, it's not in the mempool (in chain).
        getdata = (GetDataMessage) outbound();
        inbound(peer, new NotFoundMessage(unitTestParams, getdata.getItems()));
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void invDownloadTxMultiPeer() throws Exception {
        ChannelHandlerContext ctx2 = createChannelHandlerContext();
        Channel channel2 = createChannel();
        createPipeline(channel2);

        control.replay();

        // Check co-ordination of which peer to download via the memory pool.
        MockNetworkConnection conn2 = createMockNetworkConnection();
        VersionMessage ver = new VersionMessage(unitTestParams, 100);
        Peer peer2 = new Peer(unitTestParams, blockChain, ver, memoryPool);
        peer2.addWallet(wallet);

        connect();
        connect(peer2.getHandler(), channel2, ctx2, 70001);

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
        assertTrue(memoryPool.maybeWasSeen(tx.getHash()));

        // Advertising to peer2 results in no getdata message.
        conn2.inbound(inv);
        assertFalse(event.hasCaptured());
    }

    // Check that inventory message containing blocks we want is processed correctly.
    @Test
    public void newBlock() throws Exception {
        PeerEventListener listener = control.createMock(PeerEventListener.class);

        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        // Receive notification of a new block.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b2.getHash());
        inv.addItem(item);
        expect(listener.onPreMessageReceived(eq(peer), eq(inv))).andReturn(inv);
        expect(listener.onPreMessageReceived(eq(peer), eq(b2))).andReturn(b2);
        // The listener gets the delta between the first announced height and our height.
        listener.onBlocksDownloaded(eq(peer), anyObject(Block.class), eq(OTHER_PEER_CHAIN_HEIGHT - 2));
        expectLastCall();

        control.replay();

        connect();
        peer.addEventListener(listener);
        long height = peer.getBestHeight();
        
        inbound(peer, inv);
        assertEquals(height + 1, peer.getBestHeight());
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

        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
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
        expectedLocator.add(unitTestParams.getGenesisBlock().getHash());

        GetBlocksMessage message = (GetBlocksMessage) event.getValue().getMessage();
        assertEquals(message.getLocator(), expectedLocator);
        assertEquals(message.getStopHash(), Sha256Hash.ZERO_HASH);
    }

    @Test
    public void getBlock() throws Exception {
        control.replay();
        
        connect();

        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        Block b3 = makeSolvedTestBlock(b2);

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
        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b2 = makeSolvedTestBlock(b1);
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b3 = makeSolvedTestBlock(b2);
        Utils.rollMockClock(60 * 10);
        Block b4 = makeSolvedTestBlock(b3);

        // Request headers until the last 2 blocks.
        peer.setDownloadParameters((Utils.now().getTime() / 1000) - (600*2) + 1, false);
        peer.startBlockChainDownload();
        GetHeadersMessage getheaders = (GetHeadersMessage) outbound();
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.getGenesisBlock().getHash());
        assertEquals(getheaders.getLocator(), expectedLocator);
        assertEquals(getheaders.getStopHash(), Sha256Hash.ZERO_HASH);
        // Now send all the headers.
        HeadersMessage headers = new HeadersMessage(unitTestParams, b2.cloneAsHeader(),
                b3.cloneAsHeader(), b4.cloneAsHeader());
        // We expect to be asked for b3 and b4 again, but this time, with a body.
        expectedLocator.clear();
        expectedLocator.add(b2.getHash());
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.getGenesisBlock().getHash());
        inbound(peer, headers);
        GetBlocksMessage getblocks = (GetBlocksMessage) outbound();
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

    @Test
    public void pingPong() throws Exception {
        control.replay();
        connect();
        Utils.rollMockClock(0);
        // No ping pong happened yet.
        assertEquals(Long.MAX_VALUE, peer.getLastPingTime());
        assertEquals(Long.MAX_VALUE, peer.getPingTime());
        ListenableFuture<Long> future = peer.ping();
        Ping pingMsg = (Ping) outbound();
        assertEquals(Long.MAX_VALUE, peer.getLastPingTime());
        assertEquals(Long.MAX_VALUE, peer.getPingTime());
        assertFalse(future.isDone());
        Utils.rollMockClock(5);
        // The pong is returned.
        inbound(peer, new Pong(pingMsg.getNonce()));
        assertTrue(future.isDone());
        long elapsed = future.get();
        assertTrue("" + elapsed, elapsed > 1000);
        assertEquals(elapsed, peer.getLastPingTime());
        assertEquals(elapsed, peer.getPingTime());
        // Do it again and make sure it affects the average.
        future = peer.ping();
        pingMsg = (Ping) outbound();
        Utils.rollMockClock(50);
        inbound(peer, new Pong(pingMsg.getNonce()));
        elapsed = future.get();
        assertEquals(elapsed, peer.getLastPingTime());
        assertEquals(7250, peer.getPingTime());
    }

    @Test
    public void recursiveDownloadNew() throws Exception {
        recursiveDownload(true);
    }

    @Test
    public void recursiveDownloadOld() throws Exception {
        recursiveDownload(false);
    }

    public void recursiveDownload(boolean useNotFound) throws Exception {
        // Using ping or notfound?
        control.replay();
        connectWithVersion(useNotFound ? 70001 : 60001);
        // Check that we can download all dependencies of an unconfirmed relevant transaction from the mempool.
        ECKey to = new ECKey();

        final Transaction[] onTx = new Transaction[1];
        peer.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onTransaction(Peer peer1, Transaction t) {
                onTx[0] = t;
            }
        });

        // Make the some fake transactions in the following graph:
        //   t1 -> t2 -> [t5]
        //      -> t3 -> t4 -> [t6]
        //      -> [t7]
        //      -> [t8]
        // The ones in brackets are assumed to be in the chain and are represented only by hashes.
        Transaction t2 = TestUtils.createFakeTx(unitTestParams, Utils.toNanoCoins(1, 0), to);
        Sha256Hash t5 = t2.getInput(0).getOutpoint().getHash();
        Transaction t4 = TestUtils.createFakeTx(unitTestParams, Utils.toNanoCoins(1, 0), new ECKey());
        Sha256Hash t6 = t4.getInput(0).getOutpoint().getHash();
        t4.addOutput(Utils.toNanoCoins(1, 0), new ECKey());
        Transaction t3 = new Transaction(unitTestParams);
        t3.addInput(t4.getOutput(0));
        t3.addOutput(Utils.toNanoCoins(1, 0), new ECKey());
        Transaction t1 = new Transaction(unitTestParams);
        t1.addInput(t2.getOutput(0));
        t1.addInput(t3.getOutput(0));
        Sha256Hash someHash = new Sha256Hash("2b801dd82f01d17bbde881687bf72bc62e2faa8ab8133d36fcb8c3abe7459da6");
        t1.addInput(new TransactionInput(unitTestParams, t1, new byte[]{}, new TransactionOutPoint(unitTestParams, 0, someHash)));
        Sha256Hash anotherHash = new Sha256Hash("3b801dd82f01d17bbde881687bf72bc62e2faa8ab8133d36fcb8c3abe7459da6");
        t1.addInput(new TransactionInput(unitTestParams, t1, new byte[]{}, new TransactionOutPoint(unitTestParams, 1, anotherHash)));
        t1.addOutput(Utils.toNanoCoins(1, 0), to);
        t1 = TestUtils.roundTripTransaction(unitTestParams, t1);
        t2 = TestUtils.roundTripTransaction(unitTestParams, t2);
        t3 = TestUtils.roundTripTransaction(unitTestParams, t3);
        t4 = TestUtils.roundTripTransaction(unitTestParams, t4);

        // Announce the first one. Wait for it to be downloaded.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addTransaction(t1);
        inbound(peer, inv);
        GetDataMessage getdata = (GetDataMessage) outbound();
        assertEquals(t1.getHash(), getdata.getItems().get(0).hash);
        inbound(peer, t1);
        assertEquals(t1, onTx[0]);
        // We want its dependencies so ask for them.
        ListenableFuture<List<Transaction>> futures = peer.downloadDependencies(t1);
        assertFalse(futures.isDone());
        // It will recursively ask for the dependencies of t1: t2, t3, someHash and anotherHash.
        getdata = (GetDataMessage) outbound();
        assertEquals(4, getdata.getItems().size());
        assertEquals(t2.getHash(), getdata.getItems().get(0).hash);
        assertEquals(t3.getHash(), getdata.getItems().get(1).hash);
        assertEquals(someHash, getdata.getItems().get(2).hash);
        assertEquals(anotherHash, getdata.getItems().get(3).hash);
        long nonce = -1;
        if (!useNotFound)
            nonce = ((Ping) outbound()).getNonce();
        // For some random reason, t4 is delivered at this point before it's needed - perhaps it was a Bloom filter
        // false positive. We do this to check that the mempool is being checked for seen transactions before
        // requesting them.
        inbound(peer, t4);
        // Deliver the requested transactions.
        inbound(peer, t2);
        inbound(peer, t3);
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, someHash));
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, anotherHash));
            inbound(peer, notFound);
        } else {
            inbound(peer, new Pong(nonce));
        }
        assertFalse(futures.isDone());
        // It will recursively ask for the dependencies of t2: t5 and t4, but not t3 because it already found t4.
        getdata = (GetDataMessage) outbound();
        assertEquals(getdata.getItems().get(0).hash, t2.getInput(0).getOutpoint().getHash());
        // t5 isn't found and t4 is.
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, t5));
            inbound(peer, notFound);
        } else {
            bouncePing();
        }
        assertFalse(futures.isDone());
        // Continue to explore the t4 branch and ask for t6, which is in the chain.
        getdata = (GetDataMessage) outbound();
        assertEquals(t6, getdata.getItems().get(0).hash);
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, t6));
            inbound(peer, notFound);
        } else {
            bouncePing();
        }
        // That's it, we explored the entire tree.
        assertTrue(futures.isDone());
        List<Transaction> results = futures.get();
        assertTrue(results.contains(t2));
        assertTrue(results.contains(t3));
        assertTrue(results.contains(t4));
    }

    private void bouncePing() throws Exception {
        Ping ping = (Ping) outbound();
        inbound(peer, new Pong(ping.getNonce()));
    }

    @Test
    public void timeLockedTransactionNew() throws Exception {
        timeLockedTransaction(true);
    }

    @Test
    public void timeLockedTransactionOld() throws Exception {
        timeLockedTransaction(false);
    }

    public void timeLockedTransaction(boolean useNotFound) throws Exception {
        control.replay();
        connectWithVersion(useNotFound ? 70001 : 60001);
        // Test that if we receive a relevant transaction that has a lock time, it doesn't result in a notification
        // until we explicitly opt in to seeing those.
        ECKey key = new ECKey();
        Wallet wallet = new Wallet(unitTestParams);
        wallet.addKey(key);
        peer.addWallet(wallet);
        final Transaction[] vtx = new Transaction[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                vtx[0] = tx;
            }
        });
        // Send a normal relevant transaction, it's received correctly.
        Transaction t1 = TestUtils.createFakeTx(unitTestParams, Utils.toNanoCoins(1, 0), key);
        inbound(peer, t1);
        GetDataMessage getdata = (GetDataMessage) outbound();
        if (useNotFound) {
            inbound(peer, new NotFoundMessage(unitTestParams, getdata.getItems()));
        } else {
            bouncePing();
        }
        assertNotNull(vtx[0]);
        vtx[0] = null;
        // Send a timelocked transaction, nothing happens.
        Transaction t2 = TestUtils.createFakeTx(unitTestParams, Utils.toNanoCoins(2, 0), key);
        t2.setLockTime(999999);
        inbound(peer, t2);
        assertNull(vtx[0]);
        // Now we want to hear about them. Send another, we are told about it.
        wallet.setAcceptTimeLockedTransactions(true);
        inbound(peer, t2);
        getdata = (GetDataMessage) outbound();
        if (useNotFound) {
            inbound(peer, new NotFoundMessage(unitTestParams, getdata.getItems()));
        } else {
            bouncePing();
        }
        assertEquals(t2, vtx[0]);
    }

    @Test
    public void rejectTimeLockedDependencyNew() throws Exception {
        // Check that we also verify the lock times of dependencies. Otherwise an attacker could still build a tx that
        // looks legitimate and useful but won't actually ever confirm, by sending us a normal tx that spends a
        // timelocked tx.
        checkTimeLockedDependency(false, true);
    }

    @Test
    public void acceptTimeLockedDependencyNew() throws Exception {
        checkTimeLockedDependency(true, true);
    }

    @Test
    public void rejectTimeLockedDependencyOld() throws Exception {
        // Check that we also verify the lock times of dependencies. Otherwise an attacker could still build a tx that
        // looks legitimate and useful but won't actually ever confirm, by sending us a normal tx that spends a
        // timelocked tx.
        checkTimeLockedDependency(false, false);
    }

    @Test
    public void acceptTimeLockedDependencyOld() throws Exception {
        checkTimeLockedDependency(true, false);
    }

    private void checkTimeLockedDependency(boolean shouldAccept, boolean useNotFound) throws Exception {
        // Initial setup.
        control.replay();
        connectWithVersion(useNotFound ? 70001 : 60001);
        ECKey key = new ECKey();
        Wallet wallet = new Wallet(unitTestParams);
        wallet.addKey(key);
        wallet.setAcceptTimeLockedTransactions(shouldAccept);
        peer.addWallet(wallet);
        final Transaction[] vtx = new Transaction[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                vtx[0] = tx;
            }
        });
        // t1 -> t2 [locked] -> t3 (not available)
        Transaction t2 = new Transaction(unitTestParams);
        t2.setLockTime(999999);
        // Add a fake input to t3 that goes nowhere.
        Sha256Hash t3 = Sha256Hash.create("abc".getBytes(Charset.forName("UTF-8")));
        t2.addInput(new TransactionInput(unitTestParams, t2, new byte[]{}, new TransactionOutPoint(unitTestParams, 0, t3)));
        t2.getInput(0).setSequenceNumber(0xDEADBEEF);
        t2.addOutput(Utils.toNanoCoins(1, 0), new ECKey());
        Transaction t1 = new Transaction(unitTestParams);
        t1.addInput(t2.getOutput(0));
        t1.addOutput(Utils.toNanoCoins(1, 0), key);  // Make it relevant.
        // Announce t1.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addTransaction(t1);
        inbound(peer, inv);
        // Send it.
        GetDataMessage getdata = (GetDataMessage) outbound();
        assertEquals(t1.getHash(), getdata.getItems().get(0).hash);
        inbound(peer, t1);
        // Nothing arrived at our event listener yet.
        assertNull(vtx[0]);
        // We request t2.
        getdata = (GetDataMessage) outbound();
        assertEquals(t2.getHash(), getdata.getItems().get(0).hash);
        inbound(peer, t2);
        if (!useNotFound)
            bouncePing();
        // We request t3.
        getdata = (GetDataMessage) outbound();
        assertEquals(t3, getdata.getItems().get(0).hash);
        // Can't find it: bottom of tree.
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, t3));
            inbound(peer, notFound);
        } else {
            bouncePing();
        }
        // We're done but still not notified because it was timelocked.
        if (shouldAccept)
            assertNotNull(vtx[0]);
        else
            assertNull(vtx[0]);
    }

    @Test
    public void disconnectOldVersions1() throws Exception {
        expect(channel.close()).andReturn(null);
        control.replay();
        // Set up the connection with an old version.
        handler.connectRequested(ctx, new UpstreamChannelStateEvent(channel, ChannelState.CONNECTED, socketAddress));
        VersionMessage peerVersion = new VersionMessage(unitTestParams, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = 500;
        DownstreamMessageEvent versionEvent =
                new DownstreamMessageEvent(channel, Channels.future(channel), peerVersion, null);
        handler.messageReceived(ctx, versionEvent);
    }

    @Test
    public void disconnectOldVersions2() throws Exception {
        expect(channel.close()).andReturn(null);
        control.replay();
        // Set up the connection with an old version.
        handler.connectRequested(ctx, new UpstreamChannelStateEvent(channel, ChannelState.CONNECTED, socketAddress));
        VersionMessage peerVersion = new VersionMessage(unitTestParams, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = 70000;
        DownstreamMessageEvent versionEvent =
                new DownstreamMessageEvent(channel, Channels.future(channel), peerVersion, null);
        handler.messageReceived(ctx, versionEvent);
        peer.setMinProtocolVersion(500);
    }

    @Test
    public void exceptionListener() throws Exception {
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                throw new NullPointerException("boo!");
            }
        });
        final Throwable[] throwables = new Throwable[1];
        peer.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onException(Throwable throwable) {
                throwables[0] = throwable;
            }
        });
        control.replay();
        connect();
        Transaction t1 = new Transaction(unitTestParams);
        t1.addInput(new TransactionInput(unitTestParams, t1, new byte[]{}));
        t1.addOutput(Utils.toNanoCoins(1, 0), new ECKey().toAddress(unitTestParams));
        Transaction t2 = new Transaction(unitTestParams);
        t2.addInput(t1.getOutput(0));
        t2.addOutput(Utils.toNanoCoins(1, 0), wallet.getChangeAddress());
        inbound(peer, t2);
        inbound(peer, new NotFoundMessage(unitTestParams, Lists.newArrayList(new InventoryItem(InventoryItem.Type.Transaction, t2.getInput(0).getHash()))));
        assertTrue(throwables[0] instanceof NullPointerException);
    }

    // TODO: Use generics here to avoid unnecessary casting.
    private Message outbound() {
        List<DownstreamMessageEvent> messages = event.getValues();
        if (messages.isEmpty())
            throw new AssertionError("No messages sent when one was expected");
        Message message = (Message)messages.get(0).getMessage();
        messages.remove(0);
        return message;
    }
}
