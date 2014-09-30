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

package org.bitcoinj.core;

import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.testing.InboundMessageQueuer;
import org.bitcoinj.testing.TestWithNetworkConnections;
import org.bitcoinj.utils.Threading;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.google.common.util.concurrent.Uninterruptibles;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.channels.CancelledKeyException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.bitcoinj.core.Coin.*;
import static org.bitcoinj.testing.FakeTxBuilder.*;
import static org.junit.Assert.*;

@RunWith(value = Parameterized.class)
public class PeerTest extends TestWithNetworkConnections {
    private Peer peer;
    private InboundMessageQueuer writeTarget;
    private static final int OTHER_PEER_CHAIN_HEIGHT = 110;
    private MemoryPool memoryPool;
    private final AtomicBoolean fail = new AtomicBoolean(false);


    @Parameterized.Parameters
    public static Collection<ClientType[]> parameters() {
        return Arrays.asList(new ClientType[] {ClientType.NIO_CLIENT_MANAGER},
                             new ClientType[] {ClientType.BLOCKING_CLIENT_MANAGER},
                             new ClientType[] {ClientType.NIO_CLIENT},
                             new ClientType[] {ClientType.BLOCKING_CLIENT});
    }

    public PeerTest(ClientType clientType) {
        super(clientType);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        memoryPool = new MemoryPool();
        VersionMessage ver = new VersionMessage(unitTestParams, 100);
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 4000);
        peer = new Peer(unitTestParams, ver, new PeerAddress(address), blockChain, memoryPool);
        peer.addWallet(wallet);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        assertFalse(fail.get());
    }

    private void connect() throws Exception {
        connectWithVersion(70001);
    }

    private void connectWithVersion(int version) throws Exception {
        VersionMessage peerVersion = new VersionMessage(unitTestParams, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = version;
        peerVersion.localServices = VersionMessage.NODE_NETWORK;
        writeTarget = connect(peer, peerVersion);
    }

    @Test
    public void testAddEventListener() throws Exception {
        connect();
        PeerEventListener listener = new AbstractPeerEventListener();
        peer.addEventListener(listener);
        assertTrue(peer.removeEventListener(listener));
        assertFalse(peer.removeEventListener(listener));
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

        connect();
        
        peer.startBlockChainDownload();
        GetBlocksMessage getblocks = (GetBlocksMessage)outbound(writeTarget);
        assertEquals(blockStore.getChainHead().getHeader().getHash(), getblocks.getLocator().get(0));
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // Remote peer sends us an inv with some blocks.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addBlock(b2);
        inv.addBlock(b3);
        // We do a getdata on them.
        inbound(writeTarget, inv);
        GetDataMessage getdata = (GetDataMessage)outbound(writeTarget);
        assertEquals(b2.getHash(), getdata.getItems().get(0).hash);
        assertEquals(b3.getHash(), getdata.getItems().get(1).hash);
        assertEquals(2, getdata.getItems().size());
        // Remote peer sends us the blocks. The act of doing a getdata for b3 results in getting an inv with just the
        // best chain head in it.
        inbound(writeTarget, b2);
        inbound(writeTarget, b3);

        inv = new InventoryMessage(unitTestParams);
        inv.addBlock(b5);
        // We request the head block.
        inbound(writeTarget, inv);
        getdata = (GetDataMessage)outbound(writeTarget);
        assertEquals(b5.getHash(), getdata.getItems().get(0).hash);
        assertEquals(1, getdata.getItems().size());
        // Peer sends us the head block. The act of receiving the orphan block triggers a getblocks to fill in the
        // rest of the chain.
        inbound(writeTarget, b5);
        getblocks = (GetBlocksMessage)outbound(writeTarget);
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
        inbound(writeTarget, inv);
        getdata = (GetDataMessage)outbound(writeTarget);
        assertEquals(1, getdata.getItems().size());
        assertEquals(b6.getHash(), getdata.getItems().get(0).hash);
        inbound(writeTarget, b6);
        assertNull(outbound(writeTarget));  // Nothing is sent at this point.
        // We're still waiting for the response to the getblocks (b3,b5) sent above.
        inv = new InventoryMessage(unitTestParams);
        inv.addBlock(b4);
        inv.addBlock(b5);
        inbound(writeTarget, inv);
        getdata = (GetDataMessage)outbound(writeTarget);
        assertEquals(1, getdata.getItems().size());
        assertEquals(b4.getHash(), getdata.getItems().get(0).hash);
        // We already have b5 from before, so it's not requested again.
        inbound(writeTarget, b4);
        assertNull(outbound(writeTarget));
        // b5 and b6 are now connected by the block chain and we're done.
        assertNull(outbound(writeTarget));
        closePeer(peer);
    }

    // Check that an inventory tickle is processed correctly when downloading missing blocks is active.
    @Test
    public void invTickle() throws Exception {
        connect();

        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        // Make a missing block.
        Block b2 = makeSolvedTestBlock(b1);
        Block b3 = makeSolvedTestBlock(b2);
        inbound(writeTarget, b3);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b3.getHash());
        inv.addItem(item);
        inbound(writeTarget, inv);

        GetBlocksMessage getblocks = (GetBlocksMessage)outbound(writeTarget);
        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.getGenesisBlock().getHash());
        
        assertEquals(getblocks.getLocator(), expectedLocator);
        assertEquals(getblocks.getStopHash(), b3.getHash());
        assertNull(outbound(writeTarget));
    }

    // Check that an inv to a peer that is not set to download missing blocks does nothing.
    @Test
    public void invNoDownload() throws Exception {
        // Don't download missing blocks.
        peer.setDownloadData(false);

        connect();

        // Make a missing block that we receive.
        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);

        // Receive an inv.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b2.getHash());
        inv.addItem(item);
        inbound(writeTarget, inv);

        // Peer does nothing with it.
        assertNull(outbound(writeTarget));
    }

    @Test
    public void invDownloadTx() throws Exception {
        connect();

        peer.setDownloadData(true);
        // Make a transaction and tell the peer we have it.
        Coin value = COIN;
        Transaction tx = createFakeTx(unitTestParams, value, address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Transaction, tx.getHash());
        inv.addItem(item);
        inbound(writeTarget, inv);
        // Peer hasn't seen it before, so will ask for it.
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(1, getdata.getItems().size());
        assertEquals(tx.getHash(), getdata.getItems().get(0).hash);
        inbound(writeTarget, tx);
        // Ask for the dependency, it's not in the mempool (in chain).
        getdata = (GetDataMessage) outbound(writeTarget);
        inbound(writeTarget, new NotFoundMessage(unitTestParams, getdata.getItems()));
        pingAndWait(writeTarget);
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void invDownloadTxMultiPeer() throws Exception {
        // Check co-ordination of which peer to download via the memory pool.
        VersionMessage ver = new VersionMessage(unitTestParams, 100);
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", 4242);
        Peer peer2 = new Peer(unitTestParams, ver, new PeerAddress(address), blockChain, memoryPool);
        peer2.addWallet(wallet);
        VersionMessage peerVersion = new VersionMessage(unitTestParams, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = 70001;
        peerVersion.localServices = VersionMessage.NODE_NETWORK;

        connect();
        InboundMessageQueuer writeTarget2 = connect(peer2, peerVersion);

        // Make a tx and advertise it to one of the peers.
        Coin value = COIN;
        Transaction tx = createFakeTx(unitTestParams, value, this.address);
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Transaction, tx.getHash());
        inv.addItem(item);

        inbound(writeTarget, inv);

        // We got a getdata message.
        GetDataMessage message = (GetDataMessage)outbound(writeTarget);
        assertEquals(1, message.getItems().size());
        assertEquals(tx.getHash(), message.getItems().get(0).hash);
        assertTrue(memoryPool.maybeWasSeen(tx.getHash()));

        // Advertising to peer2 results in no getdata message.
        inbound(writeTarget2, inv);
        pingAndWait(writeTarget2);
        assertNull(outbound(writeTarget2));
    }

    // Check that inventory message containing blocks we want is processed correctly.
    @Test
    public void newBlock() throws Exception {
        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        final Block b2 = makeSolvedTestBlock(b1);
        // Receive notification of a new block.
        final InventoryMessage inv = new InventoryMessage(unitTestParams);
        InventoryItem item = new InventoryItem(InventoryItem.Type.Block, b2.getHash());
        inv.addItem(item);

        final AtomicInteger newBlockMessagesReceived = new AtomicInteger(0);

        connect();
        // Round-trip a ping so that we never see the response verack if we attach too quick
        pingAndWait(writeTarget);
        peer.addEventListener(new AbstractPeerEventListener() {
            @Override
            public synchronized Message onPreMessageReceived(Peer p, Message m) {
                if (p != peer)
                    fail.set(true);
                if (m instanceof Pong)
                    return m;
                int newValue = newBlockMessagesReceived.incrementAndGet();
                if (newValue == 1 && !inv.equals(m))
                    fail.set(true);
                else if (newValue == 2 && !b2.equals(m))
                    fail.set(true);
                else if (newValue > 3)
                    fail.set(true);
                return m;
            }

            @Override
            public synchronized void onBlocksDownloaded(Peer p, Block block, int blocksLeft) {
                int newValue = newBlockMessagesReceived.incrementAndGet();
                if (newValue != 3 || p != peer || !block.equals(b2) || blocksLeft != OTHER_PEER_CHAIN_HEIGHT - 2)
                    fail.set(true);
            }
        }, Threading.SAME_THREAD);
        long height = peer.getBestHeight();

        inbound(writeTarget, inv);
        pingAndWait(writeTarget);
        assertEquals(height + 1, peer.getBestHeight());
        // Response to the getdata message.
        inbound(writeTarget, b2);

        pingAndWait(writeTarget);
        Threading.waitForUserCode();
        pingAndWait(writeTarget);
        assertEquals(3, newBlockMessagesReceived.get());
        
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        List<InventoryItem> items = getdata.getItems();
        assertEquals(1, items.size());
        assertEquals(b2.getHash(), items.get(0).hash);
        assertEquals(InventoryItem.Type.Block, items.get(0).type);
    }

    // Check that it starts downloading the block chain correctly on request.
    @Test
    public void startBlockChainDownload() throws Exception {
        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        blockChain.add(b2);

        connect();
        fail.set(true);
        peer.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onChainDownloadStarted(Peer p, int blocksLeft) {
                if (p == peer && blocksLeft == 108)
                    fail.set(false);
            }
        }, Threading.SAME_THREAD);
        peer.startBlockChainDownload();

        List<Sha256Hash> expectedLocator = new ArrayList<Sha256Hash>();
        expectedLocator.add(b2.getHash());
        expectedLocator.add(b1.getHash());
        expectedLocator.add(unitTestParams.getGenesisBlock().getHash());

        GetBlocksMessage message = (GetBlocksMessage) outbound(writeTarget);
        assertEquals(message.getLocator(), expectedLocator);
        assertEquals(Sha256Hash.ZERO_HASH, message.getStopHash());
    }

    @Test
    public void getBlock() throws Exception {
        connect();

        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        Block b3 = makeSolvedTestBlock(b2);

        // Request the block.
        Future<Block> resultFuture = peer.getBlock(b3.getHash());
        assertFalse(resultFuture.isDone());
        // Peer asks for it.
        GetDataMessage message = (GetDataMessage) outbound(writeTarget);
        assertEquals(message.getItems().get(0).hash, b3.getHash());
        assertFalse(resultFuture.isDone());
        // Peer receives it.
        inbound(writeTarget, b3);
        Block b = resultFuture.get();
        assertEquals(b, b3);
    }

    @Test
    public void getLargeBlock() throws Exception {
        connect();

        Block b1 = createFakeBlock(blockStore).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        Transaction t = new Transaction(unitTestParams);
        t.addInput(b1.getTransactions().get(0).getOutput(0));
        t.addOutput(new TransactionOutput(unitTestParams, t, Coin.ZERO, new byte[Block.MAX_BLOCK_SIZE - 1000]));
        b2.addTransaction(t);

        // Request the block.
        Future<Block> resultFuture = peer.getBlock(b2.getHash());
        assertFalse(resultFuture.isDone());
        // Peer asks for it.
        GetDataMessage message = (GetDataMessage) outbound(writeTarget);
        assertEquals(message.getItems().get(0).hash, b2.getHash());
        assertFalse(resultFuture.isDone());
        // Peer receives it.
        inbound(writeTarget, b2);
        Block b = resultFuture.get();
        assertEquals(b, b2);
    }

    @Test
    public void fastCatchup() throws Exception {
        connect();
        Utils.setMockClock();
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
        peer.setDownloadParameters(Utils.currentTimeSeconds() - (600*2) + 1, false);
        peer.startBlockChainDownload();
        GetHeadersMessage getheaders = (GetHeadersMessage) outbound(writeTarget);
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
        inbound(writeTarget, headers);
        GetBlocksMessage getblocks = (GetBlocksMessage) outbound(writeTarget);
        assertEquals(expectedLocator, getblocks.getLocator());
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // We're supposed to get an inv here.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addItem(new InventoryItem(InventoryItem.Type.Block, b3.getHash()));
        inbound(writeTarget, inv);
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(b3.getHash(), getdata.getItems().get(0).hash);
        // All done.
        inbound(writeTarget, b3);
        pingAndWait(writeTarget);
        closePeer(peer);
    }

    @Test
    public void pingPong() throws Exception {
        connect();
        Utils.setMockClock();
        // No ping pong happened yet.
        assertEquals(Long.MAX_VALUE, peer.getLastPingTime());
        assertEquals(Long.MAX_VALUE, peer.getPingTime());
        ListenableFuture<Long> future = peer.ping();
        assertEquals(Long.MAX_VALUE, peer.getLastPingTime());
        assertEquals(Long.MAX_VALUE, peer.getPingTime());
        assertFalse(future.isDone());
        Ping pingMsg = (Ping) outbound(writeTarget);
        Utils.rollMockClock(5);
        // The pong is returned.
        inbound(writeTarget, new Pong(pingMsg.getNonce()));
        pingAndWait(writeTarget);
        assertTrue(future.isDone());
        long elapsed = future.get();
        assertTrue("" + elapsed, elapsed > 1000);
        assertEquals(elapsed, peer.getLastPingTime());
        assertEquals(elapsed, peer.getPingTime());
        // Do it again and make sure it affects the average.
        future = peer.ping();
        pingMsg = (Ping) outbound(writeTarget);
        Utils.rollMockClock(50);
        inbound(writeTarget, new Pong(pingMsg.getNonce()));
        elapsed = future.get();
        assertEquals(elapsed, peer.getLastPingTime());
        assertEquals(7250, peer.getPingTime());
    }

    @Test
    public void recursiveDependencyDownloadDisabled() throws Exception {
        peer.setDownloadTxDependencies(false);
        connect();
        // Check that if we request dependency download to be disabled and receive a relevant tx, things work correctly.
        Transaction tx = FakeTxBuilder.createFakeTx(unitTestParams, COIN, address);
        final Transaction[] result = new Transaction[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                result[0] = tx;
            }
        });
        inbound(writeTarget, tx);
        pingAndWait(writeTarget);
        assertEquals(tx, result[0]);
    }

    @Test
    public void recursiveDownloadNew() throws Exception {
        recursiveDependencyDownload(true);
    }

    @Test
    public void recursiveDownloadOld() throws Exception {
        recursiveDependencyDownload(false);
    }

    public void recursiveDependencyDownload(boolean useNotFound) throws Exception {
        // Using ping or notfound?
        connectWithVersion(useNotFound ? 70001 : 60001);
        // Check that we can download all dependencies of an unconfirmed relevant transaction from the mempool.
        ECKey to = new ECKey();

        final Transaction[] onTx = new Transaction[1];
        peer.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onTransaction(Peer peer1, Transaction t) {
                onTx[0] = t;
            }
        }, Threading.SAME_THREAD);

        // Make the some fake transactions in the following graph:
        //   t1 -> t2 -> [t5]
        //      -> t3 -> t4 -> [t6]
        //      -> [t7]
        //      -> [t8]
        // The ones in brackets are assumed to be in the chain and are represented only by hashes.
        Transaction t2 = FakeTxBuilder.createFakeTx(unitTestParams, COIN, to);
        Sha256Hash t5 = t2.getInput(0).getOutpoint().getHash();
        Transaction t4 = FakeTxBuilder.createFakeTx(unitTestParams, COIN, new ECKey());
        Sha256Hash t6 = t4.getInput(0).getOutpoint().getHash();
        t4.addOutput(COIN, new ECKey());
        Transaction t3 = new Transaction(unitTestParams);
        t3.addInput(t4.getOutput(0));
        t3.addOutput(COIN, new ECKey());
        Transaction t1 = new Transaction(unitTestParams);
        t1.addInput(t2.getOutput(0));
        t1.addInput(t3.getOutput(0));
        Sha256Hash someHash = new Sha256Hash("2b801dd82f01d17bbde881687bf72bc62e2faa8ab8133d36fcb8c3abe7459da6");
        t1.addInput(new TransactionInput(unitTestParams, t1, new byte[]{}, new TransactionOutPoint(unitTestParams, 0, someHash)));
        Sha256Hash anotherHash = new Sha256Hash("3b801dd82f01d17bbde881687bf72bc62e2faa8ab8133d36fcb8c3abe7459da6");
        t1.addInput(new TransactionInput(unitTestParams, t1, new byte[]{}, new TransactionOutPoint(unitTestParams, 1, anotherHash)));
        t1.addOutput(COIN, to);
        t1 = FakeTxBuilder.roundTripTransaction(unitTestParams, t1);
        t2 = FakeTxBuilder.roundTripTransaction(unitTestParams, t2);
        t3 = FakeTxBuilder.roundTripTransaction(unitTestParams, t3);
        t4 = FakeTxBuilder.roundTripTransaction(unitTestParams, t4);

        // Announce the first one. Wait for it to be downloaded.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addTransaction(t1);
        inbound(writeTarget, inv);
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        Threading.waitForUserCode();
        assertEquals(t1.getHash(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t1);
        pingAndWait(writeTarget);
        assertEquals(t1, onTx[0]);
        // We want its dependencies so ask for them.
        ListenableFuture<List<Transaction>> futures = peer.downloadDependencies(t1);
        assertFalse(futures.isDone());
        // It will recursively ask for the dependencies of t1: t2, t3, someHash and anotherHash.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(4, getdata.getItems().size());
        assertEquals(t2.getHash(), getdata.getItems().get(0).hash);
        assertEquals(t3.getHash(), getdata.getItems().get(1).hash);
        assertEquals(someHash, getdata.getItems().get(2).hash);
        assertEquals(anotherHash, getdata.getItems().get(3).hash);
        long nonce = -1;
        if (!useNotFound)
            nonce = ((Ping) outbound(writeTarget)).getNonce();
        // For some random reason, t4 is delivered at this point before it's needed - perhaps it was a Bloom filter
        // false positive. We do this to check that the mempool is being checked for seen transactions before
        // requesting them.
        inbound(writeTarget, t4);
        // Deliver the requested transactions.
        inbound(writeTarget, t2);
        inbound(writeTarget, t3);
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, someHash));
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, anotherHash));
            inbound(writeTarget, notFound);
        } else {
            inbound(writeTarget, new Pong(nonce));
        }
        assertFalse(futures.isDone());
        // It will recursively ask for the dependencies of t2: t5 and t4, but not t3 because it already found t4.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(getdata.getItems().get(0).hash, t2.getInput(0).getOutpoint().getHash());
        // t5 isn't found and t4 is.
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, t5));
            inbound(writeTarget, notFound);
        } else {
            bouncePing();
        }
        assertFalse(futures.isDone());
        // Continue to explore the t4 branch and ask for t6, which is in the chain.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t6, getdata.getItems().get(0).hash);
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, t6));
            inbound(writeTarget, notFound);
        } else {
            bouncePing();
        }
        pingAndWait(writeTarget);
        // That's it, we explored the entire tree.
        assertTrue(futures.isDone());
        List<Transaction> results = futures.get();
        assertTrue(results.contains(t2));
        assertTrue(results.contains(t3));
        assertTrue(results.contains(t4));
    }

    private void bouncePing() throws Exception {
        Ping ping = (Ping) outbound(writeTarget);
        inbound(writeTarget, new Pong(ping.getNonce()));
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
        connectWithVersion(useNotFound ? 70001 : 60001);
        // Test that if we receive a relevant transaction that has a lock time, it doesn't result in a notification
        // until we explicitly opt in to seeing those.
        Wallet wallet = new Wallet(unitTestParams);
        ECKey key = wallet.freshReceiveKey();
        peer.addWallet(wallet);
        final Transaction[] vtx = new Transaction[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                vtx[0] = tx;
            }
        });
        // Send a normal relevant transaction, it's received correctly.
        Transaction t1 = FakeTxBuilder.createFakeTx(unitTestParams, COIN, key);
        inbound(writeTarget, t1);
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        if (useNotFound) {
            inbound(writeTarget, new NotFoundMessage(unitTestParams, getdata.getItems()));
        } else {
            bouncePing();
        }
        pingAndWait(writeTarget);
        Threading.waitForUserCode();
        assertNotNull(vtx[0]);
        vtx[0] = null;
        // Send a timelocked transaction, nothing happens.
        Transaction t2 = FakeTxBuilder.createFakeTx(unitTestParams, valueOf(2, 0), key);
        t2.setLockTime(999999);
        inbound(writeTarget, t2);
        Threading.waitForUserCode();
        assertNull(vtx[0]);
        // Now we want to hear about them. Send another, we are told about it.
        wallet.setAcceptRiskyTransactions(true);
        inbound(writeTarget, t2);
        getdata = (GetDataMessage) outbound(writeTarget);
        if (useNotFound) {
            inbound(writeTarget, new NotFoundMessage(unitTestParams, getdata.getItems()));
        } else {
            bouncePing();
        }
        pingAndWait(writeTarget);
        Threading.waitForUserCode();
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
        connectWithVersion(useNotFound ? 70001 : 60001);
        Wallet wallet = new Wallet(unitTestParams);
        ECKey key = wallet.freshReceiveKey();
        wallet.setAcceptRiskyTransactions(shouldAccept);
        peer.addWallet(wallet);
        final Transaction[] vtx = new Transaction[1];
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
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
        t2.addOutput(COIN, new ECKey());
        Transaction t1 = new Transaction(unitTestParams);
        t1.addInput(t2.getOutput(0));
        t1.addOutput(COIN, key);  // Make it relevant.
        // Announce t1.
        InventoryMessage inv = new InventoryMessage(unitTestParams);
        inv.addTransaction(t1);
        inbound(writeTarget, inv);
        // Send it.
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t1.getHash(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t1);
        // Nothing arrived at our event listener yet.
        assertNull(vtx[0]);
        // We request t2.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t2.getHash(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t2);
        if (!useNotFound)
            bouncePing();
        // We request t3.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t3, getdata.getItems().get(0).hash);
        // Can't find it: bottom of tree.
        if (useNotFound) {
            NotFoundMessage notFound = new NotFoundMessage(unitTestParams);
            notFound.addItem(new InventoryItem(InventoryItem.Type.Transaction, t3));
            inbound(writeTarget, notFound);
        } else {
            bouncePing();
        }
        pingAndWait(writeTarget);
        Threading.waitForUserCode();
        // We're done but still not notified because it was timelocked.
        if (shouldAccept)
            assertNotNull(vtx[0]);
        else
            assertNull(vtx[0]);
    }

    @Test
    public void disconnectOldVersions1() throws Exception {
        // Set up the connection with an old version.
        final SettableFuture<Void> connectedFuture = SettableFuture.create();
        final SettableFuture<Void> disconnectedFuture = SettableFuture.create();
        peer.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                connectedFuture.set(null);
            }

            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                disconnectedFuture.set(null);
            }
        });
        connectWithVersion(500);
        // We must wait uninterruptibly here because connect[WithVersion] generates a peer that interrupts the current
        // thread when it disconnects.
        Uninterruptibles.getUninterruptibly(connectedFuture);
        Uninterruptibles.getUninterruptibly(disconnectedFuture);
        try {
            peer.writeTarget.writeBytes(new byte[1]);
            fail();
        } catch (IOException e) {
            assertTrue((e.getCause() != null && e.getCause() instanceof CancelledKeyException)
                    || (e instanceof SocketException && e.getMessage().equals("Socket is closed")));
        }
    }

    @Test
    public void exceptionListener() throws Exception {
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                throw new NullPointerException("boo!");
            }
        });
        final Throwable[] throwables = new Throwable[1];
        Threading.uncaughtExceptionHandler = new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread thread, Throwable throwable) {
                throwables[0] = throwable;
            }
        };
        // In real usage we're not really meant to adjust the uncaught exception handler after stuff started happening
        // but in the unit test environment other tests have just run so the thread is probably still kicking around.
        // Force it to crash so it'll be recreated with our new handler.
        Threading.USER_THREAD.execute(new Runnable() {
            @Override
            public void run() {
                throw new RuntimeException();
            }
        });
        connect();
        Transaction t1 = new Transaction(unitTestParams);
        t1.addInput(new TransactionInput(unitTestParams, t1, new byte[]{}));
        t1.addOutput(COIN, new ECKey().toAddress(unitTestParams));
        Transaction t2 = new Transaction(unitTestParams);
        t2.addInput(t1.getOutput(0));
        t2.addOutput(COIN, wallet.getChangeAddress());
        inbound(writeTarget, t2);
        final InventoryItem inventoryItem = new InventoryItem(InventoryItem.Type.Transaction, t2.getInput(0).getOutpoint().getHash());
        final NotFoundMessage nfm = new NotFoundMessage(unitTestParams, Lists.newArrayList(inventoryItem));
        inbound(writeTarget, nfm);
        pingAndWait(writeTarget);
        Threading.waitForUserCode();
        assertTrue(throwables[0] instanceof NullPointerException);
        Threading.uncaughtExceptionHandler = null;
    }

    @Test
    public void badMessage() throws Exception {
        // Bring up an actual network connection and feed it bogus data.
        final SettableFuture<Void> result = SettableFuture.create();
        Threading.uncaughtExceptionHandler = new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread thread, Throwable throwable) {
                result.setException(throwable);
            }
        };
        connect(); // Writes out a verack+version.
        final SettableFuture<Void> peerDisconnected = SettableFuture.create();
        writeTarget.peer.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerDisconnected(Peer p, int peerCount) {
                peerDisconnected.set(null);
            }
        });
        final NetworkParameters params = TestNet3Params.get();
        BitcoinSerializer serializer = new BitcoinSerializer(params);
        // Now write some bogus truncated message.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        serializer.serialize("inv", new InventoryMessage(params) {
            @Override
            public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
                // Add some hashes.
                addItem(new InventoryItem(InventoryItem.Type.Transaction, Sha256Hash.create(new byte[] { 1 })));
                addItem(new InventoryItem(InventoryItem.Type.Transaction, Sha256Hash.create(new byte[] { 2 })));
                addItem(new InventoryItem(InventoryItem.Type.Transaction, Sha256Hash.create(new byte[] { 3 })));

                // Write out a copy that's truncated in the middle.
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                super.bitcoinSerializeToStream(bos);
                byte[] bits = bos.toByteArray();
                bits = Arrays.copyOf(bits, bits.length / 2);
                stream.write(bits);
            }
        }.bitcoinSerialize(), out);
        writeTarget.writeTarget.writeBytes(out.toByteArray());
        try {
            result.get();
            fail();
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof ProtocolException);
        }
        peerDisconnected.get();
        try {
            peer.writeTarget.writeBytes(new byte[1]);
            fail();
        } catch (IOException e) {
            assertTrue((e.getCause() != null && e.getCause() instanceof CancelledKeyException)
                    || (e instanceof SocketException && e.getMessage().equals("Socket is closed")));
        }
    }
}
