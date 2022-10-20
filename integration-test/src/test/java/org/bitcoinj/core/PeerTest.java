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

import com.google.common.collect.Lists;
import com.google.common.util.concurrent.Uninterruptibles;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.listeners.BlocksDownloadedEventListener;
import org.bitcoinj.core.listeners.PreMessageReceivedEventListener;
import org.bitcoinj.testing.InboundMessageQueuer;
import org.bitcoinj.testing.TestWithNetworkConnections;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.channels.CancelledKeyException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.base.Coin.valueOf;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;
import static org.bitcoinj.testing.FakeTxBuilder.makeSolvedTestBlock;
import static org.bitcoinj.testing.FakeTxBuilder.roundTripTransaction;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(value = Parameterized.class)
public class PeerTest extends TestWithNetworkConnections {
    private Peer peer;
    private InboundMessageQueuer writeTarget;
    private static final int OTHER_PEER_CHAIN_HEIGHT = 110;
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
        VersionMessage ver = new VersionMessage(TESTNET, 100);
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 4000);
        peer = new Peer(TESTNET, ver, new PeerAddress(TESTNET, address), blockChain);
        peer.addWallet(wallet);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        assertFalse(fail.get());
    }

    private void connect() throws Exception {
        connectWithVersion(70001, VersionMessage.NODE_NETWORK);
    }

    private void connectWithVersion(int version, int flags) throws Exception {
        VersionMessage peerVersion = new VersionMessage(TESTNET, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = version;
        peerVersion.localServices = flags;
        writeTarget = connect(peer, peerVersion);
    }

    // Check that it runs through the event loop and shut down correctly
    @Test
    public void shutdown() throws Exception {
        closePeer(peer);
    }

    @Test
    public void chainDownloadEnd2End() throws Exception {
        // A full end-to-end test of the chain download process, with a new block being solved in the middle.
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
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
        InventoryMessage inv = new InventoryMessage(TESTNET);
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

        inv = new InventoryMessage(TESTNET);
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
        assertEquals(b3.getHash(), getblocks.getLocator().getHashes().get(0));
        // At this point another block is solved and broadcast. The inv triggers a getdata but we do NOT send another
        // getblocks afterwards, because that would result in us receiving the same set of blocks twice which is a
        // timewaste. The getblocks message that would have been generated is set to be the same as the previous
        // because we walk backwards down the orphan chain and then discover we already asked for those blocks, so
        // nothing is done.
        Block b6 = makeSolvedTestBlock(b5);
        inv = new InventoryMessage(TESTNET);
        inv.addBlock(b6);
        inbound(writeTarget, inv);
        getdata = (GetDataMessage)outbound(writeTarget);
        assertEquals(1, getdata.getItems().size());
        assertEquals(b6.getHash(), getdata.getItems().get(0).hash);
        inbound(writeTarget, b6);
        assertNull(outbound(writeTarget));  // Nothing is sent at this point.
        // We're still waiting for the response to the getblocks (b3,b5) sent above.
        inv = new InventoryMessage(TESTNET);
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

        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
        blockChain.add(b1);
        // Make a missing block.
        Block b2 = makeSolvedTestBlock(b1);
        Block b3 = makeSolvedTestBlock(b2);
        inbound(writeTarget, b3);
        InventoryMessage inv = new InventoryMessage(TESTNET);
        InventoryItem item = new InventoryItem(InventoryItem.Type.BLOCK, b3.getHash());
        inv.addItem(item);
        inbound(writeTarget, inv);

        GetBlocksMessage getblocks = (GetBlocksMessage)outbound(writeTarget);
        BlockLocator expectedLocator = new BlockLocator();
        expectedLocator = expectedLocator.add(b1.getHash());
        expectedLocator = expectedLocator.add(TESTNET.getGenesisBlock().getHash());
        
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
        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);

        // Receive an inv.
        InventoryMessage inv = new InventoryMessage(TESTNET);
        InventoryItem item = new InventoryItem(InventoryItem.Type.BLOCK, b2.getHash());
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
        Transaction tx = createFakeTx(TESTNET, value, address);
        InventoryMessage inv = new InventoryMessage(TESTNET);
        InventoryItem item = new InventoryItem(InventoryItem.Type.TRANSACTION, tx.getTxId());
        inv.addItem(item);
        inbound(writeTarget, inv);
        // Peer hasn't seen it before, so will ask for it.
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(1, getdata.getItems().size());
        assertEquals(tx.getTxId(), getdata.getItems().get(0).hash);
        inbound(writeTarget, tx);
        // Ask for the dependency, it's not in the mempool (in chain).
        getdata = (GetDataMessage) outbound(writeTarget);
        inbound(writeTarget, new NotFoundMessage(TESTNET, getdata.getItems()));
        pingAndWait(writeTarget);
        assertEquals(value, wallet.getBalance(Wallet.BalanceType.ESTIMATED));
    }

    @Test
    public void invDownloadTxMultiPeer() throws Exception {
        // Check co-ordination of which peer to download via the memory pool.
        VersionMessage ver = new VersionMessage(TESTNET, 100);
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 4242);
        Peer peer2 = new Peer(TESTNET, ver, new PeerAddress(TESTNET, address), blockChain);
        peer2.addWallet(wallet);
        VersionMessage peerVersion = new VersionMessage(TESTNET, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = 70001;
        peerVersion.localServices = VersionMessage.NODE_NETWORK;

        connect();
        InboundMessageQueuer writeTarget2 = connect(peer2, peerVersion);

        // Make a tx and advertise it to one of the peers.
        Coin value = COIN;
        Transaction tx = createFakeTx(TESTNET, value, this.address);
        InventoryMessage inv = new InventoryMessage(TESTNET);
        InventoryItem item = new InventoryItem(InventoryItem.Type.TRANSACTION, tx.getTxId());
        inv.addItem(item);

        inbound(writeTarget, inv);

        // We got a getdata message.
        GetDataMessage message = (GetDataMessage)outbound(writeTarget);
        assertEquals(1, message.getItems().size());
        assertEquals(tx.getTxId(), message.getItems().get(0).hash);
        assertNotEquals(0, tx.getConfidence().numBroadcastPeers());

        // Advertising to peer2 results in no getdata message.
        inbound(writeTarget2, inv);
        pingAndWait(writeTarget2);
        assertNull(outbound(writeTarget2));
    }

    // Check that inventory message containing blocks we want is processed correctly.
    @Test
    public void newBlock() throws Exception {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
        blockChain.add(b1);
        final Block b2 = makeSolvedTestBlock(b1);
        // Receive notification of a new block.
        final InventoryMessage inv = new InventoryMessage(TESTNET);
        InventoryItem item = new InventoryItem(InventoryItem.Type.BLOCK, b2.getHash());
        inv.addItem(item);

        final AtomicInteger newBlockMessagesReceived = new AtomicInteger(0);

        connect();
        // Round-trip a ping so that we never see the response verack if we attach too quick
        pingAndWait(writeTarget);
        peer.addPreMessageReceivedEventListener(Threading.SAME_THREAD, new PreMessageReceivedEventListener() {
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
        });
        peer.addBlocksDownloadedEventListener(Threading.SAME_THREAD, new BlocksDownloadedEventListener() {
            @Override
            public synchronized void onBlocksDownloaded(Peer p, Block block, @Nullable FilteredBlock filteredBlock,  int blocksLeft) {
                int newValue = newBlockMessagesReceived.incrementAndGet();
                if (newValue != 3 || p != peer || !block.equals(b2) || blocksLeft != OTHER_PEER_CHAIN_HEIGHT - 2)
                    fail.set(true);
            }
        });
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
        assertEquals(InventoryItem.Type.BLOCK, items.get(0).type);
    }

    // Check that it starts downloading the block chain correctly on request.
    @Test
    public void startBlockChainDownload() throws Exception {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        blockChain.add(b2);

        connect();
        fail.set(true);
        peer.addChainDownloadStartedEventListener(Threading.SAME_THREAD, (p, blocksLeft) -> {
            if (p == peer && blocksLeft == 108)
                fail.set(false);
        });
        peer.startBlockChainDownload();

        BlockLocator expectedLocator = new BlockLocator();
        expectedLocator = expectedLocator.add(b2.getHash());
        expectedLocator = expectedLocator.add(b1.getHash());
        expectedLocator = expectedLocator.add(TESTNET.getGenesisBlock().getHash());

        GetBlocksMessage message = (GetBlocksMessage) outbound(writeTarget);
        assertEquals(message.getLocator(), expectedLocator);
        assertEquals(Sha256Hash.ZERO_HASH, message.getStopHash());
    }

    @Test
    public void getBlock() throws Exception {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        connect();

        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
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
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        connect();

        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
        blockChain.add(b1);
        Block b2 = makeSolvedTestBlock(b1);
        Transaction t = new Transaction(TESTNET);
        t.addInput(b1.getTransactions().get(0).getOutput(0));
        t.addOutput(new TransactionOutput(TESTNET, t, Coin.ZERO, new byte[Block.MAX_BLOCK_SIZE - 1000]));
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
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        connect();
        Utils.setMockClock();
        // Check that blocks before the fast catchup point are retrieved using getheaders, and after using getblocks.
        // This test is INCOMPLETE because it does not check we handle >2000 blocks correctly.
        Block b1 = createFakeBlock(blockStore, Block.BLOCK_HEIGHT_GENESIS).block;
        blockChain.add(b1);
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b2 = makeSolvedTestBlock(b1);
        b2.setTime(Utils.currentTimeSeconds());
        b2.solve();
        Utils.rollMockClock(60 * 10);  // 10 minutes later.
        Block b3 = makeSolvedTestBlock(b2);
        b3.setTime(Utils.currentTimeSeconds());
        b3.solve();
        Utils.rollMockClock(60 * 10);
        Block b4 = makeSolvedTestBlock(b3);
        b4.setTime(Utils.currentTimeSeconds());
        b4.solve();

        // Request headers until the last 2 blocks.
        peer.setDownloadParameters(Utils.currentTimeSeconds() - (600*2) + 1, false);
        peer.startBlockChainDownload();
        GetHeadersMessage getheaders = (GetHeadersMessage) outbound(writeTarget);
        BlockLocator expectedLocator = new BlockLocator();
        expectedLocator = expectedLocator.add(b1.getHash());
        expectedLocator = expectedLocator.add(TESTNET.getGenesisBlock().getHash());
        assertEquals(getheaders.getLocator(), expectedLocator);
        assertEquals(getheaders.getStopHash(), Sha256Hash.ZERO_HASH);
        // Now send all the headers.
        HeadersMessage headers = new HeadersMessage(TESTNET, b2.cloneAsHeader(),
                b3.cloneAsHeader(), b4.cloneAsHeader());
        // We expect to be asked for b3 and b4 again, but this time, with a body.
        expectedLocator = new BlockLocator();
        expectedLocator = expectedLocator.add(b2.getHash());
        expectedLocator = expectedLocator.add(b1.getHash());
        expectedLocator = expectedLocator.add(TESTNET.getGenesisBlock().getHash());
        inbound(writeTarget, headers);
        GetBlocksMessage getblocks = (GetBlocksMessage) outbound(writeTarget);
        assertEquals(expectedLocator, getblocks.getLocator());
        assertEquals(Sha256Hash.ZERO_HASH, getblocks.getStopHash());
        // We're supposed to get an inv here.
        InventoryMessage inv = new InventoryMessage(TESTNET);
        inv.addItem(new InventoryItem(InventoryItem.Type.BLOCK, b3.getHash()));
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
        CompletableFuture<Long> future = peer.ping();
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
        Transaction tx = createFakeTx(TESTNET, COIN, address);
        final Transaction[] result = new Transaction[1];
        wallet.addCoinsReceivedEventListener((wallet, tx1, prevBalance, newBalance) -> result[0] = tx1);
        inbound(writeTarget, tx);
        pingAndWait(writeTarget);
        assertEquals(tx, result[0]);
    }

    @Test
    public void recursiveDependencyDownload() throws Exception {
        connect();
        // Check that we can download all dependencies of an unconfirmed relevant transaction from the mempool.
        ECKey to = new ECKey();

        final Transaction[] onTx = new Transaction[1];
        peer.addOnTransactionBroadcastListener(Threading.SAME_THREAD, (peer1, t) -> onTx[0] = t);

        // Make some fake transactions in the following graph:
        //   t1 -> t2 -> [t5]
        //      -> t3 -> t4 -> [t6]
        //      -> [t7]
        //      -> [t8]
        // The ones in brackets are assumed to be in the chain and are represented only by hashes.
        Transaction t2 = createFakeTx(TESTNET, COIN, to);
        Sha256Hash t5hash = t2.getInput(0).getOutpoint().getHash();
        Transaction t4 = createFakeTx(TESTNET, COIN, new ECKey());
        Sha256Hash t6hash = t4.getInput(0).getOutpoint().getHash();
        t4.addOutput(COIN, new ECKey());
        Transaction t3 = new Transaction(TESTNET);
        t3.addInput(t4.getOutput(0));
        t3.addOutput(COIN, new ECKey());
        Transaction t1 = new Transaction(TESTNET);
        t1.addInput(t2.getOutput(0));
        t1.addInput(t3.getOutput(0));
        Sha256Hash t7hash = Sha256Hash.wrap("2b801dd82f01d17bbde881687bf72bc62e2faa8ab8133d36fcb8c3abe7459da6");
        t1.addInput(new TransactionInput(TESTNET, t1, new byte[]{}, new TransactionOutPoint(TESTNET, 0, t7hash)));
        Sha256Hash t8hash = Sha256Hash.wrap("3b801dd82f01d17bbde881687bf72bc62e2faa8ab8133d36fcb8c3abe7459da6");
        t1.addInput(new TransactionInput(TESTNET, t1, new byte[]{}, new TransactionOutPoint(TESTNET, 1, t8hash)));
        t1.addOutput(COIN, to);
        t1 = roundTripTransaction(TESTNET, t1);
        t2 = roundTripTransaction(TESTNET, t2);
        t3 = roundTripTransaction(TESTNET, t3);
        t4 = roundTripTransaction(TESTNET, t4);

        // Announce the first one. Wait for it to be downloaded.
        InventoryMessage inv = new InventoryMessage(TESTNET);
        inv.addTransaction(t1);
        inbound(writeTarget, inv);
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        Threading.waitForUserCode();
        assertEquals(t1.getTxId(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t1);
        pingAndWait(writeTarget);
        assertEquals(t1, onTx[0]);
        // We want its dependencies so ask for them.
        CompletableFuture<List<Transaction>> futures = peer.downloadDependencies(t1);
        assertFalse(futures.isDone());
        // It will recursively ask for the dependencies of t1: t2, t3, t7, t8.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(4, getdata.getItems().size());
        assertEquals(t2.getTxId(), getdata.getItems().get(0).hash);
        assertEquals(t3.getTxId(), getdata.getItems().get(1).hash);
        assertEquals(t7hash, getdata.getItems().get(2).hash);
        assertEquals(t8hash, getdata.getItems().get(3).hash);
        // Deliver the requested transactions.
        inbound(writeTarget, t2);
        inbound(writeTarget, t3);
        NotFoundMessage notFound = new NotFoundMessage(TESTNET);
        notFound.addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, t7hash));
        notFound.addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, t8hash));
        inbound(writeTarget, notFound);
        assertFalse(futures.isDone());
        // It will recursively ask for the dependencies of t2: t5 and t4, but not t3 because it already found t4.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(getdata.getItems().get(0).hash, t2.getInput(0).getOutpoint().getHash());
        // t5 isn't found and t4 is.
        notFound = new NotFoundMessage(TESTNET);
        notFound.addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, t5hash));
        inbound(writeTarget, notFound);
        assertFalse(futures.isDone());
        // Request t4 ...
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t4.getTxId(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t4);
        // Continue to explore the t4 branch and ask for t6, which is in the chain.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t6hash, getdata.getItems().get(0).hash);
        notFound = new NotFoundMessage(TESTNET);
        notFound.addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, t6hash));
        inbound(writeTarget, notFound);
        pingAndWait(writeTarget);
        // That's it, we explored the entire tree.
        assertTrue(futures.isDone());
        List<Transaction> results = futures.get();
        assertEquals(3, results.size());
        assertTrue(results.contains(t2));
        assertTrue(results.contains(t3));
        assertTrue(results.contains(t4));
    }

    @Test
    public void recursiveDependencyDownload_depthLimited() throws Exception {
        peer.setDownloadTxDependencies(1); // Depth limit
        connect();

        // Make some fake transactions in the following graph:
        //   t1 -> t2 -> t3 -> [t4]
        // The ones in brackets are assumed to be in the chain and are represented only by hashes.
        Sha256Hash t4hash = Sha256Hash.wrap("2b801dd82f01d17bbde881687bf72bc62e2faa8ab8133d36fcb8c3abe7459da6");
        Transaction t3 = new Transaction(TESTNET);
        t3.addInput(new TransactionInput(TESTNET, t3, new byte[]{}, new TransactionOutPoint(TESTNET, 0, t4hash)));
        t3.addOutput(COIN, new ECKey());
        t3 = roundTripTransaction(TESTNET, t3);
        Transaction t2 = new Transaction(TESTNET);
        t2.addInput(t3.getOutput(0));
        t2.addOutput(COIN, new ECKey());
        t2 = roundTripTransaction(TESTNET, t2);
        Transaction t1 = new Transaction(TESTNET);
        t1.addInput(t2.getOutput(0));
        t1.addOutput(COIN, new ECKey());
        t1 = roundTripTransaction(TESTNET, t1);

        // Announce the first one. Wait for it to be downloaded.
        InventoryMessage inv = new InventoryMessage(TESTNET);
        inv.addTransaction(t1);
        inbound(writeTarget, inv);
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        Threading.waitForUserCode();
        assertEquals(t1.getTxId(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t1);
        pingAndWait(writeTarget);
        // We want its dependencies so ask for them.
        CompletableFuture<List<Transaction>> futures = peer.downloadDependencies(t1);
        assertFalse(futures.isDone());
        // level 1
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(1, getdata.getItems().size());
        assertEquals(t2.getTxId(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t2);
        // no level 2
        getdata = (GetDataMessage) outbound(writeTarget);
        assertNull(getdata);

        // That's it, now double check what we've got
        pingAndWait(writeTarget);
        assertTrue(futures.isDone());
        List<Transaction> results = futures.get();
        assertEquals(1, results.size());
        assertTrue(results.contains(t2));
    }

    @Test
    public void timeLockedTransactionNew() throws Exception {
        connectWithVersion(70001, VersionMessage.NODE_NETWORK);
        // Test that if we receive a relevant transaction that has a lock time, it doesn't result in a notification
        // until we explicitly opt in to seeing those.
        Wallet wallet = Wallet.createDeterministic(TESTNET, ScriptType.P2PKH);
        ECKey key = wallet.freshReceiveKey();
        peer.addWallet(wallet);
        final Transaction[] vtx = new Transaction[1];
        wallet.addCoinsReceivedEventListener((wallet1, tx, prevBalance, newBalance) -> vtx[0] = tx);
        // Send a normal relevant transaction, it's received correctly.
        Transaction t1 = createFakeTx(TESTNET, COIN, key);
        inbound(writeTarget, t1);
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        inbound(writeTarget, new NotFoundMessage(TESTNET, getdata.getItems()));
        pingAndWait(writeTarget);
        Threading.waitForUserCode();
        assertNotNull(vtx[0]);
        vtx[0] = null;
        // Send a timelocked transaction, nothing happens.
        Transaction t2 = createFakeTx(TESTNET, valueOf(2, 0), key);
        t2.setLockTime(999999);
        inbound(writeTarget, t2);
        Threading.waitForUserCode();
        assertNull(vtx[0]);
        // Now we want to hear about them. Send another, we are told about it.
        wallet.setAcceptRiskyTransactions(true);
        inbound(writeTarget, t2);
        getdata = (GetDataMessage) outbound(writeTarget);
        inbound(writeTarget, new NotFoundMessage(TESTNET, getdata.getItems()));
        pingAndWait(writeTarget);
        Threading.waitForUserCode();
        assertEquals(t2, vtx[0]);
    }

    @Test
    public void rejectTimeLockedDependency() throws Exception {
        // Check that we also verify the lock times of dependencies. Otherwise an attacker could still build a tx that
        // looks legitimate and useful but won't actually ever confirm, by sending us a normal tx that spends a
        // timelocked tx.
        checkTimeLockedDependency(false);
    }

    @Test
    public void acceptTimeLockedDependency() throws Exception {
        checkTimeLockedDependency(true);
    }

    private void checkTimeLockedDependency(boolean shouldAccept) throws Exception {
        // Initial setup.
        connectWithVersion(70001, VersionMessage.NODE_NETWORK);
        Wallet wallet = Wallet.createDeterministic(TESTNET, ScriptType.P2PKH);
        ECKey key = wallet.freshReceiveKey();
        wallet.setAcceptRiskyTransactions(shouldAccept);
        peer.addWallet(wallet);
        final Transaction[] vtx = new Transaction[1];
        wallet.addCoinsReceivedEventListener((wallet1, tx, prevBalance, newBalance) -> vtx[0] = tx);
        // t1 -> t2 [locked] -> t3 (not available)
        Transaction t2 = new Transaction(TESTNET);
        t2.setLockTime(999999);
        // Add a fake input to t3 that goes nowhere.
        Sha256Hash t3 = Sha256Hash.of("abc".getBytes(StandardCharsets.UTF_8));
        t2.addInput(new TransactionInput(TESTNET, t2, new byte[]{}, new TransactionOutPoint(TESTNET, 0, t3)));
        t2.getInput(0).setSequenceNumber(0xDEADBEEF);
        t2.addOutput(COIN, new ECKey());
        Transaction t1 = new Transaction(TESTNET);
        t1.addInput(t2.getOutput(0));
        t1.addOutput(COIN, key);  // Make it relevant.
        // Announce t1.
        InventoryMessage inv = new InventoryMessage(TESTNET);
        inv.addTransaction(t1);
        inbound(writeTarget, inv);
        // Send it.
        GetDataMessage getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t1.getTxId(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t1);
        // Nothing arrived at our event listener yet.
        assertNull(vtx[0]);
        // We request t2.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t2.getTxId(), getdata.getItems().get(0).hash);
        inbound(writeTarget, t2);
        // We request t3.
        getdata = (GetDataMessage) outbound(writeTarget);
        assertEquals(t3, getdata.getItems().get(0).hash);
        // Can't find it: bottom of tree.
        NotFoundMessage notFound = new NotFoundMessage(TESTNET);
        notFound.addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, t3));
        inbound(writeTarget, notFound);
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
        final CompletableFuture<Void> connectedFuture = new CompletableFuture<>();
        final CompletableFuture<Void> disconnectedFuture = new CompletableFuture<>();
        peer.addConnectedEventListener((peer, peerCount) -> connectedFuture.complete(null));

        peer.addDisconnectedEventListener((peer, peerCount) -> disconnectedFuture.complete(null));
        connectWithVersion(500, VersionMessage.NODE_NETWORK);
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
        wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> {
            throw new NullPointerException("boo!");
        });
        final Throwable[] throwables = new Throwable[1];
        Threading.uncaughtExceptionHandler = (thread, throwable) -> throwables[0] = throwable;
        // In real usage we're not really meant to adjust the uncaught exception handler after stuff started happening
        // but in the unit test environment other tests have just run so the thread is probably still kicking around.
        // Force it to crash so it'll be recreated with our new handler.
        Threading.USER_THREAD.execute(() -> {
            throw new RuntimeException();
        });
        connect();
        Transaction t1 = new Transaction(TESTNET);
        t1.addInput(new TransactionInput(TESTNET, t1, new byte[]{}));
        t1.addOutput(COIN, new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET));
        Transaction t2 = new Transaction(TESTNET);
        t2.addInput(t1.getOutput(0));
        t2.addOutput(COIN, wallet.currentChangeAddress());
        inbound(writeTarget, t2);
        final InventoryItem inventoryItem = new InventoryItem(InventoryItem.Type.TRANSACTION, t2.getInput(0).getOutpoint().getHash());
        final NotFoundMessage nfm = new NotFoundMessage(TESTNET, Lists.newArrayList(inventoryItem));
        inbound(writeTarget, nfm);
        pingAndWait(writeTarget);
        Threading.waitForUserCode();
        assertTrue(throwables[0] instanceof NullPointerException);
        Threading.uncaughtExceptionHandler = null;
    }

    @Test
    public void badMessage() throws Exception {
        // Bring up an actual network connection and feed it bogus data.
        final CompletableFuture<Void> result = new CompletableFuture<>();
        Threading.uncaughtExceptionHandler = (thread, throwable) -> result.completeExceptionally(throwable);
        connect(); // Writes out a verack+version.
        final CompletableFuture<Void> peerDisconnected = new CompletableFuture<>();
        writeTarget.peer.addDisconnectedEventListener((p, peerCount) -> peerDisconnected.complete(null));
        MessageSerializer serializer = TESTNET.getDefaultSerializer();
        // Now write some bogus truncated message.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        serializer.serialize("inv", new InventoryMessage(TESTNET) {
            @Override
            public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
                // Add some hashes.
                addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, Sha256Hash.of(new byte[]{1})));
                addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, Sha256Hash.of(new byte[]{2})));
                addItem(new InventoryItem(InventoryItem.Type.TRANSACTION, Sha256Hash.of(new byte[]{3})));

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
