/**
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Peer handles the high level communication with a BitCoin node. It requires a NetworkConnection to be set up for
 * it. After that it takes ownership of the connection, creates and manages its own thread used for communication
 * with the network. All these threads synchronize on the block chain.
 */
public class Peer {
	private static final Logger log = LoggerFactory.getLogger(Peer.class);
	
    private final NetworkConnection conn;
    private final NetworkParameters params;
    private Thread thread;
    // Whether the peer thread is supposed to be running or not. Set to false during shutdown so the peer thread
    // knows to quit when the socket goes away.
    private boolean running;
    private final BlockChain blockChain;

    // Used to notify clients when the initial block chain download is finished.
    private CountDownLatch chainCompletionLatch;
    // When we want to download a block or transaction from a peer, the InventoryItem is put here whilst waiting for
    // the response. Synchronized on itself.
    private final List<GetDataFuture<Block>> pendingGetBlockFutures;

    /**
     * Construct a peer that handles the given network connection and reads/writes from the given block chain. Note that
     * communication won't occur until you call start().
     */
    public Peer(NetworkParameters params, NetworkConnection conn, BlockChain blockChain) {
        this.conn = conn;
        this.params = params;
        this.blockChain = blockChain;
        this.pendingGetBlockFutures = new ArrayList<GetDataFuture<Block>>();
    }

    /** Starts the background thread that processes messages. */
    public void start() {
        this.thread = new Thread(new Runnable() {
            public void run() {
                Peer.this.run();
            }
        });
        synchronized (this) {
            running = true;
        }
        this.thread.setName("Bitcoin peer thread: " + conn.toString());
        this.thread.start();
    }

    /**
     * Runs in the peers network thread and manages communication with the peer.
     */
    private void run() {
        assert Thread.currentThread() == thread;
        try {
            while (true) {
                Message m = conn.readMessage();
                if (m instanceof InventoryMessage) {
                    processInv((InventoryMessage) m);
                } else if (m instanceof Block) {
                    processBlock((Block) m);
                } else if (m  instanceof AddressMessage) {
                    // We don't care about addresses of the network right now. But in future,
                    // we should save them in the wallet so we don't put too much load on the seed nodes and can
                    // properly explore the network.
                } else {
                    // TODO: Handle the other messages we can receive.
                    log.warn("Received unhandled message: {}", m);
                }
            }
        } catch (Exception e) {
            if (e instanceof IOException && !running) {
                // This exception was expected because we are tearing down the socket as part of quitting.
                log.info("Shutting down peer thread");
            } else {
                // We caught an unexpected exception.
                e.printStackTrace();
            }
        }
        synchronized (this) {
            running = false;
        }
    }

    private void processBlock(Block m) throws IOException {
        assert Thread.currentThread() == thread;
        try {
            // Was this block requested by getBlock()?
            synchronized (pendingGetBlockFutures) {
                for (int i = 0; i < pendingGetBlockFutures.size(); i++) {
                    GetDataFuture<Block> f = pendingGetBlockFutures.get(i);
                    if (Arrays.equals(f.getItem().hash, m.getHash())) {
                        // Yes, it was. So pass it through the future.
                        f.setResult(m);
                        // Blocks explicitly requested don't get sent to the block chain.
                        pendingGetBlockFutures.remove(i);
                        return;
                    }
                }
            }
            // Otherwise it's a block sent to us because the peer thought we needed it, so add it to the block chain.
            // This call will synchronize on blockChain.
            if (blockChain.add(m)) {
                // The block was successfully linked into the chain. Notify the user of our progress.
                if (chainCompletionLatch != null) {
                    chainCompletionLatch.countDown();
                    if (chainCompletionLatch.getCount() == 0) {
                        // All blocks fetched, so we don't need this anymore.
                        chainCompletionLatch = null;
                    }
                }
            } else {
                // This block is unconnected - we don't know how to get from it back to the genesis block yet. That
                // must mean that there are blocks we are missing, so do another getblocks with a new block locator
                // to ask the peer to send them to us. This can happen during the initial block chain download where
                // the peer will only send us 500 at a time and then sends us the head block expecting us to request
                // the others.

                // TODO: Should actually request root of orphan chain here.
                blockChainDownload(m.getHash());
            }
        } catch (VerificationException e) {
            // We don't want verification failures to kill the thread.
        	log.warn("block verification failed", e);
        } catch (ScriptException e) {
            // We don't want script failures to kill the thread.
        	log.warn("script exception", e);
        }
    }

    private void processInv(InventoryMessage inv) throws IOException {
        assert Thread.currentThread() == thread;
        // The peer told us about some blocks or transactions they have. For now we only care about blocks.
        // Note that as we don't actually want to store the entire block chain or even the headers of the block
        // chain, we may end up requesting blocks we already requested before. This shouldn't (in theory) happen
        // enough to be a problem.
        Block topBlock = blockChain.getUnconnectedBlock();
        byte[] topHash = (topBlock != null ? topBlock.getHash() : null);
        if (inv.items.size() == 1 && inv.items.get(0).type == InventoryItem.Type.Block && topHash != null &&
                Arrays.equals(inv.items.get(0).hash, topHash)) {
            // An inv with a single hash containing our most recent unconnected block is a special inv,
            // it's kind of like a tickle from the peer telling us that it's time to download more blocks to catch up to
            // the block chain. We could just ignore this and treat it as a regular inv but then we'd download the head
            // block over and over again after each batch of 500 blocks, which is wasteful.
            blockChainDownload(topHash);
            return;
        }
        InventoryMessage getdata = new InventoryMessage(params);
        for (InventoryItem item : inv.items) {
            if (item.type != InventoryItem.Type.Block) continue;
            getdata.items.add(item);
        }
        // No blocks to download. This probably contained transactions instead, but right now we can't prove they are
        // valid so we don't bother downloading transactions that aren't in blocks yet.
        if (getdata.items.size() == 0)
            return;
        // This will cause us to receive a bunch of block messages.
        conn.writeMessage(NetworkConnection.MSG_GETDATA, getdata);
    }

    /**
     * Asks the connected peer for the block of the given hash, and returns a Future representing the answer.
     * If you want the block right away and don't mind waiting for it, just call .get() on the result. Your thread
     * will block until the peer answers. You can also use the Future object to wait with a timeout, or just check
     * whether it's done later.
     *
     * @param blockHash Hash of the block you wareare requesting.
     * @throws IOException
     */
    public Future<Block> getBlock(byte[] blockHash) throws IOException {
        InventoryMessage getdata = new InventoryMessage(params);
        InventoryItem inventoryItem = new InventoryItem(InventoryItem.Type.Block, blockHash);
        getdata.items.add(inventoryItem);
        GetDataFuture<Block> future = new GetDataFuture<Block>(inventoryItem);
        // Add to the list of things we're waiting for. It's important this come before the network send to avoid
        // race conditions.
        synchronized (pendingGetBlockFutures) {
          pendingGetBlockFutures.add(future);
        }
        conn.writeMessage(NetworkConnection.MSG_GETDATA, getdata);
        return future;
    }

    // A GetDataFuture wraps the result of a getBlock or (in future) getTransaction so the owner of the object can
    // decide whether to wait forever, wait for a short while or check later after doing other work.
    private class GetDataFuture<T extends Message> implements Future<T> {
        private boolean cancelled;
        private final InventoryItem item;
        private final CountDownLatch latch;
        private T result;

        GetDataFuture(InventoryItem item) {
            this.item = item;
            this.latch = new CountDownLatch(1);
        }

        public boolean cancel(boolean b) {
            // Cannot cancel a getdata - once sent, it's sent.
            cancelled = true;
            return false;
        }

        public boolean isCancelled() {
            return cancelled;
        }

        public boolean isDone() {
            return result != null || cancelled;
        }

        public T get() throws InterruptedException, ExecutionException {
            latch.await();
            assert result != null;
            return result;
        }

        public T get(long l, TimeUnit timeUnit) throws InterruptedException, ExecutionException, TimeoutException {
            if (!latch.await(l, timeUnit))
                throw new TimeoutException();
            assert result != null;
            return result;
        }

        InventoryItem getItem() {
            return item;
        }

        /** Called by the Peer when the result has arrived. Completes the task. */
        void setResult(T result) {
            assert Thread.currentThread() == thread;  // Called from peer thread.
            this.result = result;
            // Now release the thread that is waiting. We don't need to synchronize here as the latch establishes
            // a memory barrier.
            latch.countDown();
        }
    }

    /**
     * Send the given Transaction, ie, make a payment with BitCoins. To create a transaction you can broadcast, use
     * a {@link Wallet}. After the broadcast completes, confirm the send using the wallet confirmSend() method.
     * @throws IOException
     */
    void broadcastTransaction(Transaction tx) throws IOException {
        conn.writeMessage(NetworkConnection.MSG_TX, tx);
    }

    private void blockChainDownload(byte[] toHash) throws IOException {
        // This may run in ANY thread.

        // The block chain download process is a bit complicated. Basically, we start with zero or more blocks in a
        // chain that we have from a previous session. We want to catch up to the head of the chain BUT we don't know
        // where that chain is up to or even if the top block we have is even still in the chain - we
        // might have got ourselves onto a fork that was later resolved by the network.
        //
        // To solve this, we send the peer a block locator which is just a list of block hashes. It contains the
        // blocks we know about, but not all of them, just enough of them so the peer can figure out if we did end up
        // on a fork and if so, what the earliest still valid block we know about is likely to be.
        //
        // Once it has decided which blocks we need, it will send us an inv with up to 500 block messages. We may
        // have some of them already if we already have a block chain and just need to catch up. Once we request the
        // last block, if there are still more to come it sends us an "inv" containing only the hash of the head
        // block.
        //
        // That causes us to download the head block but then we find (in processBlock) that we can't connect
        // it to the chain yet because we don't have the intermediate blocks. So we rerun this function building a
        // new block locator describing where we're up to.
        //
        // The getblocks with the new locator gets us another inv with another bunch of blocks. We download them once
        // again. This time when the peer sends us an inv with the head block, we already have it so we won't download
        // it again - but we recognize this case as special and call back into blockChainDownload to continue the
        // process.
        //
        // So this is a complicated process but it has the advantage that we can download a chain of enormous length
        // in a relatively stateless manner and with constant/bounded memory usage.
        log.info("blockChainDownload({})", Utils.bytesToHexString(toHash));

        // TODO: Block locators should be abstracted out rather than special cased here.
        List<byte[]> blockLocator = new LinkedList<byte[]>();
        // We don't do the exponential thinning here, so if we get onto a fork of the chain we will end up
        // redownloading the whole thing again.
        blockLocator.add(params.genesisBlock.getHash());
        Block topBlock = blockChain.getChainHead().getHeader();
        if (!topBlock.equals(params.genesisBlock))
            blockLocator.add(0, topBlock.getHash());
        GetBlocksMessage message = new GetBlocksMessage(params, blockLocator, toHash);
        conn.writeMessage(NetworkConnection.MSG_GETBLOCKS, message);
    }

    /**
     * Starts an asynchronous download of the block chain. The chain download is deemed to be complete once we've
     * downloaded the same number of blocks that the peer advertised having in its version handshake message.
     *
     * @return a {@link CountDownLatch} that can be used to track progress and wait for completion.
     */
    public CountDownLatch startBlockChainDownload() throws IOException {
        // Chain will overflow signed int blocks in ~41,000 years.
        int chainHeight = (int) conn.getVersionMessage().bestHeight;
        if (chainHeight <= 0) {
            // This should not happen because we shouldn't have given the user a Peer that is to another client-mode
            // node. If that happens it means the user overrode us somewhere.
            throw new  RuntimeException("Peer does not have block chain");
        }
        int blocksToGet = chainHeight - blockChain.getChainHead().getHeight();
        chainCompletionLatch = new CountDownLatch(blocksToGet);
        if (blocksToGet > 0) {
            // When we just want as many blocks as possible, we can set the target hash to zero.
            blockChainDownload(new byte[32]);
        }
        return chainCompletionLatch;
    }

    /**
     * Terminates the network connection and stops the background thread.
     */
    public void disconnect() {
        synchronized (this) {
            running = false;
        }
        try {
            // This will cause the background thread to die, but it's really ugly. We must do a better job of this.
            conn.shutdown();
        } catch (IOException e) {
            // Don't care about this.
        }
    }
}
