/*
 * Copyright 2012 Matt Corallo.
 * Copyright 2014 Andreas Schildbach
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

import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.FullPrunedBlockStore;
import org.bitcoinj.store.H2FullPrunedBlockStore;
import org.bitcoinj.utils.BlockFileLoader;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A tool for comparing the blocks which are accepted/rejected by bitcoind/bitcoinj
 * It is designed to run as a testnet-in-a-box network between a single bitcoind node and bitcoinj
 * It is not an automated unit-test because it requires a bit more set-up...read comments below
 */
public class BitcoindComparisonTool {
    private static final Logger log = LoggerFactory.getLogger(BitcoindComparisonTool.class);

    private static NetworkParameters params;
    private static FullPrunedBlockStore store;
    private static FullPrunedBlockChain chain;
    private static PeerGroup peers;
    private static Sha256Hash bitcoindChainHead;
    private static volatile Peer bitcoind;
    private static volatile InventoryMessage mostRecentInv = null;

    static class BlockWrapper {
        public Block block;
    }

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        System.out.println("USAGE: bitcoinjBlockStoreLocation runLargeReorgs(1/0) [port=18444]");
        boolean runLargeReorgs = args.length > 1 && Integer.parseInt(args[1]) == 1;

        params = RegTestParams.get();

        File blockFile = File.createTempFile("testBlocks", ".dat");
        blockFile.deleteOnExit();

        FullBlockTestGenerator generator = new FullBlockTestGenerator(params);
        final RuleList blockList = generator.getBlocksToTest(false, runLargeReorgs, blockFile);
        final Map<Sha256Hash, Block> preloadedBlocks = new HashMap<Sha256Hash, Block>();
        final Iterator<Block> blocks = new BlockFileLoader(params, Arrays.asList(blockFile));

        try {
            store = new H2FullPrunedBlockStore(params, args.length > 0 ? args[0] : "BitcoindComparisonTool", blockList.maximumReorgBlockCount);
            ((H2FullPrunedBlockStore)store).resetStore();
            //store = new MemoryFullPrunedBlockStore(params, blockList.maximumReorgBlockCount);
            chain = new FullPrunedBlockChain(params, store);
        } catch (BlockStoreException e) {
            e.printStackTrace();
            System.exit(1);
        }

        peers = new PeerGroup(params, chain);
        peers.setUserAgent("BlockAcceptanceComparisonTool", "1.0");
        peers.getVersionMessage().localServices = VersionMessage.NODE_NETWORK;
        Preconditions.checkState(peers.getVersionMessage().hasBlockChain());
        
        // bitcoind MUST be on localhost or we will get banned as a DoSer
        peers.addAddress(new PeerAddress(InetAddress.getByName("localhost"), args.length > 2 ? Integer.parseInt(args[2]) : params.getPort()));

        final BlockWrapper currentBlock = new BlockWrapper();

        final Set<Sha256Hash> blocksRequested = Collections.synchronizedSet(new HashSet<Sha256Hash>());
        final AtomicInteger unexpectedInvs = new AtomicInteger(0);
        peers.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                super.onPeerConnected(peer, peerCount);
                log.info("bitcoind connected");
                bitcoind = peer;
            }

            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                super.onPeerDisconnected(peer, peerCount);
                log.error("bitcoind node disconnected!");
                System.exit(1);
            }
            
            @Override
            public Message onPreMessageReceived(Peer peer, Message m) {
                if (m instanceof HeadersMessage) {
                    for (Block block : ((HeadersMessage) m).getBlockHeaders())
                        bitcoindChainHead = block.getHash();
                    return null;
                } else if (m instanceof Block) {
                    log.error("bitcoind sent us a block it already had, make sure bitcoind has no blocks!");
                    System.exit(1);
                } else if (m instanceof GetDataMessage) {
                    for (InventoryItem item : ((GetDataMessage)m).items)
                        if (item.type == InventoryItem.Type.Block) {
                            try {
                                if (currentBlock.block.getHash().equals(item.hash))
                                    bitcoind.sendMessage(currentBlock.block);
                                else {
                                    Block nextBlock = preloadedBlocks.get(item.hash);
                                    while (nextBlock == null || !nextBlock.getHash().equals(item.hash)) {
                                        nextBlock = blocks.next();
                                        preloadedBlocks.put(nextBlock.getHash(), nextBlock);
                                    }
                                }
                            }catch (IOException e) { throw new RuntimeException(e); }
                            blocksRequested.add(item.hash);
                        }
                    return null;
                } else if (m instanceof GetHeadersMessage) {
                    try {
                        LinkedList<Block> headers = new LinkedList<Block>();
                        Block it = blockList.hashHeaderMap.get(currentBlock.block.getHash());
                        while (it != null) {
                            headers.addFirst(it);
                            it = blockList.hashHeaderMap.get(it.getPrevBlockHash());
                        }
                        LinkedList<Block> sendHeaders = new LinkedList<Block>();
                        for (Sha256Hash hash : ((GetHeadersMessage)m).getLocator()) {
                            boolean found = false;
                            for (Block b : headers) {
                                if (found) {
                                    sendHeaders.addLast(b);
                                    if (b.getHash().equals(((GetHeadersMessage)m).getStopHash()))
                                        break;
                                } else if (b.getHash().equals(hash))
                                    found = true;
                            }
                            if (found)
                                break;
                        }
                        bitcoind.sendMessage(new HeadersMessage(params, sendHeaders));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    return null;
                } else if (m instanceof InventoryMessage) {
                    if (mostRecentInv != null) {
                        log.error("Got an inv when we weren't expecting one");
                        unexpectedInvs.incrementAndGet();
                    }
                    mostRecentInv = (InventoryMessage) m;
                }
                return m;
            }
        }, Threading.SAME_THREAD);
        peers.addPeerFilterProvider(new PeerFilterProvider() {
            @Override public long getEarliestKeyCreationTime() {
                return Long.MAX_VALUE;
            }

            @Override public int getBloomFilterElementCount() {
                return 1;
            }

            @Override
            public boolean isRequiringUpdateAllBloomFilter() {
                return false;
            }

            @Override
            public void beginBloomFilterCalculation() {
            }

            @Override
            public void endBloomFilterCalculation() {
            }

            @Override public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
                BloomFilter filter = new BloomFilter(1, 0.99, 0);
                filter.setMatchAll();
                return filter;
            }
        });
        
        bitcoindChainHead = params.getGenesisBlock().getHash();
        
        // Connect to bitcoind and make sure it has no blocks
        peers.startAsync();
        peers.setMaxConnections(1);
        peers.downloadBlockChain();
        
        while (bitcoind == null)
            Thread.sleep(50);
        
        ArrayList<Sha256Hash> locator = new ArrayList<Sha256Hash>(1);
        locator.add(params.getGenesisBlock().getHash());
        Sha256Hash hashTo = new Sha256Hash("0000000000000000000000000000000000000000000000000000000000000000");
                
        int differingBlocks = 0;
        int invalidBlocks = 0;
        int mempoolRulesFailed = 0;
        for (Rule rule : blockList.list) {
            if (rule instanceof BlockAndValidity) {
                BlockAndValidity block = (BlockAndValidity) rule;
                boolean threw = false;
                Block nextBlock = preloadedBlocks.get(((BlockAndValidity) rule).blockHash);
                // Always load at least one block because sometimes we have duplicates with the same hash (b56/57)
                for (int i = 0; i < 1 || nextBlock == null || !nextBlock.getHash().equals(((BlockAndValidity)rule).blockHash); i++) {
                    Block b = blocks.next();
                    preloadedBlocks.put(b.getHash(), b);
                    nextBlock = preloadedBlocks.get(((BlockAndValidity) rule).blockHash);
                }
                currentBlock.block = nextBlock;
                log.info("Testing block {}", currentBlock.block.getHash());
                try {
                    if (chain.add(nextBlock) != block.connects) {
                        log.error("Block didn't match connects flag on block \"" + block.ruleName + "\"");
                        invalidBlocks++;
                    }
                } catch (VerificationException e) {
                    threw = true;
                    if (!block.throwsException) {
                        log.error("Block didn't match throws flag on block \"" + block.ruleName + "\"");
                        e.printStackTrace();
                        invalidBlocks++;
                    } else if (block.connects) {
                        log.error("Block didn't match connects flag on block \"" + block.ruleName + "\"");
                        e.printStackTrace();
                        invalidBlocks++;
                    }
                }
                if (!threw && block.throwsException) {
                    log.error("Block didn't match throws flag on block \"" + block.ruleName + "\"");
                    invalidBlocks++;
                } else if (!chain.getChainHead().getHeader().getHash().equals(block.hashChainTipAfterBlock)) {
                    log.error("New block head didn't match the correct value after block \"" + block.ruleName + "\"");
                    invalidBlocks++;
                } else if (chain.getChainHead().getHeight() != block.heightAfterBlock) {
                    log.error("New block head didn't match the correct height after block " + block.ruleName);
                    invalidBlocks++;
                }

                // Shouldnt double-request
                boolean shouldntRequest = blocksRequested.contains(nextBlock.getHash());
                if (shouldntRequest)
                    blocksRequested.remove(nextBlock.getHash());
                InventoryMessage message = new InventoryMessage(params);
                message.addBlock(nextBlock);
                bitcoind.sendMessage(message);
                // bitcoind doesn't request blocks inline so we can't rely on a ping for synchronization
                for (int i = 0; !shouldntRequest && !blocksRequested.contains(nextBlock.getHash()); i++) {
                    if (i % 20 == 19)
                        log.error("bitcoind still hasn't requested block " + block.ruleName + " with hash " + nextBlock.getHash());
                    Thread.sleep(50);
                }
                if (shouldntRequest) {
                    Thread.sleep(100);
                    if (blocksRequested.contains(nextBlock.getHash())) {
                        log.error("bitcoind re-requested block " + block.ruleName + " with hash " + nextBlock.getHash());
                        invalidBlocks++;
                    }
                }
                // If the block throws, we may want to get bitcoind to request the same block again
                if (block.throwsException)
                    blocksRequested.remove(nextBlock.getHash());
                //bitcoind.sendMessage(nextBlock);
                locator.clear();
                locator.add(bitcoindChainHead);
                bitcoind.sendMessage(new GetHeadersMessage(params, locator, hashTo));
                bitcoind.ping().get();
                if (!chain.getChainHead().getHeader().getHash().equals(bitcoindChainHead)) {
                    differingBlocks++;
                    log.error("bitcoind and bitcoinj acceptance differs on block \"" + block.ruleName + "\"");
                }
                if (block.sendOnce)
                    preloadedBlocks.remove(nextBlock.getHash());
                log.info("Block \"" + block.ruleName + "\" completed processing");
            } else if (rule instanceof MemoryPoolState) {
                MemoryPoolMessage message = new MemoryPoolMessage();
                bitcoind.sendMessage(message);
                bitcoind.ping().get();
                if (mostRecentInv == null && !((MemoryPoolState) rule).mempool.isEmpty()) {
                    log.error("bitcoind had an empty mempool, but we expected some transactions on rule " + rule.ruleName);
                    mempoolRulesFailed++;
                } else if (mostRecentInv != null && ((MemoryPoolState) rule).mempool.isEmpty()) {
                    log.error("bitcoind had a non-empty mempool, but we expected an empty one on rule " + rule.ruleName);
                    mempoolRulesFailed++;
                } else if (mostRecentInv != null) {
                    Set<InventoryItem> originalRuleSet = new HashSet<InventoryItem>(((MemoryPoolState)rule).mempool);
                    boolean matches = mostRecentInv.items.size() == ((MemoryPoolState)rule).mempool.size();
                    for (InventoryItem item : mostRecentInv.items)
                        if (!((MemoryPoolState) rule).mempool.remove(item))
                            matches = false;
                    if (matches)
                        continue;
                    log.error("bitcoind's mempool didn't match what we were expecting on rule " + rule.ruleName);
                    log.info("  bitcoind's mempool was: ");
                    for (InventoryItem item : mostRecentInv.items)
                        log.info("    " + item.hash);
                    log.info("  The expected mempool was: ");
                    for (InventoryItem item : originalRuleSet)
                        log.info("    " + item.hash);
                    mempoolRulesFailed++;
                }
                mostRecentInv = null;
            } else {
                throw new RuntimeException("Unknown rule");
            }
        }

        log.info("Done testing.\n" +
                "Blocks which were not handled the same between bitcoind/bitcoinj: " + differingBlocks + "\n" +
                "Blocks which should/should not have been accepted but weren't/were: " + invalidBlocks + "\n" +
                "Transactions which were/weren't in memory pool but shouldn't/should have been: " + mempoolRulesFailed + "\n" +
                "Unexpected inv messages: " + unexpectedInvs.get());
        System.exit(differingBlocks > 0 || invalidBlocks > 0 || mempoolRulesFailed > 0 || unexpectedInvs.get() > 0 ? 1 : 0);
    }
}
