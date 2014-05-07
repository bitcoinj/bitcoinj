/*
 * Copyright 2012 Matt Corallo.
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

import com.google.bitcoin.params.RegTestParams;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.FullPrunedBlockStore;
import com.google.bitcoin.store.H2FullPrunedBlockStore;
import com.google.bitcoin.utils.BlockFileLoader;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.bitcoin.utils.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;

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

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        System.out.println("USAGE: bitcoinjBlockStoreLocation runLargeReorgs(1/0) [port=18444]");
        boolean runLargeReorgs = args.length > 1 && Integer.parseInt(args[1]) == 1;

        params = RegTestParams.get();

        File blockFile = File.createTempFile("testBlocks", ".dat");
        blockFile.deleteOnExit();

        FullBlockTestGenerator generator = new FullBlockTestGenerator(params);
        RuleList blockList = generator.getBlocksToTest(false, runLargeReorgs, blockFile);
        Iterator<Block> blocks = new BlockFileLoader(params, Arrays.asList(blockFile));

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
        
        // bitcoind MUST be on localhost or we will get banned as a DoSer
        peers.addAddress(new PeerAddress(InetAddress.getByName("localhost"), args.length > 2 ? Integer.parseInt(args[2]) : params.getPort()));

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
                        if (item.type == InventoryItem.Type.Block)
                            blocksRequested.add(item.hash);
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
            private final Lock lock = Threading.lock("pfp");

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
            public Lock getLock() {
                return lock;
            }

            @Override public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
                BloomFilter filter = new BloomFilter(1, 0.99, 0);
                filter.setMatchAll();
                return filter;
            }
        });
        
        bitcoindChainHead = params.getGenesisBlock().getHash();
        
        // Connect to bitcoind and make sure it has no blocks
        peers.start();
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
                Block nextBlock = blocks.next();
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

                InventoryMessage message = new InventoryMessage(params);
                message.addBlock(nextBlock);
                bitcoind.sendMessage(message);
                // bitcoind doesn't request blocks inline so we can't rely on a ping for synchronization
                for (int i = 0; !blocksRequested.contains(nextBlock.getHash()); i++) {
                    if (i % 20 == 19)
                        log.error("bitcoind still hasn't requested block " + block.ruleName + " with hash " + nextBlock.getHash());
                    Thread.sleep(50);
                }
                bitcoind.sendMessage(nextBlock);
                locator.clear();
                locator.add(bitcoindChainHead);
                bitcoind.sendMessage(new GetHeadersMessage(params, locator, hashTo));
                bitcoind.ping().get();
                if (!chain.getChainHead().getHeader().getHash().equals(bitcoindChainHead)) {
                    differingBlocks++;
                    log.error("bitcoind and bitcoinj acceptance differs on block \"" + block.ruleName + "\"");
                }
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
                log.error("Unknown rule");
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
