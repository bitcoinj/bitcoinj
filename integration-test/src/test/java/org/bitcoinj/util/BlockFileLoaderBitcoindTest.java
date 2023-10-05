/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.util;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PrunedException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.BlockFileLoader;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This is an integration test that REQUIRES a local Bitcoin Core installation
 */
@Ignore("This requires a bitcoind installation AND takes a long time to run.")
public class BlockFileLoaderBitcoindTest {

    @Before
    public void setUp() {
        Context.propagate(new Context());
    }

    @Test
    public void iterateEntireBitcoindBlockchain() {
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, BlockFileLoader.getReferenceClientBlockFileList());

        long blockCount = 0;
        long lastLog = 0;
        for (Block b : loader) {
            if (blockCount >= lastLog + 10_000) {
                lastLog = blockCount;
                System.out.println("At block: " + blockCount);
            }
            blockCount++;
        }
        System.out.println("Final block height: " + (blockCount - 1));
        assertTrue(blockCount > 1);
    }

    @Test
    public void iterateEntireBitcoindBlockchainIntoBlockStore() throws BlockStoreException, PrunedException {
        Network network = BitcoinNetwork.MAINNET;
        NetworkParameters params = NetworkParameters.of(network);
        BlockFileLoader loader = new BlockFileLoader(network, BlockFileLoader.getReferenceClientBlockFileList());
        BlockStore store = new MemoryBlockStore(params.getGenesisBlock());
        AbstractBlockChain chain = new BlockChain(network, store);

        long blockCount = 0;
        long lastLog = 0;
        for (Block b : loader) {
            chain.add(b);
            if (blockCount >= lastLog + 100) {
                lastLog = blockCount;
                System.out.println("At block: " + blockCount);
            }
            blockCount++;
        }
        System.out.println("Final block height: " + (blockCount - 1));
        assertTrue(blockCount > 1);
    }

    @Test
    public void streamEntireBitcoindBlockchainAsBuffers() {
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, BlockFileLoader.getReferenceClientBlockFileList());

        long blockCount = loader.streamBuffers().count();
        System.out.println("Final block height: " + (blockCount - 1));
        assertTrue(blockCount > 1);
    }

    @Test
    public void streamEntireBitcoindBlockchainAsBlocks() {
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, BlockFileLoader.getReferenceClientBlockFileList());

        long blockCount = loader.stream().count();
        System.out.println("Final block height: " + (blockCount - 1));
        assertTrue(blockCount > 1);
    }
}
