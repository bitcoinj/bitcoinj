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
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Context;
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
        for (Block b : loader) {
            blockCount++;
            System.out.println("Block count: " + blockCount);
        }
        assertTrue(blockCount > 1);
    }
}
