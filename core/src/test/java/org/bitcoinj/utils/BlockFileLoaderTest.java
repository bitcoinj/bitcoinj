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

package org.bitcoinj.utils;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Context;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import static org.junit.Assert.assertEquals;

public class BlockFileLoaderTest {
    @Before
    public void setUp() throws Exception {
        Context.propagate(new Context());
    }

    @Test
    public void iterateFirst100kCount() {
        File blockFile = new File(getClass().getResource("../core/first-100k-blocks.dat").getFile());
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, Collections.singletonList(blockFile));

        long blockCount = 0;
        for (Block b : loader) {
            blockCount++;
        }

        assertEquals(439, blockCount);
    }

    @Test
    public void iterateFirst100kTwice() {
        File blockFile = new File(getClass().getResource("../core/first-100k-blocks.dat").getFile());
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, Collections.singletonList(blockFile));

        long blockCount = 0;
        for (Block b : loader) {
            blockCount++;
        }

        assertEquals(439, blockCount);

        long blockCount2 = 0;
        for (Block b : loader) {
            blockCount2++;
        }

        assertEquals(439, blockCount2);
    }

    @Test
    public void streamFirst100kCount() {
        File blockFile = new File(getClass().getResource("../core/first-100k-blocks.dat").getFile());
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, Collections.singletonList(blockFile));

        long blockCount = loader.stream().count();

        assertEquals(439, blockCount);
    }

    @Test
    public void streamFirst100kTwice() {
        File blockFile = new File(getClass().getResource("../core/first-100k-blocks.dat").getFile());
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, Collections.singletonList(blockFile));

        long blockCount = loader.stream().count();

        assertEquals(439, blockCount);

        long blockCount2 = loader.stream().count();

        assertEquals(439, blockCount2);
    }

    @Test
    public void streamFirst100kCountTransactions() {
        File blockFile = new File(getClass().getResource("../core/first-100k-blocks.dat").getFile());
        BlockFileLoader loader = new BlockFileLoader(BitcoinNetwork.MAINNET, Collections.singletonList(blockFile));

        long transactionCount = loader.stream()
                .map(Block::getTransactions)
                .filter(Objects::nonNull)
                .mapToLong(Collection::size)
                .sum();

        assertEquals(446, transactionCount);
    }
}
