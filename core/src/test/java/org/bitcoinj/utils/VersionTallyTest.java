/*
 * Copyright 2015 Ross Nicoll.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.utils;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.testing.FakeTxBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class VersionTallyTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();

    public VersionTallyTest() {
    }

    @BeforeClass
    public static void setUpClass() {
        TimeUtils.clearMockClock();
    }

    @Before
    public void setUp() {
        BriefLogFormatter.initVerbose();
    }

    /**
     * Verify that the version tally returns null until it collects enough data.
     */
    @Test
    public void testNullWhileEmpty() {
        VersionTally instance = new VersionTally(TESTNET);
        for (int i = 0; i < TESTNET.getMajorityWindow(); i++) {
            assertNull(instance.getCountAtOrAbove(1));
            instance.add(1);
        }
        assertEquals(TESTNET.getMajorityWindow(), instance.getCountAtOrAbove(1).intValue());
    }

    /**
     * Verify that the size of the version tally matches the network parameters.
     */
    @Test
    public void testSize() {
        VersionTally instance = new VersionTally(TESTNET);
        assertEquals(TESTNET.getMajorityWindow(), instance.size());
    }

    /**
     * Verify that version count and substitution works correctly.
     */
    @Test
    public void testVersionCounts() {
        VersionTally instance = new VersionTally(TESTNET);

        // Fill the tally with 1s
        for (int i = 0; i < TESTNET.getMajorityWindow(); i++) {
            assertNull(instance.getCountAtOrAbove(1));
            instance.add(1);
        }
        assertEquals(TESTNET.getMajorityWindow(), instance.getCountAtOrAbove(1).intValue());

        // Check the count updates as we replace with 2s
        for (int i = 0; i < TESTNET.getMajorityWindow(); i++) {
            assertEquals(i, instance.getCountAtOrAbove(2).intValue());
            instance.add(2);
        }
 
        // Inject a rogue 1
        instance.add(1);
        assertEquals(TESTNET.getMajorityWindow() - 1, instance.getCountAtOrAbove(2).intValue());

        // Check we accept high values as well
        instance.add(10);
        assertEquals(TESTNET.getMajorityWindow() - 1, instance.getCountAtOrAbove(2).intValue());
    }

    @Test
    public void testInitialize() throws BlockStoreException {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        final BlockStore blockStore = new MemoryBlockStore(TESTNET.getGenesisBlock());
        final BlockChain chain = new BlockChain(BitcoinNetwork.TESTNET, blockStore);

        // Build a historical chain of version 2 blocks
        Instant time = Instant.ofEpochSecond(1231006505);
        StoredBlock chainHead = null;
        for (int height = 0; height < TESTNET.getMajorityWindow(); height++) {
            chainHead = FakeTxBuilder.createFakeBlock(blockStore, 2, time, height).storedBlock;
            assertEquals(2, chainHead.getHeader().getVersion());
            time = time.plus(1, ChronoUnit.MINUTES);
        }

        VersionTally instance = new VersionTally(TESTNET);
        instance.initialize(blockStore, chainHead);
        assertEquals(TESTNET.getMajorityWindow(), instance.getCountAtOrAbove(2).intValue());
    }
}
