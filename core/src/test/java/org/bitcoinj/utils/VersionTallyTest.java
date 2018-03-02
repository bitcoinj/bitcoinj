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

import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.testing.FakeTxBuilder;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class VersionTallyTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();

    public VersionTallyTest() {
    }

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();
        Context context = new Context(UNITTEST);
    }

    /**
     * Verify that the version tally returns null until it collects enough data.
     */
    @Test
    public void testNullWhileEmpty() {
        VersionTally instance = new VersionTally(UNITTEST);
        for (int i = 0; i < UNITTEST.getMajorityWindow(); i++) {
            assertNull(instance.getCountAtOrAbove(1));
            instance.add(1);
        }
        assertEquals(UNITTEST.getMajorityWindow(), instance.getCountAtOrAbove(1).intValue());
    }

    /**
     * Verify that the size of the version tally matches the network parameters.
     */
    @Test
    public void testSize() {
        VersionTally instance = new VersionTally(UNITTEST);
        assertEquals(UNITTEST.getMajorityWindow(), instance.size());
    }

    /**
     * Verify that version count and substitution works correctly.
     */
    @Test
    public void testVersionCounts() {
        VersionTally instance = new VersionTally(UNITTEST);

        // Fill the tally with 1s
        for (int i = 0; i < UNITTEST.getMajorityWindow(); i++) {
            assertNull(instance.getCountAtOrAbove(1));
            instance.add(1);
        }
        assertEquals(UNITTEST.getMajorityWindow(), instance.getCountAtOrAbove(1).intValue());

        // Check the count updates as we replace with 2s
        for (int i = 0; i < UNITTEST.getMajorityWindow(); i++) {
            assertEquals(i, instance.getCountAtOrAbove(2).intValue());
            instance.add(2);
        }
 
        // Inject a rogue 1
        instance.add(1);
        assertEquals(UNITTEST.getMajorityWindow() - 1, instance.getCountAtOrAbove(2).intValue());

        // Check we accept high values as well
        instance.add(10);
        assertEquals(UNITTEST.getMajorityWindow() - 1, instance.getCountAtOrAbove(2).intValue());
    }

    @Test
    public void testInitialize() throws BlockStoreException {
        final BlockStore blockStore = new MemoryBlockStore(UNITTEST);
        final BlockChain chain = new BlockChain(UNITTEST, blockStore);

        // Build a historical chain of version 2 blocks
        long timeSeconds = 1231006505;
        StoredBlock chainHead = null;
        for (int height = 0; height < UNITTEST.getMajorityWindow(); height++) {
            chainHead = FakeTxBuilder.createFakeBlock(blockStore, 2, timeSeconds, height).storedBlock;
            assertEquals(2, chainHead.getHeader().getVersion());
            timeSeconds += 60;
        }

        VersionTally instance = new VersionTally(UNITTEST);
        instance.initialize(blockStore, chainHead);
        assertEquals(UNITTEST.getMajorityWindow(), instance.getCountAtOrAbove(2).intValue());
    }
}
