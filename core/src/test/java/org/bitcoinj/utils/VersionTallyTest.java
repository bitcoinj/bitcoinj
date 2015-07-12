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
    private NetworkParameters unitTestParams;

    public VersionTallyTest() {
    }

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();

        unitTestParams = UnitTestParams.get();
        Context context = new Context(unitTestParams);
    }

    /**
     * Verify that the version tally returns null until it collects enough data.
     */
    @Test
    public void testNullWhileEmpty() {
        VersionTally instance = new VersionTally(unitTestParams);
        for (int i = 0; i < unitTestParams.getMajorityWindow(); i++) {
            assertNull(instance.getCount(1));
            instance.add(1);
        }
        assertEquals(unitTestParams.getMajorityWindow(), instance.getCount(1).intValue());
    }

    /**
     * Verify that the size of the version tally matches the network parameters.
     */
    @Test
    public void testSize() {
        VersionTally instance = new VersionTally(unitTestParams);
        assertEquals(unitTestParams.getMajorityWindow(), instance.size());
    }

    /**
     * Verify that version count and substitution works correctly.
     */
    @Test
    public void testVersionCounts() {
        VersionTally instance = new VersionTally(unitTestParams);

        // Fill the tally with 1s
        for (int i = 0; i < unitTestParams.getMajorityWindow(); i++) {
            assertNull(instance.getCount(1));
            instance.add(1);
        }
        assertEquals(unitTestParams.getMajorityWindow(), instance.getCount(1).intValue());

        for (int i = 0; i < unitTestParams.getMajorityWindow(); i++) {
            assertEquals(unitTestParams.getMajorityWindow() - i, instance.getCount(1).intValue());
            assertEquals(i, instance.getCount(2).intValue());
            instance.add(2);
        }
    }

    @Test
    public void testInitialize() throws BlockStoreException {
        final BlockStore blockStore = new MemoryBlockStore(unitTestParams);
        final BlockChain chain = new BlockChain(unitTestParams, blockStore);

        // Build a historical chain of version 2 blocks
        long timeSeconds = 1231006505;
        StoredBlock chainHead = null;
        for (int blockCount = 0; blockCount < unitTestParams.getMajorityWindow(); blockCount++) {
            chainHead = FakeTxBuilder.createFakeBlock(blockStore, 2, timeSeconds).storedBlock;
            assertEquals(2, chainHead.getHeader().getVersion());
            timeSeconds += 60;
        }

        VersionTally instance = new VersionTally(unitTestParams);
        instance.initialize(blockStore, chainHead);
        assertEquals(unitTestParams.getMajorityWindow(), instance.getCount(2).intValue());
    }
}
