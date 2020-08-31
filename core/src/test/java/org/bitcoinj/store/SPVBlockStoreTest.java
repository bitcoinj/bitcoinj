/*
 * Copyright 2013 Google Inc.
 * Copyright 2018 Andreas Schildbach
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

package org.bitcoinj.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.math.BigInteger;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.params.UnitTestParams;
import org.junit.Before;
import org.junit.Test;

import com.google.common.base.Stopwatch;

public class SPVBlockStoreTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private File blockStoreFile;

    @Before
    public void setup() throws Exception {
        blockStoreFile = File.createTempFile("spvblockstore", null);
        blockStoreFile.delete();
        blockStoreFile.deleteOnExit();
    }

    @Test
    public void basics() throws Exception {
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile);

        Address to = LegacyAddress.fromKey(UNITTEST, new ECKey());
        // Check the first block in a new store is the genesis block.
        StoredBlock genesis = store.getChainHead();
        assertEquals(UNITTEST.getGenesisBlock(), genesis.getHeader());
        assertEquals(0, genesis.getHeight());

        // Build a new block.
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        store.close();

        // Check we can get it back out again if we rebuild the store object.
        store = new SPVBlockStore(UNITTEST, blockStoreFile);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        StoredBlock chainHead = store.getChainHead();
        assertEquals(b1, chainHead);
        store.close();
    }

    @Test(expected = BlockStoreException.class)
    public void twoStores_onSameFile() throws Exception {
        new SPVBlockStore(UNITTEST, blockStoreFile);
        new SPVBlockStore(UNITTEST, blockStoreFile);
    }

    @Test
    public void twoStores_butSequentially() throws Exception {
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile);
        store.close();
        store = new SPVBlockStore(UNITTEST, blockStoreFile);
    }

    @Test(expected = BlockStoreException.class)
    public void twoStores_sequentially_butMismatchingCapacity() throws Exception {
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile, 10, false);
        store.close();
        store = new SPVBlockStore(UNITTEST, blockStoreFile, 20, false);
    }

    @Test
    public void twoStores_sequentially_grow() throws Exception {
        Address to = LegacyAddress.fromKey(UNITTEST, new ECKey());
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile, 10, true);
        final StoredBlock block0 = store.getChainHead();
        final StoredBlock block1 = block0.build(block0.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(block1);
        final StoredBlock block2 = block1.build(block1.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(block2);
        store.setChainHead(block2);
        store.close();

        store = new SPVBlockStore(UNITTEST, blockStoreFile, 20, true);
        final StoredBlock read2 = store.getChainHead();
        assertEquals(block2, read2);
        final StoredBlock read1 = read2.getPrev(store);
        assertEquals(block1, read1);
        final StoredBlock read0 = read1.getPrev(store);
        assertEquals(block0, read0);
        store.close();
        assertEquals(SPVBlockStore.getFileSize(20), blockStoreFile.length());
    }

    @Test(expected = BlockStoreException.class)
    public void twoStores_sequentially_shrink() throws Exception {
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile, 20, true);
        store.close();
        store = new SPVBlockStore(UNITTEST, blockStoreFile, 10, true);
    }

    @Test
    public void performanceTest() throws BlockStoreException {
        // On slow machines, this test could fail. Then either add @Ignore or adapt the threshold and please report to
        // us.
        final int ITERATIONS = 100000;
        final long THRESHOLD_MS = 2000;
        SPVBlockStore store = new SPVBlockStore(UNITTEST, blockStoreFile);
        Stopwatch watch = Stopwatch.createStarted();
        for (int i = 0; i < ITERATIONS; i++) {
            // Using i as the nonce so that the block hashes are different.
            Block block = new Block(UNITTEST, 0, Sha256Hash.ZERO_HASH, Sha256Hash.ZERO_HASH, 0, 0, i,
                    Collections.<Transaction> emptyList());
            StoredBlock b = new StoredBlock(block, BigInteger.ZERO, i);
            store.put(b);
            store.setChainHead(b);
        }
        assertTrue("took " + watch + " for " + ITERATIONS + " iterations",
                watch.elapsed(TimeUnit.MILLISECONDS) < THRESHOLD_MS);
        store.close();
    }
}
