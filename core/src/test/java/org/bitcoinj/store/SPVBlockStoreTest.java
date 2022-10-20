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

import com.google.common.base.Stopwatch;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.params.TestNet3Params;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.math.BigInteger;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SPVBlockStoreTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private File blockStoreFile;

    @BeforeClass
    public static void setUpClass() {
        Utils.resetMocking();
    }

    @Before
    public void setup() throws Exception {
        Context.propagate(new Context());
        blockStoreFile = File.createTempFile("spvblockstore", null);
        blockStoreFile.delete();
        blockStoreFile.deleteOnExit();
    }

    @Test
    public void basics() throws Exception {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile);

        Address to = new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        // Check the first block in a new store is the genesis block.
        StoredBlock genesis = store.getChainHead();
        assertEquals(TESTNET.getGenesisBlock(), genesis.getHeader());
        assertEquals(0, genesis.getHeight());

        // Build a new block.
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        store.close();

        // Check we can get it back out again if we rebuild the store object.
        store = new SPVBlockStore(TESTNET, blockStoreFile);
        StoredBlock b2 = store.get(b1.getHeader().getHash());
        assertEquals(b1, b2);
        // Check the chain head was stored correctly also.
        StoredBlock chainHead = store.getChainHead();
        assertEquals(b1, chainHead);
        store.close();
    }

    @Test(expected = BlockStoreException.class)
    public void twoStores_onSameFile() throws Exception {
        new SPVBlockStore(TESTNET, blockStoreFile);
        new SPVBlockStore(TESTNET, blockStoreFile);
    }

    @Test
    public void twoStores_butSequentially() throws Exception {
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile);
        store.close();
        store = new SPVBlockStore(TESTNET, blockStoreFile);
    }

    @Test(expected = BlockStoreException.class)
    public void twoStores_sequentially_butMismatchingCapacity() throws Exception {
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile, 10, false);
        store.close();
        store = new SPVBlockStore(TESTNET, blockStoreFile, 20, false);
    }

    @Test
    public void twoStores_sequentially_grow() throws Exception {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        Address to = new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile, 10, true);
        final StoredBlock block0 = store.getChainHead();
        final StoredBlock block1 = block0.build(block0.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(block1);
        final StoredBlock block2 = block1.build(block1.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(block2);
        store.setChainHead(block2);
        store.close();

        store = new SPVBlockStore(TESTNET, blockStoreFile, 20, true);
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
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile, 20, true);
        store.close();
        store = new SPVBlockStore(TESTNET, blockStoreFile, 10, true);
    }

    @Test
    public void performanceTest() throws BlockStoreException {
        // On slow machines, this test could fail. Then either add @Ignore or adapt the threshold and please report to
        // us.
        final int ITERATIONS = 100000;
        final long THRESHOLD_MS = 2000;
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile);
        Stopwatch watch = Stopwatch.createStarted();
        for (int i = 0; i < ITERATIONS; i++) {
            // Using i as the nonce so that the block hashes are different.
            Block block = new Block(TESTNET, 0, Sha256Hash.ZERO_HASH, Sha256Hash.ZERO_HASH, 0, 0, i,
                    Collections.emptyList());
            StoredBlock b = new StoredBlock(block, BigInteger.ZERO, i);
            store.put(b);
            store.setChainHead(b);
        }
        assertTrue("took " + watch + " for " + ITERATIONS + " iterations",
                watch.elapsed(TimeUnit.MILLISECONDS) < THRESHOLD_MS);
        store.close();
    }

    @Test
    public void clear() throws Exception {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile);

        // Build a new block.
        Address to = new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        StoredBlock genesis = store.getChainHead();
        StoredBlock b1 = genesis.build(genesis.getHeader().createNextBlock(to).cloneAsHeader());
        store.put(b1);
        store.setChainHead(b1);
        assertEquals(b1.getHeader().getHash(), store.getChainHead().getHeader().getHash());
        store.clear();
        assertNull(store.get(b1.getHeader().getHash()));
        assertEquals(TESTNET.getGenesisBlock().getHash(), store.getChainHead().getHeader().getHash());
        store.close();
    }

    @Test
    public void oneStoreDelete() throws Exception {
        SPVBlockStore store = new SPVBlockStore(TESTNET, blockStoreFile);
        store.close();
        boolean deleted = blockStoreFile.delete();
        if (!Utils.isWindows()) {
            // TODO: Deletion is failing on Windows
            assertTrue(deleted);
        }
    }
}
