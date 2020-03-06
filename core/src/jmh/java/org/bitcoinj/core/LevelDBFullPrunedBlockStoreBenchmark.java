/*
 * Copyright 2019 Tim Strasser
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

import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.FullPrunedBlockStore;
import org.bitcoinj.store.LevelDBFullPrunedBlockStore;
import org.openjdk.jmh.annotations.*;

public class LevelDBFullPrunedBlockStoreBenchmark {

    public static int NUM_BLOCKS = 10;

    @State(Scope.Benchmark)
    public static class BenchmarkParams {
        @Param({"true", "false"})
        boolean instrument;
    }

    @org.openjdk.jmh.annotations.Benchmark
    @BenchmarkMode(Mode.All)
    @Warmup(iterations = 5)
    @Measurement(iterations = 5)
    public void benchmark(BenchmarkParams benchmarkParams) throws PrunedException, BlockStoreException {
        NetworkParameters params = UnitTestParams.get();
        Context context = new Context(params);
        FullPrunedBlockStore store = new LevelDBFullPrunedBlockStore(
                params, "test-leveldb", 10, 100 * 1024 * 1024l,
                10 * 1024 * 1024, 100000, benchmarkParams.instrument, Integer.MAX_VALUE);
        FullPrunedBlockChain fullPrunedBlockChain = new FullPrunedBlockChain(context, store);
        ECKey ecKey = new ECKey();
        int height = 1;
        for (int i = 0; i < NUM_BLOCKS; i++) {
            Block block = params.getGenesisBlock().createNextBlockWithCoinbase(Block.BLOCK_VERSION_GENESIS, ecKey.getPubKey(), height++);
            fullPrunedBlockChain.add(block);
        }

        store.close();
    }
}
