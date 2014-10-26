/*
 * Copyright 2014 Kalpesh Parmar.
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

import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.FullPrunedBlockStore;
import org.bitcoinj.store.MySQLFullPrunedBlockStore;
import org.junit.After;
import org.junit.Ignore;

/**
 * A MySQL implementation of the {@link AbstractFullPrunedBlockChainTest}
 */
@Ignore("enable the mysql driver dependency in the maven POM")
public class MySQLFullPrunedBlockChainTest extends AbstractFullPrunedBlockChainTest {

    @After
    public void tearDown() throws Exception {
        ((MySQLFullPrunedBlockStore)store).deleteStore();
    }

    // Replace these with your mysql location/credentials and remove @Ignore to test
    private static final String DB_HOSTNAME = "localhost";
    private static final String DB_NAME = "bitcoinj_test";
    private static final String DB_USERNAME = "bitcoinj";
    private static final String DB_PASSWORD = "password";

    @Override
    public FullPrunedBlockStore createStore(NetworkParameters params, int blockCount)
            throws BlockStoreException {
        return new MySQLFullPrunedBlockStore(params, blockCount, DB_HOSTNAME, DB_NAME, DB_USERNAME, DB_PASSWORD);
    }

    @Override
    public void resetStore(FullPrunedBlockStore store) throws BlockStoreException {
        ((MySQLFullPrunedBlockStore)store).resetStore();
    }
}