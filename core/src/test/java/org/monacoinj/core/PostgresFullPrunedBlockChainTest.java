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

package org.monacoinj.core;

import org.monacoinj.store.BlockStoreException;
import org.monacoinj.store.FullPrunedBlockStore;
import org.monacoinj.store.PostgresFullPrunedBlockStore;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;

/**
 * A Postgres implementation of the {@link AbstractFullPrunedBlockChainTest}
 */
@Ignore("enable the postgres driver dependency in the maven POM")
public class PostgresFullPrunedBlockChainTest extends AbstractFullPrunedBlockChainTest
{
    // Replace these with your postgres location/credentials and remove @Ignore to test
    // You can set up a fresh postgres with the command: create user monacoinj superuser password 'password';
    private static final String DB_HOSTNAME = "localhost";
    private static final String DB_NAME = "monacoinj_test";
    private static final String DB_USERNAME = "monacoinj";
    private static final String DB_PASSWORD = "password";
    private static final String DB_SCHEMA = "blockstore_schema";

    // whether to run the test with a schema name
    private boolean useSchema = false;

    @After
    public void tearDown() throws Exception {
        ((PostgresFullPrunedBlockStore)store).deleteStore();
    }

    @Override
    public FullPrunedBlockStore createStore(NetworkParameters params, int blockCount)
            throws BlockStoreException {
        if(useSchema) {
            return new PostgresFullPrunedBlockStore(params, blockCount, DB_HOSTNAME, DB_NAME, DB_USERNAME, DB_PASSWORD, DB_SCHEMA);
        }
        else {
            return new PostgresFullPrunedBlockStore(params, blockCount, DB_HOSTNAME, DB_NAME, DB_USERNAME, DB_PASSWORD);
        }
    }

    @Override
    public void resetStore(FullPrunedBlockStore store) throws BlockStoreException {
        ((PostgresFullPrunedBlockStore)store).resetStore();
    }

    @Test
    public void testFirst100kBlocksWithCustomSchema() throws Exception {
        boolean oldSchema = useSchema;
        useSchema = true;
        try {
            super.testFirst100KBlocks();
        } finally {
            useSchema = oldSchema;
        }
    }
}
