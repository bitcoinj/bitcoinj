/*
 * Copyright 2012 Matt Corallo.
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

package org.bitcoinj.store;

import org.bitcoinj.core.*;

import java.sql.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// Originally written for Apache Derby, but its DELETE (and general) performance was awful
/**
 * A full pruned block store using the H2 pure-java embedded database.
 *
 * Note that because of the heavy delete load on the database, during IBD,
 * you may see the database files grow quite large (around 1.5G).
 * H2 automatically frees some space at shutdown, so close()ing the database
 * decreases the space usage somewhat (to only around 1.3G).
 */
public class H2FullPrunedBlockStore extends DatabaseFullPrunedBlockStore {
    private static final String H2_DUPLICATE_KEY_ERROR_CODE = "23505";
    private static final String DATABASE_DRIVER_CLASS = "org.h2.Driver";
    private static final String DATABASE_CONNECTION_URL_PREFIX = "jdbc:h2:";

    // create table SQL
    private static final String CREATE_SETTINGS_TABLE = "CREATE TABLE settings ( "
            + "name VARCHAR(32) NOT NULL CONSTRAINT settings_pk PRIMARY KEY,"
            + "value BLOB"
            + ")";

    private static final String CREATE_HEADERS_TABLE = "CREATE TABLE headers ( "
            + "hash BINARY(28) NOT NULL CONSTRAINT headers_pk PRIMARY KEY,"
            + "chainwork BLOB NOT NULL,"
            + "height INT NOT NULL,"
            + "header BLOB NOT NULL,"
            + "wasundoable BOOL NOT NULL"
            + ")";

    private static final String CREATE_UNDOABLE_TABLE = "CREATE TABLE undoableblocks ( "
            + "hash BINARY(28) NOT NULL CONSTRAINT undoableblocks_pk PRIMARY KEY,"
            + "height INT NOT NULL,"
            + "txoutchanges BLOB,"
            + "transactions BLOB"
            + ")";

    private static final String CREATE_OPEN_OUTPUT_TABLE = "CREATE TABLE openoutputs ("
            + "hash BINARY(32) NOT NULL,"
            + "index INT NOT NULL,"
            + "height INT NOT NULL,"
            + "value BIGINT NOT NULL,"
            + "scriptbytes BLOB NOT NULL,"
            + "toaddress VARCHAR(35),"
            + "addresstargetable TINYINT,"
            + "coinbase BOOLEAN,"
            + "PRIMARY KEY (hash, index),"
            + ")";

    // Some indexes to speed up inserts
    private static final String CREATE_OUTPUTS_ADDRESS_MULTI_INDEX      = "CREATE INDEX openoutputs_hash_index_height_toaddress_idx ON openoutputs (hash, index, height, toaddress)";
    private static final String CREATE_OUTPUTS_TOADDRESS_INDEX          = "CREATE INDEX openoutputs_toaddress_idx ON openoutputs (toaddress)";
    private static final String CREATE_OUTPUTS_ADDRESSTARGETABLE_INDEX  = "CREATE INDEX openoutputs_addresstargetable_idx ON openoutputs (addresstargetable)";
    private static final String CREATE_OUTPUTS_HASH_INDEX               = "CREATE INDEX openoutputs_hash_idx ON openoutputs (hash)";
    private static final String CREATE_UNDOABLE_TABLE_INDEX             = "CREATE INDEX undoableblocks_height_idx ON undoableblocks (height)";

    /**
     * Creates a new H2FullPrunedBlockStore
     * @param params A copy of the NetworkParameters used
     * @param dbName The path to the database on disk
     * @param fullStoreDepth The number of blocks of history stored in full (something like 1000 is pretty safe)
     * @throws BlockStoreException if the database fails to open for any reason
     */
    public H2FullPrunedBlockStore(NetworkParameters params, String dbName, int fullStoreDepth) throws BlockStoreException {
        super(params, DATABASE_CONNECTION_URL_PREFIX + dbName + ";create=true;LOCK_TIMEOUT=60000;DB_CLOSE_ON_EXIT=FALSE", fullStoreDepth, null, null, null);
    }

    /**
     * Creates a new H2FullPrunedBlockStore with the given cache size
     * @param params A copy of the NetworkParameters used
     * @param dbName The path to the database on disk
     * @param fullStoreDepth The number of blocks of history stored in full (something like 1000 is pretty safe)
     * @param cacheSize The number of kilobytes to dedicate to H2 Cache (the default value of 16MB (16384) is a safe bet
     *                  to achieve good performance/cost when importing blocks from disk, past 32MB makes little sense,
     *                  and below 4MB sees a sharp drop in performance)
     * @throws BlockStoreException if the database fails to open for any reason
     */
    public H2FullPrunedBlockStore(NetworkParameters params, String dbName, int fullStoreDepth, int cacheSize) throws BlockStoreException {
        this(params, dbName, fullStoreDepth);
        try {
            Statement s = conn.get().createStatement();
            s.executeUpdate("SET CACHE_SIZE " + cacheSize);
            s.close();
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    @Override
    protected String getDuplicateKeyErrorCode() {
        return H2_DUPLICATE_KEY_ERROR_CODE;
    }

    @Override
    protected List<String> getCreateTablesSQL() {
        List<String> sqlStatements = new ArrayList<String>();
        sqlStatements.add(CREATE_SETTINGS_TABLE);
        sqlStatements.add(CREATE_HEADERS_TABLE);
        sqlStatements.add(CREATE_UNDOABLE_TABLE);
        sqlStatements.add(CREATE_OPEN_OUTPUT_TABLE);
        return sqlStatements;
    }

    @Override
    protected List<String> getCreateIndexesSQL() {
        List<String> sqlStatements = new ArrayList<String>();
        sqlStatements.add(CREATE_UNDOABLE_TABLE_INDEX);
        sqlStatements.add(CREATE_OUTPUTS_ADDRESS_MULTI_INDEX);
        sqlStatements.add(CREATE_OUTPUTS_ADDRESSTARGETABLE_INDEX);
        sqlStatements.add(CREATE_OUTPUTS_HASH_INDEX);
        sqlStatements.add(CREATE_OUTPUTS_TOADDRESS_INDEX);
        return sqlStatements;
    }

    @Override
    protected List<String> getCreateSchemeSQL() {
        // do nothing
        return Collections.emptyList();
    }

    @Override
    protected String getDatabaseDriverClass() {
        return DATABASE_DRIVER_CLASS;
    }
}