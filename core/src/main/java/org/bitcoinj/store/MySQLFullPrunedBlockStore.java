/*
 * Copyright 2014 Kalpesh Parmar
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

import org.bitcoinj.core.NetworkParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <p>A full pruned block store using the MySQL database engine. As an added bonus an address index is calculated,
 * so you can use {@link #calculateBalanceForAddress(org.bitcoinj.core.Address)} to quickly look up
 * the quantity of bitcoins controlled by that address.</p>
 */
public class MySQLFullPrunedBlockStore extends DatabaseFullPrunedBlockStore {
    private static final Logger log = LoggerFactory.getLogger(MySQLFullPrunedBlockStore.class);

    private static final String MYSQL_DUPLICATE_KEY_ERROR_CODE = "23000";
    private static final String DATABASE_DRIVER_CLASS = "com.mysql.jdbc.Driver";
    private static final String DATABASE_CONNECTION_URL_PREFIX = "jdbc:mysql://";

    // create table SQL
    private static final String CREATE_SETTINGS_TABLE = "CREATE TABLE settings (\n" +
            "    name varchar(32) NOT NULL,\n" +
            "    value blob,\n" +
            "    CONSTRAINT `setting_pk` PRIMARY KEY (name)\n" +
            ")\n";

    private static final String CREATE_HEADERS_TABLE = "CREATE TABLE headers (\n" +
            "    hash blob NOT NULL,\n" +
            "    chainwork mediumblob NOT NULL,\n" +
            "    height integer NOT NULL,\n" +
            "    header blob NOT NULL,\n" +
            "    wasundoable tinyint(1) NOT NULL,\n" +
            "    CONSTRAINT `headers_pk` PRIMARY KEY (hash(28)) USING btree\n" +
            ")";

    private static final String CREATE_UNDOABLE_TABLE = "CREATE TABLE undoableblocks (\n" +
            "    hash blob NOT NULL,\n" +
            "    height integer NOT NULL,\n" +
            "    txoutchanges mediumblob,\n" +
            "    transactions mediumblob,\n" +
            "    CONSTRAINT `undoableblocks_pk` PRIMARY KEY (hash(28)) USING btree\n" +
            ")\n";

    private static final String CREATE_OPEN_OUTPUT_TABLE = "CREATE TABLE openoutputs (\n" +
            "    hash blob NOT NULL,\n" +
            "    `index` integer NOT NULL,\n" +
            "    height integer NOT NULL,\n" +
            "    value bigint NOT NULL,\n" +
            "    scriptbytes mediumblob NOT NULL,\n" +
            "    toaddress varchar(35),\n" +
            "    addresstargetable tinyint(1),\n" +
            "    coinbase boolean,\n" +
            "    CONSTRAINT `openoutputs_pk` PRIMARY KEY (hash(32),`index`) USING btree\n" +
            ")\n";

    // Some indexes to speed up inserts
    private static final String CREATE_OUTPUTS_ADDRESS_MULTI_INDEX              = "CREATE INDEX openoutputs_hash_index_height_toaddress_idx ON openoutputs (hash(32), `index`, height, toaddress) USING btree";
    private static final String CREATE_OUTPUTS_TOADDRESS_INDEX                  = "CREATE INDEX openoutputs_toaddress_idx ON openoutputs (toaddress) USING btree";
    private static final String CREATE_OUTPUTS_ADDRESSTARGETABLE_INDEX          = "CREATE INDEX openoutputs_addresstargetable_idx ON openoutputs (addresstargetable) USING btree";
    private static final String CREATE_OUTPUTS_HASH_INDEX                       = "CREATE INDEX openoutputs_hash_idx ON openoutputs (hash(32)) USING btree";
    private static final String CREATE_UNDOABLE_TABLE_INDEX                     = "CREATE INDEX undoableblocks_height_idx ON undoableBlocks (height) USING btree";

    // SQL involving index column (table openOutputs) overridden as it is a reserved word and must be back ticked in MySQL.
    private static final String SELECT_OPENOUTPUTS_SQL                          = "SELECT height, value, scriptBytes, coinbase, toaddress, addresstargetable FROM openOutputs WHERE hash = ? AND `index` = ?";
    private static final String INSERT_OPENOUTPUTS_SQL                          = "INSERT INTO openOutputs (hash, `index`, height, value, scriptBytes, toAddress, addressTargetable, coinbase) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String DELETE_OPENOUTPUTS_SQL                          = "DELETE FROM openOutputs WHERE hash = ? AND `index` = ?";

    private static final String SELECT_TRANSACTION_OUTPUTS_SQL                  = "SELECT hash, value, scriptBytes, height, `index`, coinbase, toaddress, addresstargetable FROM openOutputs where toaddress = ?";

    /**
     * Creates a new MySQLFullPrunedBlockStore.
     *
     * @param params A copy of the NetworkParameters used
     * @param fullStoreDepth The number of blocks of history stored in full (something like 1000 is pretty safe)
     * @param hostname The hostname of the database to connect to
     * @param dbName The database to connect to
     * @param username The database username
     * @param password The password to the database
     * @throws BlockStoreException if the database fails to open for any reason
     */
    public MySQLFullPrunedBlockStore(NetworkParameters params, int fullStoreDepth, String hostname, String dbName,
                                     String username, String password) throws BlockStoreException {
        super(params, DATABASE_CONNECTION_URL_PREFIX + hostname + "/" + dbName, fullStoreDepth, username, password, null);
    }

    @Override
    protected String getDuplicateKeyErrorCode() {
        return MYSQL_DUPLICATE_KEY_ERROR_CODE;
    }

    @Override
    protected String getSelectOpenoutputsSQL() {
        return SELECT_OPENOUTPUTS_SQL;
    }

    @Override
    protected String getInsertOpenoutputsSQL() {
        return INSERT_OPENOUTPUTS_SQL;
    }

    @Override
    protected String getDeleteOpenoutputsSQL() {
        return DELETE_OPENOUTPUTS_SQL;
    }

    @Override
    protected String getTrasactionOutputSelectSQL() {
        return SELECT_TRANSACTION_OUTPUTS_SQL;
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
