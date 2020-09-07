/*
 * Copyright 2014 BitPOS Pty Ltd.
 * Copyright 2014 Andreas Schildbach.
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
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.sql.*;
import java.util.*;

/**
 * <p>A generic full pruned block store for a relational database.  This generic class requires
 * certain table structures for the block store.</p>
 *
 * <p>The following are the tables and field names/types that are assumed:</p>
 *
 * <table>
 *     <caption><b>setting</b> table</caption>
 *     <tr><th>Field Name</th><th>Type (generic)</th></tr>
 *     <tr><td>name</td><td>string</td></tr>
 *     <tr><td>value</td><td>binary</td></tr>
 * </table>
 *
 * <table>
 *     <caption><b>headers</b> table</caption>
 *     <tr><th>Field Name</th><th>Type (generic)</th></tr>
 *     <tr><td>hash</td><td>binary</td></tr>
 *     <tr><td>chainwork</td><td>binary</td></tr>
 *     <tr><td>height</td><td>integer</td></tr>
 *     <tr><td>header</td><td>binary</td></tr>
 *     <tr><td>wasundoable</td><td>boolean</td></tr>
 * </table>
 *
 * <table>
 *     <caption><b>undoableblocks</b> table</caption>
 *     <tr><th>Field Name</th><th>Type (generic)</th></tr>
 *     <tr><td>hash</td><td>binary</td></tr>
 *     <tr><td>height</td><td>integer</td></tr>
 *     <tr><td>txoutchanges</td><td>binary</td></tr>
 *     <tr><td>transactions</td><td>binary</td></tr>
 * </table>
 *
 * <table>
 *     <caption><b>openoutputs</b> table</caption>
 *     <tr><th>Field Name</th><th>Type (generic)</th></tr>
 *     <tr><td>hash</td><td>binary</td></tr>
 *     <tr><td>index</td><td>integer</td></tr>
 *     <tr><td>height</td><td>integer</td></tr>
 *     <tr><td>value</td><td>integer</td></tr>
 *     <tr><td>scriptbytes</td><td>binary</td></tr>
 *     <tr><td>toaddress</td><td>string</td></tr>
 *     <tr><td>addresstargetable</td><td>integer</td></tr>
 *     <tr><td>coinbase</td><td>boolean</td></tr>
 * </table>
 */
public abstract class DatabaseFullPrunedBlockStore implements FullPrunedBlockStore {
    private static final Logger log = LoggerFactory.getLogger(DatabaseFullPrunedBlockStore.class);

    private static final String CHAIN_HEAD_SETTING                              = "chainhead";
    private static final String VERIFIED_CHAIN_HEAD_SETTING                     = "verifiedchainhead";
    private static final String VERSION_SETTING                                 = "version";

    // Drop table SQL.
    private static final String DROP_SETTINGS_TABLE                             = "DROP TABLE settings";
    private static final String DROP_HEADERS_TABLE                              = "DROP TABLE headers";
    private static final String DROP_UNDOABLE_TABLE                             = "DROP TABLE undoableblocks";
    private static final String DROP_OPEN_OUTPUT_TABLE                          = "DROP TABLE openoutputs";

    // Queries SQL.
    private static final String SELECT_SETTINGS_SQL                             = "SELECT value FROM settings WHERE name = ?";
    private static final String INSERT_SETTINGS_SQL                             = "INSERT INTO settings(name, value) VALUES(?, ?)";
    private static final String UPDATE_SETTINGS_SQL                             = "UPDATE settings SET value = ? WHERE name = ?";

    private static final String SELECT_HEADERS_SQL                              = "SELECT chainwork, height, header, wasundoable FROM headers WHERE hash = ?";
    private static final String INSERT_HEADERS_SQL                              = "INSERT INTO headers(hash, chainwork, height, header, wasundoable) VALUES(?, ?, ?, ?, ?)";
    private static final String UPDATE_HEADERS_SQL                              = "UPDATE headers SET wasundoable=? WHERE hash=?";

    private static final String SELECT_UNDOABLEBLOCKS_SQL                       = "SELECT txoutchanges, transactions FROM undoableblocks WHERE hash = ?";
    private static final String INSERT_UNDOABLEBLOCKS_SQL                       = "INSERT INTO undoableblocks(hash, height, txoutchanges, transactions) VALUES(?, ?, ?, ?)";
    private static final String UPDATE_UNDOABLEBLOCKS_SQL                       = "UPDATE undoableblocks SET txoutchanges=?, transactions=? WHERE hash = ?";
    private static final String DELETE_UNDOABLEBLOCKS_SQL                       = "DELETE FROM undoableblocks WHERE height <= ?";

    private static final String SELECT_OPENOUTPUTS_SQL                          = "SELECT height, value, scriptbytes, coinbase, toaddress, addresstargetable FROM openoutputs WHERE hash = ? AND index = ?";
    private static final String SELECT_OPENOUTPUTS_COUNT_SQL                    = "SELECT COUNT(*) FROM openoutputs WHERE hash = ?";
    private static final String INSERT_OPENOUTPUTS_SQL                          = "INSERT INTO openoutputs (hash, index, height, value, scriptbytes, toaddress, addresstargetable, coinbase) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String DELETE_OPENOUTPUTS_SQL                          = "DELETE FROM openoutputs WHERE hash = ? AND index = ?";

    // Dump table SQL (this is just for data sizing statistics).
    private static final String SELECT_DUMP_SETTINGS_SQL                        = "SELECT name, value FROM settings";
    private static final String SELECT_DUMP_HEADERS_SQL                         = "SELECT chainwork, header FROM headers";
    private static final String SELECT_DUMP_UNDOABLEBLOCKS_SQL                  = "SELECT txoutchanges, transactions FROM undoableblocks";
    private static final String SELECT_DUMP_OPENOUTPUTS_SQL                     = "SELECT value, scriptbytes FROM openoutputs";

    private static final String SELECT_TRANSACTION_OUTPUTS_SQL                  = "SELECT hash, value, scriptbytes, height, index, coinbase, toaddress, addresstargetable FROM openoutputs where toaddress = ?";

    // Select the balance of an address SQL.
    private static final String SELECT_BALANCE_SQL                              = "select sum(value) from openoutputs where toaddress = ?";

    // Tables exist SQL.
    private static final String SELECT_CHECK_TABLES_EXIST_SQL                   = "SELECT * FROM settings WHERE 1 = 2";

    // Compatibility SQL.
    private static final String SELECT_COMPATIBILITY_COINBASE_SQL               = "SELECT coinbase FROM openoutputs WHERE 1 = 2";

    protected Sha256Hash chainHeadHash;
    protected StoredBlock chainHeadBlock;
    protected Sha256Hash verifiedChainHeadHash;
    protected StoredBlock verifiedChainHeadBlock;
    protected NetworkParameters params;
    protected ThreadLocal<Connection> conn;
    protected List<Connection> allConnections;
    protected String connectionURL;
    protected int fullStoreDepth;
    protected String username;
    protected String password;
    protected String schemaName;

    /**
     * <p>Create a new DatabaseFullPrunedBlockStore, using the full connection URL instead of a hostname and password,
     * and optionally allowing a schema to be specified.</p>
     *
     * @param params A copy of the NetworkParameters used.
     * @param connectionURL The jdbc url to connect to the database.
     * @param fullStoreDepth The number of blocks of history stored in full (something like 1000 is pretty safe).
     * @param username The database username.
     * @param password The password to the database.
     * @param schemaName The name of the schema to put the tables in.  May be null if no schema is being used.
     * @throws BlockStoreException If there is a failure to connect and/or initialise the database.
     */
    public DatabaseFullPrunedBlockStore(NetworkParameters params, String connectionURL, int fullStoreDepth,
                                        @Nullable String username, @Nullable String password, @Nullable String schemaName) throws BlockStoreException {
        this.params = params;
        this.fullStoreDepth = fullStoreDepth;
        this.connectionURL = connectionURL;
        this.schemaName = schemaName;
        this.username = username;
        this.password = password;
        this.conn = new ThreadLocal<>();
        this.allConnections = new LinkedList<>();

        try {
            Class.forName(getDatabaseDriverClass());
            log.info(getDatabaseDriverClass() + " loaded. ");
        } catch (ClassNotFoundException e) {
            log.error("check CLASSPATH for database driver jar ", e);
        }

        maybeConnect();

        try {
            // Create tables if needed
            if (!tablesExists()) {
                createTables();
            } else {
                checkCompatibility();
            }
            initFromDatabase();
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    /**
     * Get the database driver class,
     * <p>i.e org.postgresql.Driver.</p>
     * @return The fully qualified database driver class.
     */
    protected abstract String getDatabaseDriverClass();

    /**
     * Get the SQL statements that create the schema (DDL).
     * @return The list of SQL statements.
     */
    protected abstract List<String> getCreateSchemeSQL();

    /**
     * Get the SQL statements that create the tables (DDL).
     * @return The list of SQL statements.
     */
    protected abstract List<String> getCreateTablesSQL();

    /**
     * Get the SQL statements that create the indexes (DDL).
     * @return The list of SQL statements.
     */
    protected abstract List<String> getCreateIndexesSQL();

    /**
     * Get the database specific error code that indicated a duplicate key error when inserting a record.
     * <p>This is the code returned by {@link SQLException#getSQLState()}</p>
     * @return The database duplicate error code.
     */
    protected abstract String getDuplicateKeyErrorCode();

    /**
     * Get the SQL to select the total balance for a given address.
     * @return The SQL prepared statement.
     */
    protected String getBalanceSelectSQL() {
        return SELECT_BALANCE_SQL;
    }

    /**
     * Get the SQL statement that checks if tables exist.
     * @return The SQL prepared statement.
     */
    protected String getTablesExistSQL() {
        return SELECT_CHECK_TABLES_EXIST_SQL;
    }

    /**
     * Get the SQL statements to check if the database is compatible.
     * @return The SQL prepared statements.
     */
    protected List<String> getCompatibilitySQL() {
        List<String> sqlStatements = new ArrayList<>();
        sqlStatements.add(SELECT_COMPATIBILITY_COINBASE_SQL);
        return sqlStatements;
    }

    /**
     * Get the SQL to select the transaction outputs for a given address.
     * @return The SQL prepared statement.
     */
    protected String getTransactionOutputSelectSQL() {
        return SELECT_TRANSACTION_OUTPUTS_SQL;
    }

    /**
     * Get the SQL to drop all the tables (DDL).
     * @return The SQL drop statements.
     */
    protected List<String> getDropTablesSQL() {
        List<String> sqlStatements = new ArrayList<>();
        sqlStatements.add(DROP_SETTINGS_TABLE);
        sqlStatements.add(DROP_HEADERS_TABLE);
        sqlStatements.add(DROP_UNDOABLE_TABLE);
        sqlStatements.add(DROP_OPEN_OUTPUT_TABLE);
        return sqlStatements;
    }

    /**
     * Get the SQL to select a setting value.
     * @return The SQL select statement.
     */
    protected String getSelectSettingsSQL() {
        return SELECT_SETTINGS_SQL;
    }

    /**
     * Get the SQL to insert a settings record.
     * @return The SQL insert statement.
     */
    protected String getInsertSettingsSQL() {
        return INSERT_SETTINGS_SQL;
    }

    /**
     * Get the SQL to update a setting value.
     * @return The SQL update statement.
     */
    protected String getUpdateSettingsSLQ() {
        return UPDATE_SETTINGS_SQL;
    }

    /**
     * Get the SQL to select a headers record.
     * @return The SQL select  statement.
     */
    protected String getSelectHeadersSQL() {
        return SELECT_HEADERS_SQL;
    }

    /**
     * Get the SQL to insert a headers record.
     * @return The SQL insert statement.
     */
    protected String getInsertHeadersSQL() {
        return INSERT_HEADERS_SQL;
    }

    /**
     * Get the SQL to update a headers record.
     * @return The SQL update statement.
     */
    protected String getUpdateHeadersSQL() {
        return UPDATE_HEADERS_SQL;
    }

    /**
     * Get the SQL to select an undoableblocks record.
     * @return The SQL select statement.
     */
    protected String getSelectUndoableBlocksSQL() {
        return SELECT_UNDOABLEBLOCKS_SQL;
    }

    /**
     * Get the SQL to insert a undoableblocks record.
     * @return The SQL insert statement.
     */
    protected String getInsertUndoableBlocksSQL() {
        return INSERT_UNDOABLEBLOCKS_SQL;
    }

    /**
     * Get the SQL to update a undoableblocks record.
     * @return The SQL update statement.
     */
    protected String getUpdateUndoableBlocksSQL() {
        return UPDATE_UNDOABLEBLOCKS_SQL;
    }

    /**
     * Get the SQL to delete a undoableblocks record.
     * @return The SQL delete statement.
     */
    protected String getDeleteUndoableBlocksSQL() {
        return DELETE_UNDOABLEBLOCKS_SQL;
    }

    /**
     * Get the SQL to select a openoutputs record.
     * @return The SQL select statement.
     */
    protected String getSelectOpenoutputsSQL() {
        return SELECT_OPENOUTPUTS_SQL;
    }

    /**
     * Get the SQL to select count of openoutputs.
     * @return The SQL select statement.
     */
    protected String getSelectOpenoutputsCountSQL() {
        return SELECT_OPENOUTPUTS_COUNT_SQL;
    }

    /**
     * Get the SQL to insert a openoutputs record.
     * @return The SQL insert statement.
     */
    protected String getInsertOpenoutputsSQL() {
        return INSERT_OPENOUTPUTS_SQL;
    }

    /**
     * Get the SQL to delete a openoutputs record.
     * @return The SQL delete statement.
     */
    protected String getDeleteOpenoutputsSQL() {
        return DELETE_OPENOUTPUTS_SQL;
    }

    /**
     * Get the SQL to select the setting dump fields for sizing/statistics.
     * @return The SQL select statement.
     */
    protected String getSelectSettingsDumpSQL() {
        return SELECT_DUMP_SETTINGS_SQL;
    }

    /**
     * Get the SQL to select the headers dump fields for sizing/statistics.
     * @return The SQL select statement.
     */
    protected String getSelectHeadersDumpSQL() {
        return SELECT_DUMP_HEADERS_SQL;
    }

    /**
     * Get the SQL to select the undoableblocks dump fields for sizing/statistics.
     * @return The SQL select statement.
     */
    protected String getSelectUndoableblocksDumpSQL() {
        return SELECT_DUMP_UNDOABLEBLOCKS_SQL;
    }

    /**
     * Get the SQL to select the openoutouts dump fields for sizing/statistics.
     * @return The SQL select statement.
     */
    protected String getSelectopenoutputsDumpSQL() {
        return SELECT_DUMP_OPENOUTPUTS_SQL;
    }

    /**
     * <p>If there isn't a connection on the {@link ThreadLocal} then create and store it.</p>
     * <p>This will also automatically set up the schema if it does not exist within the DB.</p>
     * @throws BlockStoreException if successful connection to the DB couldn't be made.
     */
    protected synchronized final void maybeConnect() throws BlockStoreException {
        try {
            if (conn.get() != null && !conn.get().isClosed())
                return;

            if (username == null || password == null) {
                conn.set(DriverManager.getConnection(connectionURL));
            } else {
                Properties props = new Properties();
                props.setProperty("user", this.username);
                props.setProperty("password", this.password);
                conn.set(DriverManager.getConnection(connectionURL, props));
            }
            allConnections.add(conn.get());
            Connection connection = conn.get();
            // set the schema if one is needed
            if (schemaName != null) {
                Statement s = connection.createStatement();
                for (String sql : getCreateSchemeSQL()) {
                    s.execute(sql);
                }
            }
            log.info("Made a new connection to database " + connectionURL);
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
    }

    @Override
    public synchronized void close() {
        for (Connection conn : allConnections) {
            try {
                if (!conn.getAutoCommit()) {
                    conn.rollback();
                }
                conn.close();
                if (conn == this.conn.get()) {
                    this.conn.set(null);
                }
            } catch (SQLException ex) {
                throw new RuntimeException(ex);
            }
        }
        allConnections.clear();
    }

    /**
     * <p>Check if a tables exists within the database.</p>
     *
     * <p>This specifically checks for the 'settings' table and
     * if it exists makes an assumption that the rest of the data
     * structures are present.</p>
     *
     * @return If the tables exists.
     * @throws java.sql.SQLException
     */
    private boolean tablesExists() throws SQLException {
        PreparedStatement ps = null;
        try {
            ps = conn.get().prepareStatement(getTablesExistSQL());
            ResultSet results = ps.executeQuery();
            results.close();
            return true;
        } catch (SQLException ex) {
            return false;
        } finally {
            if(ps != null && !ps.isClosed()) {
                ps.close();
            }
        }
    }

    /**
     * Check that the database is compatible with this version of the {@link DatabaseFullPrunedBlockStore}.
     * @throws BlockStoreException If the database is not compatible.
     */
    private void checkCompatibility() throws SQLException, BlockStoreException {
        for(String sql : getCompatibilitySQL()) {
            PreparedStatement ps = null;
            try {
                ps = conn.get().prepareStatement(sql);
                ResultSet results = ps.executeQuery();
                results.close();
            } catch (SQLException ex) {
                throw new BlockStoreException("Database block store is not compatible with the current release.  " +
                        "See bitcoinj release notes for further information: " + ex.getMessage());
            } finally {
                if (ps != null && !ps.isClosed()) {
                    ps.close();
                }
            }
        }
    }

    /**
     * Create the tables/block store in the database and
     * @throws java.sql.SQLException If there is a database error.
     * @throws BlockStoreException If the block store could not be created.
     */
    private void createTables() throws SQLException, BlockStoreException {
        Statement s = conn.get().createStatement();
        // create all the database tables
        for (String sql : getCreateTablesSQL()) {
            if (log.isDebugEnabled()) {
                log.debug("DatabaseFullPrunedBlockStore : CREATE table [SQL= {0}]", sql);
            }
            s.executeUpdate(sql);
        }
        // create all the database indexes
        for (String sql : getCreateIndexesSQL()) {
            if (log.isDebugEnabled()) {
                log.debug("DatabaseFullPrunedBlockStore : CREATE index [SQL= {0}]", sql);
            }
            s.executeUpdate(sql);
        }
        s.close();

        // insert the initial settings for this store
        PreparedStatement ps = conn.get().prepareStatement(getInsertSettingsSQL());
        ps.setString(1, CHAIN_HEAD_SETTING);
        ps.setNull(2, Types.BINARY);
        ps.execute();
        ps.setString(1, VERIFIED_CHAIN_HEAD_SETTING);
        ps.setNull(2, Types.BINARY);
        ps.execute();
        ps.setString(1, VERSION_SETTING);
        ps.setBytes(2, "03".getBytes());
        ps.execute();
        ps.close();
        createNewStore(params);
    }

    /**
     * Create a new store for the given {@link NetworkParameters}.
     * @param params The network.
     * @throws BlockStoreException If the store couldn't be created.
     */
    private void createNewStore(NetworkParameters params) throws BlockStoreException {
        try {
            // Set up the genesis block. When we start out fresh, it is by
            // definition the top of the chain.
            StoredBlock storedGenesisHeader = new StoredBlock(params.getGenesisBlock().cloneAsHeader(), params.getGenesisBlock().getWork(), 0);
            // The coinbase in the genesis block is not spendable. This is because of how Bitcoin Core inits
            // its database - the genesis transaction isn't actually in the db so its spent flags can never be updated.
            List<Transaction> genesisTransactions = new LinkedList<>();
            StoredUndoableBlock storedGenesis = new StoredUndoableBlock(params.getGenesisBlock().getHash(), genesisTransactions);
            put(storedGenesisHeader, storedGenesis);
            setChainHead(storedGenesisHeader);
            setVerifiedChainHead(storedGenesisHeader);
        } catch (VerificationException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    /**
     * Initialise the store state from the database.
     * @throws java.sql.SQLException If there is a database error.
     * @throws BlockStoreException If there is a block store error.
     */
    private void initFromDatabase() throws SQLException, BlockStoreException {
        PreparedStatement ps = conn.get().prepareStatement(getSelectSettingsSQL());
        ResultSet rs;
        ps.setString(1, CHAIN_HEAD_SETTING);
        rs = ps.executeQuery();
        if (!rs.next()) {
            throw new BlockStoreException("corrupt database block store - no chain head pointer");
        }
        Sha256Hash hash = Sha256Hash.wrap(rs.getBytes(1));
        rs.close();
        this.chainHeadBlock = get(hash);
        this.chainHeadHash = hash;
        if (this.chainHeadBlock == null) {
            throw new BlockStoreException("corrupt database block store - head block not found");
        }
        ps.setString(1, VERIFIED_CHAIN_HEAD_SETTING);
        rs = ps.executeQuery();
        if (!rs.next()) {
            throw new BlockStoreException("corrupt database block store - no verified chain head pointer");
        }
        hash = Sha256Hash.wrap(rs.getBytes(1));
        rs.close();
        ps.close();
        this.verifiedChainHeadBlock = get(hash);
        this.verifiedChainHeadHash = hash;
        if (this.verifiedChainHeadBlock == null) {
            throw new BlockStoreException("corrupt database block store - verified head block not found");
        }
    }

    protected void putUpdateStoredBlock(StoredBlock storedBlock, boolean wasUndoable) throws SQLException {
        try {
            PreparedStatement s =
                    conn.get().prepareStatement(getInsertHeadersSQL());
            // We skip the first 4 bytes because (on mainnet) the minimum target has 4 0-bytes
            byte[] hashBytes = new byte[28];
            System.arraycopy(storedBlock.getHeader().getHash().getBytes(), 4, hashBytes, 0, 28);
            s.setBytes(1, hashBytes);
            s.setBytes(2, storedBlock.getChainWork().toByteArray());
            s.setInt(3, storedBlock.getHeight());
            s.setBytes(4, storedBlock.getHeader().cloneAsHeader().unsafeBitcoinSerialize());
            s.setBoolean(5, wasUndoable);
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            // It is possible we try to add a duplicate StoredBlock if we upgraded
            // In that case, we just update the entry to mark it wasUndoable
            if  (!(e.getSQLState().equals(getDuplicateKeyErrorCode())) || !wasUndoable)
                throw e;

            PreparedStatement s = conn.get().prepareStatement(getUpdateHeadersSQL());
            s.setBoolean(1, true);
            // We skip the first 4 bytes because (on mainnet) the minimum target has 4 0-bytes
            byte[] hashBytes = new byte[28];
            System.arraycopy(storedBlock.getHeader().getHash().getBytes(), 4, hashBytes, 0, 28);
            s.setBytes(2, hashBytes);
            s.executeUpdate();
            s.close();
        }
    }

    @Override
    public void put(StoredBlock storedBlock) throws BlockStoreException {
        maybeConnect();
        try {
            putUpdateStoredBlock(storedBlock, false);
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }


    @Override
    public void put(StoredBlock storedBlock, StoredUndoableBlock undoableBlock) throws BlockStoreException {
        maybeConnect();
        // We skip the first 4 bytes because (on mainnet) the minimum target has 4 0-bytes
        byte[] hashBytes = new byte[28];
        System.arraycopy(storedBlock.getHeader().getHash().getBytes(), 4, hashBytes, 0, 28);
        int height = storedBlock.getHeight();
        byte[] transactions = null;
        byte[] txOutChanges = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (undoableBlock.getTxOutChanges() != null) {
                undoableBlock.getTxOutChanges().serializeToStream(bos);
                txOutChanges = bos.toByteArray();
            } else {
                int numTxn = undoableBlock.getTransactions().size();
                Utils.uint32ToByteStreamLE(numTxn, bos);
                for (Transaction tx : undoableBlock.getTransactions())
                    tx.bitcoinSerialize(bos);
                transactions = bos.toByteArray();
            }
            bos.close();
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }

        try {
            try {
                PreparedStatement s =
                        conn.get().prepareStatement(getInsertUndoableBlocksSQL());
                s.setBytes(1, hashBytes);
                s.setInt(2, height);
                if (transactions == null) {
                    s.setBytes(3, txOutChanges);
                    s.setNull(4, Types.BINARY);
                } else {
                    s.setNull(3, Types.BINARY);
                    s.setBytes(4, transactions);
                }
                s.executeUpdate();
                s.close();
                try {
                    putUpdateStoredBlock(storedBlock, true);
                } catch (SQLException e) {
                    throw new BlockStoreException(e);
                }
            } catch (SQLException e) {
                if (!e.getSQLState().equals(getDuplicateKeyErrorCode()))
                    throw new BlockStoreException(e);

                // There is probably an update-or-insert statement, but it wasn't obvious from the docs
                PreparedStatement s =
                        conn.get().prepareStatement(getUpdateUndoableBlocksSQL());
                s.setBytes(3, hashBytes);
                if (transactions == null) {
                    s.setBytes(1, txOutChanges);
                    s.setNull(2, Types.BINARY);
                } else {
                    s.setNull(1, Types.BINARY);
                    s.setBytes(2, transactions);
                }
                s.executeUpdate();
                s.close();
            }
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
    }

    public StoredBlock get(Sha256Hash hash, boolean wasUndoableOnly) throws BlockStoreException {
        // Optimize for chain head
        if (chainHeadHash != null && chainHeadHash.equals(hash))
            return chainHeadBlock;
        if (verifiedChainHeadHash != null && verifiedChainHeadHash.equals(hash))
            return verifiedChainHeadBlock;
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get()
                    .prepareStatement(getSelectHeadersSQL());
            // We skip the first 4 bytes because (on mainnet) the minimum target has 4 0-bytes
            byte[] hashBytes = new byte[28];
            System.arraycopy(hash.getBytes(), 4, hashBytes, 0, 28);
            s.setBytes(1, hashBytes);
            ResultSet results = s.executeQuery();
            if (!results.next()) {
                return null;
            }
            // Parse it.

            if (wasUndoableOnly && !results.getBoolean(4))
                return null;

            BigInteger chainWork = new BigInteger(results.getBytes(1));
            int height = results.getInt(2);
            Block b = params.getDefaultSerializer().makeBlock(results.getBytes(3));
            b.verifyHeader();
            StoredBlock stored = new StoredBlock(b, chainWork, height);
            return stored;
        } catch (SQLException | VerificationException e) {
            // VerificationException: Should not be able to happen unless the database contains bad blocks.
            throw new BlockStoreException(e);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new BlockStoreException("Failed to close PreparedStatement");
                }
            }
        }
    }

    @Override
    public StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        return get(hash, false);
    }

    @Override
    public StoredBlock getOnceUndoableStoredBlock(Sha256Hash hash) throws BlockStoreException {
        return get(hash, true);
    }

    @Override
    public StoredUndoableBlock getUndoBlock(Sha256Hash hash) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get()
                    .prepareStatement(getSelectUndoableBlocksSQL());
            // We skip the first 4 bytes because (on mainnet) the minimum target has 4 0-bytes

            byte[] hashBytes = new byte[28];
            System.arraycopy(hash.getBytes(), 4, hashBytes, 0, 28);
            s.setBytes(1, hashBytes);
            ResultSet results = s.executeQuery();
            if (!results.next()) {
                return null;
            }
            // Parse it.
            byte[] txOutChanges = results.getBytes(1);
            byte[] transactions = results.getBytes(2);
            StoredUndoableBlock block;
            if (txOutChanges == null) {
                int numTxn = (int) Utils.readUint32(transactions, 0);
                int offset = 4;
                List<Transaction> transactionList = new LinkedList<>();
                for (int i = 0; i < numTxn; i++) {
                    Transaction tx = params.getDefaultSerializer().makeTransaction(transactions, offset);
                    transactionList.add(tx);
                    offset += tx.getMessageSize();
                }
                block = new StoredUndoableBlock(hash, transactionList);
            } else {
                TransactionOutputChanges outChangesObject =
                        new TransactionOutputChanges(new ByteArrayInputStream(txOutChanges));
                block = new StoredUndoableBlock(hash, outChangesObject);
            }
            return block;
        } catch (SQLException | IOException | ProtocolException | ClassCastException | NullPointerException e) {
            // IOException, ProtocolException, ClassCastException, NullPointerException: Corrupted database.
            throw new BlockStoreException(e);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new BlockStoreException("Failed to close PreparedStatement");
                }
            }
        }
    }

    @Override
    public StoredBlock getChainHead() throws BlockStoreException {
        return chainHeadBlock;
    }

    @Override
    public void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        Sha256Hash hash = chainHead.getHeader().getHash();
        this.chainHeadHash = hash;
        this.chainHeadBlock = chainHead;
        maybeConnect();
        try {
            PreparedStatement s = conn.get()
                    .prepareStatement(getUpdateSettingsSLQ());
            s.setString(2, CHAIN_HEAD_SETTING);
            s.setBytes(1, hash.getBytes());
            s.executeUpdate();
            s.close();
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
    }

    @Override
    public StoredBlock getVerifiedChainHead() throws BlockStoreException {
        return verifiedChainHeadBlock;
    }

    @Override
    public void setVerifiedChainHead(StoredBlock chainHead) throws BlockStoreException {
        Sha256Hash hash = chainHead.getHeader().getHash();
        this.verifiedChainHeadHash = hash;
        this.verifiedChainHeadBlock = chainHead;
        maybeConnect();
        try {
            PreparedStatement s = conn.get()
                    .prepareStatement(getUpdateSettingsSLQ());
            s.setString(2, VERIFIED_CHAIN_HEAD_SETTING);
            s.setBytes(1, hash.getBytes());
            s.executeUpdate();
            s.close();
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
        if (this.chainHeadBlock.getHeight() < chainHead.getHeight())
            setChainHead(chainHead);
        removeUndoableBlocksWhereHeightIsLessThan(chainHead.getHeight() - fullStoreDepth);
    }

    private void removeUndoableBlocksWhereHeightIsLessThan(int height) throws BlockStoreException {
        try {
            PreparedStatement s = conn.get()
                    .prepareStatement(getDeleteUndoableBlocksSQL());
            s.setInt(1, height);
            if (log.isDebugEnabled())
                log.debug("Deleting undoable undoable block with height <= " + height);
            s.executeUpdate();
            s.close();
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
    }

    @Override
    public UTXO getTransactionOutput(Sha256Hash hash, long index) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get()
                    .prepareStatement(getSelectOpenoutputsSQL());
            s.setBytes(1, hash.getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int) index);
            ResultSet results = s.executeQuery();
            if (!results.next()) {
                return null;
            }
            // Parse it.
            int height = results.getInt(1);
            Coin value = Coin.valueOf(results.getLong(2));
            byte[] scriptBytes = results.getBytes(3);
            boolean coinbase = results.getBoolean(4);
            String address = results.getString(5);
            UTXO txout = new UTXO(hash,
                    index,
                    value,
                    height,
                    coinbase,
                    new Script(scriptBytes),
                    address);
            return txout;
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new BlockStoreException("Failed to close PreparedStatement");
                }
            }
        }
    }

    @Override
    public void addUnspentTransactionOutput(UTXO out) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get().prepareStatement(getInsertOpenoutputsSQL());
            s.setBytes(1, out.getHash().getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int) out.getIndex());
            s.setInt(3, out.getHeight());
            s.setLong(4, out.getValue().value);
            s.setBytes(5, out.getScript().getProgram());
            s.setString(6, out.getAddress());
            ScriptType scriptType = out.getScript().getScriptType();
            s.setInt(7, scriptType != null ? scriptType.id : 0);
            s.setBoolean(8, out.isCoinbase());
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            if (!(e.getSQLState().equals(getDuplicateKeyErrorCode())))
                throw new BlockStoreException(e);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new BlockStoreException(e);
                }
            }
        }
    }

    @Override
    public void removeUnspentTransactionOutput(UTXO out) throws BlockStoreException {
        maybeConnect();
        // TODO: This should only need one query (maybe a stored procedure)
        if (getTransactionOutput(out.getHash(), out.getIndex()) == null)
            throw new BlockStoreException("Tried to remove a UTXO from DatabaseFullPrunedBlockStore that it didn't have!");
        try {
            PreparedStatement s = conn.get()
                    .prepareStatement(getDeleteOpenoutputsSQL());
            s.setBytes(1, out.getHash().getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int)out.getIndex());
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    @Override
    public void beginDatabaseBatchWrite() throws BlockStoreException {
        maybeConnect();
        if (log.isDebugEnabled())
            log.debug("Starting database batch write with connection: " + conn.get().toString());
        try {
            conn.get().setAutoCommit(false);
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    @Override
    public void commitDatabaseBatchWrite() throws BlockStoreException {
        maybeConnect();
        if (log.isDebugEnabled())
            log.debug("Committing database batch write with connection: " + conn.get().toString());
        try {
            conn.get().commit();
            conn.get().setAutoCommit(true);
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    @Override
    public void abortDatabaseBatchWrite() throws BlockStoreException {
        maybeConnect();
        if (log.isDebugEnabled())
            log.debug("Rollback database batch write with connection: " + conn.get().toString());
        try {
            if (!conn.get().getAutoCommit()) {
                conn.get().rollback();
                conn.get().setAutoCommit(true);
            } else {
                log.warn("Warning: Rollback attempt without transaction");
            }
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    @Override
    public boolean hasUnspentOutputs(Sha256Hash hash, int numOutputs) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get().prepareStatement(getSelectOpenoutputsCountSQL());
            s.setBytes(1, hash.getBytes());
            ResultSet results = s.executeQuery();
            if (!results.next()) {
                throw new BlockStoreException("Got no results from a COUNT(*) query");
            }
            int count = results.getInt(1);
            return count != 0;
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new BlockStoreException("Failed to close PreparedStatement");
                }
            }
        }
    }

    @Override
    public NetworkParameters getParams() {
        return params;
    }

    @Override
    public int getChainHeadHeight() throws UTXOProviderException {
        try {
            return getVerifiedChainHead().getHeight();
        } catch (BlockStoreException e) {
            throw new UTXOProviderException(e);
        }
    }

    /**
     * Resets the store by deleting the contents of the tables and reinitialising them.
     * @throws BlockStoreException If the tables couldn't be cleared and initialised.
     */
    public void resetStore() throws BlockStoreException {
        maybeConnect();
        try {
            deleteStore();
            createTables();
            initFromDatabase();
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Deletes the store by deleting the tables within the database.
     * @throws BlockStoreException If tables couldn't be deleted.
     */
    public void deleteStore() throws BlockStoreException {
        maybeConnect();
        try {
            Statement s = conn.get().createStatement();
            for(String sql : getDropTablesSQL()) {
                s.execute(sql);
            }
            s.close();
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Calculate the balance for a coinbase, to-address, or p2sh address.
     *
     * <p>The balance {@link DatabaseFullPrunedBlockStore#getBalanceSelectSQL()} returns
     * the balance (summed) as an number, then use calculateClientSide=false</p>
     *
     * <p>The balance {@link DatabaseFullPrunedBlockStore#getBalanceSelectSQL()} returns
     * the all the openoutputs as stored in the DB (binary), then use calculateClientSide=true</p>
     *
     * @param address The address to calculate the balance of
     * @return The balance of the address supplied.  If the address has not been seen, or there are no outputs open for this
     *         address, the return value is 0.
     * @throws BlockStoreException If there is an error getting the balance.
     */
    public BigInteger calculateBalanceForAddress(Address address) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get().prepareStatement(getBalanceSelectSQL());
            s.setString(1, address.toString());
            ResultSet rs = s.executeQuery();
            BigInteger balance = BigInteger.ZERO;
            if (rs.next()) {
                return BigInteger.valueOf(rs.getLong(1));
            }
            return balance;
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new BlockStoreException("Could not close statement");
                }
            }
        }
    }

    @Override
    public List<UTXO> getOpenTransactionOutputs(List<ECKey> keys) throws UTXOProviderException {
        PreparedStatement s = null;
        List<UTXO> outputs = new ArrayList<>();
        try {
            maybeConnect();
            s = conn.get().prepareStatement(getTransactionOutputSelectSQL());
            for (ECKey key : keys) {
                // TODO switch to pubKeyHash in order to support native segwit addresses
                s.setString(1, LegacyAddress.fromKey(params, key).toString());
                ResultSet rs = s.executeQuery();
                while (rs.next()) {
                    Sha256Hash hash = Sha256Hash.wrap(rs.getBytes(1));
                    Coin amount = Coin.valueOf(rs.getLong(2));
                    byte[] scriptBytes = rs.getBytes(3);
                    int height = rs.getInt(4);
                    int index = rs.getInt(5);
                    boolean coinbase = rs.getBoolean(6);
                    String toAddress = rs.getString(7);
                    UTXO output = new UTXO(hash,
                            index,
                            amount,
                            height,
                            coinbase,
                            new Script(scriptBytes),
                            toAddress);
                    outputs.add(output);
                }
            }
            return outputs;
        } catch (SQLException | BlockStoreException ex) {
            throw new UTXOProviderException(ex);
        } finally {
            if (s != null)
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new UTXOProviderException("Could not close statement", e);
                }
        }
    }

    /**
     * Dumps information about the size of actual data in the database to standard output
     * The only truly useless data counted is printed in the form "N in id indexes"
     * This does not take database indexes into account.
     */
    public void dumpSizes() throws SQLException, BlockStoreException {
        maybeConnect();
        Statement s = conn.get().createStatement();
        long size = 0;
        long totalSize = 0;
        int count = 0;
        ResultSet rs = s.executeQuery(getSelectSettingsDumpSQL());
        while (rs.next()) {
            size += rs.getString(1).length();
            size += rs.getBytes(2).length;
            count++;
        }
        rs.close();
        System.out.printf(Locale.US, "Settings size: %d, count: %d, average size: %f%n", size, count, (double)size/count);

        totalSize += size; size = 0; count = 0;
        rs = s.executeQuery(getSelectHeadersDumpSQL());
        while (rs.next()) {
            size += 28; // hash
            size += rs.getBytes(1).length;
            size += 4; // height
            size += rs.getBytes(2).length;
            count++;
        }
        rs.close();
        System.out.printf(Locale.US, "Headers size: %d, count: %d, average size: %f%n", size, count, (double)size/count);

        totalSize += size; size = 0; count = 0;
        rs = s.executeQuery(getSelectUndoableblocksDumpSQL());
        while (rs.next()) {
            size += 28; // hash
            size += 4; // height
            byte[] txOutChanges = rs.getBytes(1);
            byte[] transactions = rs.getBytes(2);
            if (txOutChanges == null)
                size += transactions.length;
            else
                size += txOutChanges.length;
            // size += the space to represent NULL
            count++;
        }
        rs.close();
        System.out.printf(Locale.US, "Undoable Blocks size: %d, count: %d, average size: %f%n", size, count, (double)size/count);

        totalSize += size; size = 0; count = 0;
        long scriptSize = 0;
        rs = s.executeQuery(getSelectopenoutputsDumpSQL());
        while (rs.next()) {
            size += 32; // hash
            size += 4; // index
            size += 4; // height
            size += rs.getBytes(1).length;
            size += rs.getBytes(2).length;
            scriptSize += rs.getBytes(2).length;
            count++;
        }
        rs.close();
        System.out.printf(Locale.US, "Open Outputs size: %d, count: %d, average size: %f, average script size: %f (%d in id indexes)%n",
                size, count, (double)size/count, (double)scriptSize/count, count * 8);

        totalSize += size;
        System.out.println("Total Size: " + totalSize);

        s.close();
    }
}
