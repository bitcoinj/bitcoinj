/*
 * Copyright 2012 Matt Corallo.
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

package com.google.bitcoin.store;

import com.google.bitcoin.core.*;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.sql.*;
import java.util.LinkedList;
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
public class H2FullPrunedBlockStore implements FullPrunedBlockStore {
    private static final Logger log = LoggerFactory.getLogger(H2FullPrunedBlockStore.class);

    private Sha256Hash chainHeadHash;
    private StoredBlock chainHeadBlock;
    private Sha256Hash verifiedChainHeadHash;
    private StoredBlock verifiedChainHeadBlock;
    private NetworkParameters params;
    private ThreadLocal<Connection> conn;
    private List<Connection> allConnections;
    private String connectionURL;
    private int fullStoreDepth;

    static final String driver = "org.h2.Driver";
    static final String CREATE_SETTINGS_TABLE = "CREATE TABLE settings ( "
        + "name VARCHAR(32) NOT NULL CONSTRAINT settings_pk PRIMARY KEY,"
        + "value BLOB"
        + ")";
    static final String CHAIN_HEAD_SETTING = "chainhead";
    static final String VERIFIED_CHAIN_HEAD_SETTING = "verifiedchainhead";

    static final String CREATE_HEADERS_TABLE = "CREATE TABLE headers ( "
        + "hash BINARY(28) NOT NULL CONSTRAINT headers_pk PRIMARY KEY,"
        + "chainWork BLOB NOT NULL,"
        + "height INT NOT NULL,"
        + "header BLOB NOT NULL,"
        + "wasUndoable BOOL NOT NULL"
        + ")";
    
    static final String CREATE_UNDOABLE_TABLE = "CREATE TABLE undoableBlocks ( "
        + "hash BINARY(28) NOT NULL CONSTRAINT undoableBlocks_pk PRIMARY KEY,"
        + "height INT NOT NULL,"
        + "txOutChanges BLOB,"
        + "transactions BLOB"
        + ")";
    static final String CREATE_UNDOABLE_TABLE_INDEX = "CREATE INDEX heightIndex ON undoableBlocks (height)";
    
    static final String CREATE_OPEN_OUTPUT_INDEX_TABLE = "CREATE TABLE openOutputsIndex ("
        + "hash BINARY(32) NOT NULL CONSTRAINT openOutputsIndex_pk PRIMARY KEY,"
        + "height INT NOT NULL,"
        + "id BIGINT NOT NULL AUTO_INCREMENT"
        + ")";
    static final String CREATE_OPEN_OUTPUT_TABLE = "CREATE TABLE openOutputs ("
        + "id BIGINT NOT NULL,"
        + "index INT NOT NULL,"
        + "value BLOB NOT NULL,"
        + "scriptBytes BLOB NOT NULL,"
        + "PRIMARY KEY (id, index),"
        + "CONSTRAINT openOutputs_fk FOREIGN KEY (id) REFERENCES openOutputsIndex(id)"
        + ")";

    /**
     * Creates a new H2FullPrunedBlockStore
     * @param params A copy of the NetworkParameters used
     * @param dbName The path to the database on disk
     * @param fullStoreDepth The number of blocks of history stored in full (something like 1000 is pretty safe)
     * @throws BlockStoreException if the database fails to open for any reason
     */
    public H2FullPrunedBlockStore(NetworkParameters params, String dbName, int fullStoreDepth) throws BlockStoreException {
        this.params = params;
        this.fullStoreDepth = fullStoreDepth;
        connectionURL = "jdbc:h2:" + dbName + ";create=true";
        
        conn = new ThreadLocal<Connection>();
        allConnections = new LinkedList<Connection>();

        try {
            Class.forName(driver);
            log.info(driver + " loaded. ");
        } catch (java.lang.ClassNotFoundException e) {
            log.error("check CLASSPATH for H2 jar ", e);
        }
        
        maybeConnect();
        
        try {
            // Create tables if needed
            if (!tableExists("settings"))
                createTables();
            initFromDatabase();
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
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
    
    private synchronized void maybeConnect() throws BlockStoreException {
        try {
            if (conn.get() != null)
                return;
            
            conn.set(DriverManager.getConnection(connectionURL));
            allConnections.add(conn.get());
            log.info("Made a new connection to database " + connectionURL);
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
    }
    
    public synchronized void close() {
        for (Connection conn : allConnections) {
            try {
                conn.rollback();
            } catch (SQLException ex) {
                throw new RuntimeException(ex);
            }
        }
        allConnections.clear();
    }

    public void resetStore() throws BlockStoreException {
        maybeConnect();
        try {
            Statement s = conn.get().createStatement();
            s.executeUpdate("DROP TABLE settings");
            s.executeUpdate("DROP TABLE headers");
            s.executeUpdate("DROP TABLE undoableBlocks");
            s.executeUpdate("DROP TABLE openOutputs");
            s.executeUpdate("DROP TABLE openOutputsIndex");
            s.close();
            createTables();
            initFromDatabase();
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void createTables() throws SQLException, BlockStoreException {
        Statement s = conn.get().createStatement();
        log.debug("H2FullPrunedBlockStore : CREATE headers table");
        s.executeUpdate(CREATE_HEADERS_TABLE);

        log.debug("H2FullPrunedBlockStore : CREATE settings table");
        s.executeUpdate(CREATE_SETTINGS_TABLE);
        
        log.debug("H2FullPrunedBlockStore : CREATE undoable block table");
        s.executeUpdate(CREATE_UNDOABLE_TABLE);
        
        log.debug("H2FullPrunedBlockStore : CREATE undoable block index");
        s.executeUpdate(CREATE_UNDOABLE_TABLE_INDEX);
        
        log.debug("H2FullPrunedBlockStore : CREATE open output index table");
        s.executeUpdate(CREATE_OPEN_OUTPUT_INDEX_TABLE);
        
        log.debug("H2FullPrunedBlockStore : CREATE open output table");
        s.executeUpdate(CREATE_OPEN_OUTPUT_TABLE);

        s.executeUpdate("INSERT INTO settings(name, value) VALUES('" + CHAIN_HEAD_SETTING + "', NULL)");
        s.executeUpdate("INSERT INTO settings(name, value) VALUES('" + VERIFIED_CHAIN_HEAD_SETTING + "', NULL)");
        s.close();
        createNewStore(params);
    }

    private void initFromDatabase() throws SQLException, BlockStoreException {
        Statement s = conn.get().createStatement();
        ResultSet rs = s.executeQuery("SELECT value FROM settings WHERE name = '" + CHAIN_HEAD_SETTING + "'");
        if (!rs.next()) {
            throw new BlockStoreException("corrupt H2 block store - no chain head pointer");
        }
        Sha256Hash hash = new Sha256Hash(rs.getBytes(1));
        rs.close();
        this.chainHeadBlock = get(hash);
        this.chainHeadHash = hash;
        if (this.chainHeadBlock == null)
        {
            throw new BlockStoreException("corrupt H2 block store - head block not found");
        }
        
        rs = s.executeQuery("SELECT value FROM settings WHERE name = '" + VERIFIED_CHAIN_HEAD_SETTING + "'");
        if (!rs.next()) {
            throw new BlockStoreException("corrupt H2 block store - no verified chain head pointer");
        }
        hash = new Sha256Hash(rs.getBytes(1));
        rs.close();
        s.close();
        this.verifiedChainHeadBlock = get(hash);
        this.verifiedChainHeadHash = hash;
        if (this.verifiedChainHeadBlock == null)
        {
            throw new BlockStoreException("corrupt H2 block store - verified head block not found");
        }
    }

    private void createNewStore(NetworkParameters params) throws BlockStoreException {
        try {
            // Set up the genesis block. When we start out fresh, it is by
            // definition the top of the chain.
            StoredBlock storedGenesisHeader = new StoredBlock(params.genesisBlock.cloneAsHeader(), params.genesisBlock.getWork(), 0);
            // The coinbase in the genesis block is not spendable. This is because of how the reference client inits
            // its database - the genesis transaction isn't actually in the db so its spent flags can never be updated.
            List<Transaction> genesisTransactions = Lists.newLinkedList();
            StoredUndoableBlock storedGenesis = new StoredUndoableBlock(params.genesisBlock.getHash(), genesisTransactions);
            put(storedGenesisHeader, storedGenesis);
            setChainHead(storedGenesisHeader);
            setVerifiedChainHead(storedGenesisHeader);
        } catch (VerificationException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    private boolean tableExists(String table) throws SQLException {
        Statement s = conn.get().createStatement();
        try {
            ResultSet results = s.executeQuery("SELECT * FROM " + table + " WHERE 1 = 2");
            results.close();
            return true;
        } catch (SQLException ex) {
            return false;
        } finally {
            s.close();
        }
    }
    
    /**
     * Dumps information about the size of actual data in the database to standard output
     * The only truly useless data counted is printed in the form "N in id indexes"
     * This does not take database indexes into account
     */
    public void dumpSizes() throws SQLException, BlockStoreException {
        maybeConnect();
        Statement s = conn.get().createStatement();
        long size = 0;
        long totalSize = 0;
        int count = 0;
        ResultSet rs = s.executeQuery("SELECT name, value FROM settings");
        while (rs.next()) {
            size += rs.getString(1).length();
            size += rs.getBytes(2).length;
            count++;
        }
        rs.close();
        System.out.printf("Settings size: %d, count: %d, average size: %f%n", size, count, (double)size/count);
        
        totalSize += size; size = 0; count = 0;
        rs = s.executeQuery("SELECT chainWork, header FROM headers");
        while (rs.next()) {
            size += 28; // hash
            size += rs.getBytes(1).length;
            size += 4; // height
            size += rs.getBytes(2).length;
            count++;
        }
        rs.close();
        System.out.printf("Headers size: %d, count: %d, average size: %f%n", size, count, (double)size/count);
        
        totalSize += size; size = 0; count = 0;
        rs = s.executeQuery("SELECT txOutChanges, transactions FROM undoableBlocks");
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
        System.out.printf("Undoable Blocks size: %d, count: %d, average size: %f%n", size, count, (double)size/count);
        
        totalSize += size; size = 0; count = 0;
        rs = s.executeQuery("SELECT id FROM openOutputsIndex");
        while (rs.next()) {
            size += 32; // hash
            size += 4; // height
            size += 8; // id
            count++;
        }
        rs.close();
        System.out.printf("Open Outputs Index size: %d, count: %d, size in id indexes: %d%n", size, count, count * 8);
        
        totalSize += size; size = 0; count = 0;
        long scriptSize = 0;
        rs = s.executeQuery("SELECT value, scriptBytes FROM openOutputs");
        while (rs.next()) {
            size += 8; // id
            size += 4; // index
            size += rs.getBytes(1).length;
            size += rs.getBytes(2).length;
            scriptSize += rs.getBytes(2).length;
            count++;
        }
        rs.close();
        System.out.printf("Open Outputs size: %d, count: %d, average size: %f, average script size: %f (%d in id indexes)%n",
                size, count, (double)size/count, (double)scriptSize/count, count * 8);
        
        totalSize += size;
        System.out.println("Total Size: " + totalSize);
        
        s.close();
    }
    
    
    private void putUpdateStoredBlock(StoredBlock storedBlock, boolean wasUndoable) throws SQLException {
        try {
            PreparedStatement s =
                    conn.get().prepareStatement("INSERT INTO headers(hash, chainWork, height, header, wasUndoable)"
                            + " VALUES(?, ?, ?, ?, ?)");
            // We skip the first 4 bytes because (on prodnet) the minimum target has 4 0-bytes
            byte[] hashBytes = new byte[28];
            System.arraycopy(storedBlock.getHeader().getHash().getBytes(), 3, hashBytes, 0, 28);
            s.setBytes(1, hashBytes);
            s.setBytes(2, storedBlock.getChainWork().toByteArray());
            s.setInt(3, storedBlock.getHeight());
            s.setBytes(4, storedBlock.getHeader().unsafeBitcoinSerialize());
            s.setBoolean(5, wasUndoable);
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            // It is possible we try to add a duplicate StoredBlock if we upgraded
            // In that case, we just update the entry to mark it wasUndoable
            if (e.getErrorCode() != 23505 || !wasUndoable)
                throw e;
            
            PreparedStatement s = conn.get().prepareStatement("UPDATE headers SET wasUndoable=? WHERE hash=?");
            s.setBoolean(1, true);
            // We skip the first 4 bytes because (on prodnet) the minimum target has 4 0-bytes
            byte[] hashBytes = new byte[28];
            System.arraycopy(storedBlock.getHeader().getHash().getBytes(), 3, hashBytes, 0, 28);
            s.setBytes(2, hashBytes);
            s.executeUpdate();
            s.close();
        }
    }

    public void put(StoredBlock storedBlock) throws BlockStoreException {
        maybeConnect();
        try {
            putUpdateStoredBlock(storedBlock, false);
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }
    
    public void put(StoredBlock storedBlock, StoredUndoableBlock undoableBlock) throws BlockStoreException {
        maybeConnect();
        // We skip the first 4 bytes because (on prodnet) the minimum target has 4 0-bytes
        byte[] hashBytes = new byte[28];
        System.arraycopy(storedBlock.getHeader().getHash().getBytes(), 3, hashBytes, 0, 28);
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
                bos.write((int) (0xFF & (numTxn >> 0)));
                bos.write((int) (0xFF & (numTxn >> 8)));
                bos.write((int) (0xFF & (numTxn >> 16)));
                bos.write((int) (0xFF & (numTxn >> 24)));
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
                        conn.get().prepareStatement("INSERT INTO undoableBlocks(hash, height, txOutChanges, transactions)"
                                + " VALUES(?, ?, ?, ?)");
                s.setBytes(1, hashBytes);
                s.setInt(2, height);
                if (transactions == null) {
                    s.setBytes(3, txOutChanges);
                    s.setNull(4, Types.BLOB);
                } else {
                    s.setNull(3, Types.BLOB);
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
                if (e.getErrorCode() != 23505)
                    throw new BlockStoreException(e);
                
                // There is probably an update-or-insert statement, but it wasn't obvious from the docs
                PreparedStatement s =
                        conn.get().prepareStatement("UPDATE undoableBlocks SET txOutChanges=?, transactions=?"
                                + " WHERE hash = ?");
                s.setBytes(3, hashBytes);
                if (transactions == null) {
                    s.setBytes(1, txOutChanges);
                    s.setNull(2, Types.BLOB);
                } else {
                    s.setNull(1, Types.BLOB);
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
                .prepareStatement("SELECT chainWork, height, header, wasUndoable FROM headers WHERE hash = ?");
            // We skip the first 4 bytes because (on prodnet) the minimum target has 4 0-bytes
            byte[] hashBytes = new byte[28];
            System.arraycopy(hash.getBytes(), 3, hashBytes, 0, 28);
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
            Block b = new Block(params, results.getBytes(3));
            b.verifyHeader();
            StoredBlock stored = new StoredBlock(b, chainWork, height);
            return stored;
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        } catch (ProtocolException e) {
            // Corrupted database.
            throw new BlockStoreException(e);
        } catch (VerificationException e) {
            // Should not be able to happen unless the database contains bad
            // blocks.
            throw new BlockStoreException(e);
        } finally {
            if (s != null)
                try {
                    s.close();
                } catch (SQLException e) { throw new BlockStoreException("Failed to close PreparedStatement"); }
        }
    }
    
    public StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        return get(hash, false);
    }
    
    public StoredBlock getOnceUndoableStoredBlock(Sha256Hash hash) throws BlockStoreException {
        return get(hash, true);
    }
    
    public StoredUndoableBlock getUndoBlock(Sha256Hash hash) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get()
                .prepareStatement("SELECT txOutChanges, transactions FROM undoableBlocks WHERE hash = ?");
            // We skip the first 4 bytes because (on prodnet) the minimum target has 4 0-bytes
            byte[] hashBytes = new byte[28];
            System.arraycopy(hash.getBytes(), 3, hashBytes, 0, 28);
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
                int offset = 0;
                int numTxn = ((transactions[offset++] & 0xFF) << 0) |
                             ((transactions[offset++] & 0xFF) << 8) |
                             ((transactions[offset++] & 0xFF) << 16) |
                             ((transactions[offset++] & 0xFF) << 24);
                List<Transaction> transactionList = new LinkedList<Transaction>();
                for (int i = 0; i < numTxn; i++) {
                    Transaction tx = new Transaction(params, transactions, offset);
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
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        } catch (NullPointerException e) {
            // Corrupted database.
            throw new BlockStoreException(e);
        } catch (ClassCastException e) {
            // Corrupted database.
            throw new BlockStoreException(e);
        } catch (ProtocolException e) {
            // Corrupted database.
            throw new BlockStoreException(e);
        } catch (IOException e) {
            // Corrupted database.
            throw new BlockStoreException(e);
        } finally {
            if (s != null)
                try {
                    s.close();
                } catch (SQLException e) { throw new BlockStoreException("Failed to close PreparedStatement"); }
        }
    }

    public StoredBlock getChainHead() throws BlockStoreException {
        return chainHeadBlock;
    }

    public void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        Sha256Hash hash = chainHead.getHeader().getHash();
        this.chainHeadHash = hash;
        this.chainHeadBlock = chainHead;
        maybeConnect();
        try {
            PreparedStatement s = conn.get()
                .prepareStatement("UPDATE settings SET value = ? WHERE name = ?");
            s.setString(2, CHAIN_HEAD_SETTING);
            s.setBytes(1, hash.getBytes());
            s.executeUpdate();
            s.close();
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
    }
    
    public StoredBlock getVerifiedChainHead() throws BlockStoreException {
        return verifiedChainHeadBlock;
    }

    public void setVerifiedChainHead(StoredBlock chainHead) throws BlockStoreException {
        Sha256Hash hash = chainHead.getHeader().getHash();
        this.verifiedChainHeadHash = hash;
        this.verifiedChainHeadBlock = chainHead;
        maybeConnect();
        try {
            PreparedStatement s = conn.get()
                .prepareStatement("UPDATE settings SET value = ? WHERE name = ?");
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
                .prepareStatement("DELETE FROM undoableBlocks WHERE height <= ?");
            s.setInt(1, height);
            s.executeUpdate();
            s.close();
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        }
    }

    public StoredTransactionOutput getTransactionOutput(Sha256Hash hash, long index) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get()
                .prepareStatement("SELECT openOutputsIndex.height, openOutputs.value, openOutputs.scriptBytes " +
                		"FROM openOutputsIndex NATURAL JOIN openOutputs " +
                		"WHERE openOutputsIndex.hash = ? AND openOutputs.index = ?");
            s.setBytes(1, hash.getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int)index);
            ResultSet results = s.executeQuery();
            if (!results.next()) {
                return null;
            }
            // Parse it.
            int height = results.getInt(1);
            BigInteger value = new BigInteger(results.getBytes(2));
            // Tell the StoredTransactionOutput that we are a coinbase, as that is encoded in height
            StoredTransactionOutput txout = new StoredTransactionOutput(hash, index, value, height, true, results.getBytes(3));
            return txout;
        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        } finally {
            if (s != null)
                try {
                    s.close();
                } catch (SQLException e) { throw new BlockStoreException("Failed to close PreparedStatement"); }
        }
    }

    public void addUnspentTransactionOutput(StoredTransactionOutput out) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            try {
                s = conn.get().prepareStatement("INSERT INTO openOutputsIndex(hash, height)"
                        + " VALUES(?, ?)");
                s.setBytes(1, out.getHash().getBytes());
                s.setInt(2, out.getHeight());
                s.executeUpdate();
            } catch (SQLException e) {
                if (e.getErrorCode() != 23505)
                    throw e;
            } finally {
                if (s != null)
                    s.close();
            }
            
            s = conn.get().prepareStatement("INSERT INTO openOutputs (id, index, value, scriptBytes) " +
            		"VALUES ((SELECT id FROM openOutputsIndex WHERE hash = ?), " +
            		"?, ?, ?)");
            s.setBytes(1, out.getHash().getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int)out.getIndex());
            s.setBytes(3, out.getValue().toByteArray());
            s.setBytes(4, out.getScriptBytes());
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            if (e.getErrorCode() != 23505)
                throw new BlockStoreException(e);
        } finally {
            if (s != null)
                try {
                    s.close();
                } catch (SQLException e) { throw new BlockStoreException(e); }
        }
    }

    public void removeUnspentTransactionOutput(StoredTransactionOutput out) throws BlockStoreException {
        maybeConnect();
        // TODO: This should only need one query (maybe a stored procedure)
        if (getTransactionOutput(out.getHash(), out.getIndex()) == null)
            throw new BlockStoreException("Tried to remove a StoredTransactionOutput from H2FullPrunedBlockStore that it didn't have!");
        try {
            PreparedStatement s = conn.get()
                .prepareStatement("DELETE FROM openOutputs " +
                		"WHERE id = (SELECT id FROM openOutputsIndex WHERE hash = ?) AND index = ?");
            s.setBytes(1, out.getHash().getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int)out.getIndex());
            s.executeUpdate();
            s.close();
            
            // This is quite an ugly query, is there no better way?
            s = conn.get().prepareStatement("DELETE FROM openOutputsIndex " +
                            "WHERE hash = ? AND 1 = (CASE WHEN ((SELECT COUNT(*) FROM openOutputs WHERE id =" +
                            "(SELECT id FROM openOutputsIndex WHERE hash = ?)) = 0) THEN 1 ELSE 0 END)");
            s.setBytes(1, out.getHash().getBytes());
            s.setBytes(2, out.getHash().getBytes());
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    public void beginDatabaseBatchWrite() throws BlockStoreException {
        maybeConnect();
        try {
            conn.get().setAutoCommit(false);
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    public void commitDatabaseBatchWrite() throws BlockStoreException {
        maybeConnect();
        try {
            conn.get().commit();
            conn.get().setAutoCommit(true);
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    public void abortDatabaseBatchWrite() throws BlockStoreException {
        maybeConnect();
        try {
            conn.get().rollback();
            conn.get().setAutoCommit(true);
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

    public boolean hasUnspentOutputs(Sha256Hash hash, int numOutputs) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get()
                .prepareStatement("SELECT COUNT(*) FROM openOutputsIndex " +
                        "WHERE hash = ?");
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
            if (s != null)
                try {
                    s.close();
                } catch (SQLException e) { throw new BlockStoreException("Failed to close PreparedStatement"); }
        }
    }
}