/*
 * Copyright 2014 BitPOS Pty Ltd.
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
import com.google.bitcoin.script.Script;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.sql.*;
import java.util.*;

/**
 * <p>A full pruned block store using the Postgres database engine. As an added bonus an address index is calculated,
 * so you can use {@link #calculateBalanceForAddress(com.google.bitcoin.core.Address)} to quickly look up
 * the quantity of bitcoins controlled by that address.</p>
 */
public class PostgresFullPrunedBlockStore implements FullPrunedBlockStore {
    private static final Logger log = LoggerFactory.getLogger(PostgresFullPrunedBlockStore.class);
    private static final String POSTGRES_DUPLICATE_KEY_ERROR_CODE = "23505";

    private Sha256Hash chainHeadHash;
    private StoredBlock chainHeadBlock;
    private Sha256Hash verifiedChainHeadHash;
    private StoredBlock verifiedChainHeadBlock;
    private NetworkParameters params;
    private ThreadLocal<Connection> conn;
    private List<Connection> allConnections;
    private String connectionURL;
    private int fullStoreDepth;
    private String username;
    private String password;

    private static final String driver = "org.postgresql.Driver";
    private static final String CREATE_SETTINGS_TABLE = "CREATE TABLE settings (\n" +
            "    name character varying(32) NOT NULL,\n" +
            "    value bytea\n" +
            ");";
    private static final String CHAIN_HEAD_SETTING = "chainhead";
    private static final String VERIFIED_CHAIN_HEAD_SETTING = "verifiedchainhead";
    private static final String VERSION_SETTING = "version";

    private static final String CREATE_HEADERS_TABLE = "CREATE TABLE headers (" +
            "    hash bytea NOT NULL," +
            "    chainwork bytea NOT NULL," +
            "    height integer NOT NULL," +
            "    header bytea NOT NULL," +
            "    wasundoable boolean NOT NULL" +
            ");";

    private static final String CREATE_UNDOABLE_TABLE = "CREATE TABLE undoableblocks (" +
            "    hash bytea NOT NULL," +
            "    height integer NOT NULL," +
            "    txoutchanges bytea," +
            "    transactions bytea" +
            ");";
    private static final String CREATE_OPEN_OUTPUT_TABLE = "CREATE TABLE openoutputs (" +
            "    hash bytea NOT NULL," +
            "    index integer NOT NULL," +
            "    height integer NOT NULL," +
            "    value bytea NOT NULL," +
            "    scriptbytes bytea NOT NULL," +
            "    toaddress character varying(35)," +
            "    addresstargetable integer" +
            ");";

    private static final String CREATE_UNDOABLE_TABLE_INDEX = "CREATE INDEX heightIndex ON undoableBlocks (height)";

    // Some indexes to speed up inserts
    private static final String CREATE_HEADERS_HASH_INDEX = "CREATE INDEX headershashindex ON headers USING btree (hash);";
    private static final String CREATE_OUTPUTS_ADDRESS_INDEX = "CREATE INDEX idx_address ON openoutputs USING btree (hash, index, height, toaddress);";
    private static final String CREATE_OUTPUT_ADDRESS_TYPE_INDEX = "CREATE INDEX idx_addresstargetable ON openoutputs USING btree (addresstargetable);";
    private static final String CREATE_OUTPUTS_HASH_INDEX = "CREATE INDEX openoutputshash ON openoutputs USING btree (hash);";
    private static final String CREATE_OUTPUTS_HASH_INDEX_INDEX = "CREATE INDEX openoutputshashindex ON openoutputs USING btree (hash, index);";
    private static final String CREATE_UNDOABLE_HASH_INDEX = "CREATE INDEX undoableblockshashindex ON undoableblocks USING btree (hash);";


    /**
     * Creates a new PostgresFullPrunedBlockStore.
     *
     * @param params A copy of the NetworkParameters used
     * @param fullStoreDepth The number of blocks of history stored in full (something like 1000 is pretty safe)
     * @param hostname The hostname of the database to connect to
     * @param dbName The database to connect to
     * @param username The database username
     * @param password The password to the database
     * @throws BlockStoreException if the database fails to open for any reason
     */
    public PostgresFullPrunedBlockStore(NetworkParameters params, int fullStoreDepth, String hostname, String dbName,
                                        String username, String password) throws BlockStoreException {
        this.params = params;
        this.fullStoreDepth = fullStoreDepth;
        connectionURL = "jdbc:postgresql://" + hostname + "/" + dbName;

        this.username = username;
        this.password = password;

        conn = new ThreadLocal<Connection>();
        allConnections = new LinkedList<Connection>();

        try {
            Class.forName(driver);
            log.info(driver + " loaded. ");
        } catch (java.lang.ClassNotFoundException e) {
            log.error("check CLASSPATH for Postgres jar ", e);
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



    private synchronized void maybeConnect() throws BlockStoreException {
        try {
            if (conn.get() != null)
                return;

            Properties props = new Properties();
            props.setProperty("user", this.username);
            props.setProperty("password", this.password);

            conn.set(DriverManager.getConnection(connectionURL, props));

            Connection connection = conn.get();
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
            s.execute("DROP TABLE settings");
            s.execute("DROP TABLE headers");
            s.execute("DROP TABLE undoableBlocks");
            s.execute("DROP TABLE openOutputs");
            s.close();
            createTables();
            initFromDatabase();
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void createTables() throws SQLException, BlockStoreException {
        Statement s = conn.get().createStatement();
        if (log.isDebugEnabled())
            log.debug("PostgresFullPrunedBlockStore : CREATE headers table");
        s.executeUpdate(CREATE_HEADERS_TABLE);

        if (log.isDebugEnabled())
            log.debug("PostgresFullPrunedBlockStore : CREATE settings table");
        s.executeUpdate(CREATE_SETTINGS_TABLE);

        if (log.isDebugEnabled())
            log.debug("PostgresFullPrunedBlockStore : CREATE undoable block table");
        s.executeUpdate(CREATE_UNDOABLE_TABLE);

        if (log.isDebugEnabled())
            log.debug("PostgresFullPrunedBlockStore : CREATE undoable block index");
        s.executeUpdate(CREATE_UNDOABLE_TABLE_INDEX);
        if (log.isDebugEnabled())
            log.debug("PostgresFullPrunedBlockStore : CREATE open output table");
        s.executeUpdate(CREATE_OPEN_OUTPUT_TABLE);

        // Create indexes..
        s.executeUpdate(CREATE_HEADERS_HASH_INDEX);
        s.executeUpdate(CREATE_OUTPUT_ADDRESS_TYPE_INDEX);
        s.executeUpdate(CREATE_OUTPUTS_ADDRESS_INDEX);
        s.executeUpdate(CREATE_OUTPUTS_HASH_INDEX);
        s.executeUpdate(CREATE_OUTPUTS_HASH_INDEX_INDEX);
        s.executeUpdate(CREATE_UNDOABLE_HASH_INDEX);


        s.executeUpdate("INSERT INTO settings(name, value) VALUES('" + CHAIN_HEAD_SETTING + "', NULL)");
        s.executeUpdate("INSERT INTO settings(name, value) VALUES('" + VERIFIED_CHAIN_HEAD_SETTING + "', NULL)");
        s.executeUpdate("INSERT INTO settings(name, value) VALUES('" + VERSION_SETTING + "', '03')");
        s.close();
        createNewStore(params);
    }

    private void initFromDatabase() throws SQLException, BlockStoreException {
        Statement s = conn.get().createStatement();
        ResultSet rs;

        rs = s.executeQuery("SELECT value FROM settings WHERE name = '" + CHAIN_HEAD_SETTING + "'");
        if (!rs.next()) {
            throw new BlockStoreException("corrupt Postgres block store - no chain head pointer");
        }
        Sha256Hash hash = new Sha256Hash(rs.getBytes(1));
        rs.close();
        this.chainHeadBlock = get(hash);
        this.chainHeadHash = hash;
        if (this.chainHeadBlock == null) {
            throw new BlockStoreException("corrupt Postgres block store - head block not found");
        }

        rs = s.executeQuery("SELECT value FROM settings WHERE name = '" + VERIFIED_CHAIN_HEAD_SETTING + "'");
        if (!rs.next()) {
            throw new BlockStoreException("corrupt Postgres block store - no verified chain head pointer");
        }
        hash = new Sha256Hash(rs.getBytes(1));
        rs.close();
        s.close();
        this.verifiedChainHeadBlock = get(hash);
        this.verifiedChainHeadHash = hash;
        if (this.verifiedChainHeadBlock == null) {
            throw new BlockStoreException("corrupt Postgres block store - verified head block not found");
        }
    }

    private void createNewStore(NetworkParameters params) throws BlockStoreException {
        try {
            // Set up the genesis block. When we start out fresh, it is by
            // definition the top of the chain.
            StoredBlock storedGenesisHeader = new StoredBlock(params.getGenesisBlock().cloneAsHeader(), params.getGenesisBlock().getWork(), 0);
            // The coinbase in the genesis block is not spendable. This is because of how the reference client inits
            // its database - the genesis transaction isn't actually in the db so its spent flags can never be updated.
            List<Transaction> genesisTransactions = Lists.newLinkedList();
            StoredUndoableBlock storedGenesis = new StoredUndoableBlock(params.getGenesisBlock().getHash(), genesisTransactions);
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
        long scriptSize = 0;
        rs = s.executeQuery("SELECT value, scriptBytes FROM openOutputs");
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
            if  (!(e.getSQLState().equals(POSTGRES_DUPLICATE_KEY_ERROR_CODE)) || !wasUndoable)
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
            if (log.isDebugEnabled())
                log.debug("Looking for undoable block with hash: " + Utils.bytesToHexString(hashBytes));

            PreparedStatement findS = conn.get().prepareStatement("select 1 from undoableBlocks where hash = ?");
            findS.setBytes(1, hashBytes);

            ResultSet rs = findS.executeQuery();
            if (rs.next())
            {
                // We already have this output, update it.
                findS.close();

                // Postgres insert-or-updates are very complex (and finnicky).  This level of transaction isolation
                // seems to work for bitcoinj
                PreparedStatement s =
                        conn.get().prepareStatement("UPDATE undoableBlocks SET txOutChanges=?, transactions=?"
                                + " WHERE hash = ?");
                s.setBytes(3, hashBytes);

                if (log.isDebugEnabled())
                    log.debug("Updating undoable block with hash: " + Utils.bytesToHexString(hashBytes));


                if (transactions == null) {
                    s.setBytes(1, txOutChanges);
                    s.setNull(2, Types.BINARY);
                } else {
                    s.setNull(1, Types.BINARY);
                    s.setBytes(2, transactions);
                }
                s.executeUpdate();
                s.close();

                return;
            }

            PreparedStatement s =
                    conn.get().prepareStatement("INSERT INTO undoableBlocks(hash, height, txOutChanges, transactions)"
                            + " VALUES(?, ?, ?, ?)");
            s.setBytes(1, hashBytes);
            s.setInt(2, height);

            if (log.isDebugEnabled())
                log.debug("Inserting undoable block with hash: " + Utils.bytesToHexString(hashBytes)  + " at height " + height);


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
            if (!e.getSQLState().equals(POSTGRES_DUPLICATE_KEY_ERROR_CODE))
                throw new BlockStoreException(e);
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

            if (log.isDebugEnabled())
                log.debug("Deleting undoable undoable block with height <= " + height);


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
                    .prepareStatement("SELECT height, value, scriptBytes FROM openOutputs " +
                            "WHERE hash = ? AND index = ?");
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

        // Calculate the toAddress (if any)
        String dbAddress = "";
        int type = 0;
        Script  outputScript = null;
        try
        {
            outputScript = new Script(out.getScriptBytes());
        }
        catch (ScriptException e)
        {
            // Unparseable, but this isn't an error - it's an output not containing an address
            log.info("Could not parse script for output: " + out.getHash().toString());
        }
        if (outputScript != null && (outputScript.isSentToAddress()
                || outputScript.isSentToRawPubKey()
                || outputScript.isPayToScriptHash()))
        {
            if (outputScript.isSentToAddress())
            {
                Address targetAddr = new Address(params, outputScript.getPubKeyHash());
                dbAddress = targetAddr.toString();
                type = 1;
            }
            else if (outputScript.isSentToRawPubKey())
            {
                /*
                 *   Note we use the deprecated getFromAddress here.  Coinbase outputs seem to have the target address
                 *   in the pubkey of the script - perhaps we can rename this function?
                 */

                dbAddress = outputScript.getFromAddress(params).toString();
                type = 2;
            } else if (outputScript.isPayToScriptHash())
            {
                dbAddress = Address.fromP2SHHash(params, outputScript.getPubKeyHash()).toString();
                type = 3;
            }
        }

        try {
            s = conn.get().prepareStatement("INSERT INTO openOutputs (hash, index, height, value, scriptBytes, toAddress, addressTargetable) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)");
            s.setBytes(1, out.getHash().getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int)out.getIndex());
            s.setInt(3, out.getHeight());
            s.setBytes(4, out.getValue().toByteArray());
            s.setBytes(5, out.getScriptBytes());
            s.setString(6, dbAddress);
            s.setInt(7, type);
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            if (!(e.getSQLState().equals(POSTGRES_DUPLICATE_KEY_ERROR_CODE)))
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
            throw new BlockStoreException("Tried to remove a StoredTransactionOutput from PostgresFullPrunedBlockStore that it didn't have!");
        try {
            PreparedStatement s = conn.get()
                    .prepareStatement("DELETE FROM openOutputs WHERE hash = ? AND index = ?");
            s.setBytes(1, out.getHash().getBytes());
            // index is actually an unsigned int
            s.setInt(2, (int)out.getIndex());
            s.executeUpdate();
            s.close();
        } catch (SQLException e) {
            throw new BlockStoreException(e);
        }
    }

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

    public boolean hasUnspentOutputs(Sha256Hash hash, int numOutputs) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;
        try {
            s = conn.get()
                    .prepareStatement("SELECT COUNT(*) FROM openOutputs WHERE hash = ?");
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

    /**
     * Calculate the balance for a coinbase, to-address, or p2sh address.
     * @param address The address to calculate the balance of
     * @return The balance of the address supplied.  If the address has not been seen, or there are no outputs open for this
     *         address, the return value is 0
     * @throws BlockStoreException
     */
    public BigInteger calculateBalanceForAddress(Address address) throws BlockStoreException {
        maybeConnect();
        PreparedStatement s = null;


        try {
            s = conn.get().prepareStatement("select sum(('x'||lpad(substr(value::text, 3, 50),16,'0'))::bit(64)::bigint) "
                    + "from openoutputs where toaddress = ?");
            s.setString(1, address.toString());
            ResultSet rs = s.executeQuery();
            if (rs.next()) {
                return BigInteger.valueOf(rs.getLong(1));
            } else {
                throw new BlockStoreException("Failed to execute balance lookup");
            }

        } catch (SQLException ex) {
            throw new BlockStoreException(ex);
        } finally {
            if (s != null)
                try {
                    s.close();
                } catch (SQLException e) {
                    throw new BlockStoreException("Could not close statement");
                }
        }
    }


}
