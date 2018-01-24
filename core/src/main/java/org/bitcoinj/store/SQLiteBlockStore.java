package org.bitcoinj.store;

import org.bitcoinj.core.*;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.*;
class SQLiteBlockStore implements BlockStore {

    private StoredBlock chainHead;
    private NetworkParameters params;
    Connection conn;
    public SQLiteBlockStore(NetworkParameters params, String filename) throws ClassNotFoundException {
        Class.forName("org.sqlite.JDBC");
        try {
            conn = DriverManager.getConnection("jdbc:sqlite:"+filename + ".db");
            Statement createTable = conn.createStatement();
            createTable.execute("CREATE TABLE IF NOT EXISTS `blockStore` (`hash`TEXT NOT NULL UNIQUE, `chainwork` REAL NOT NULL, `height` INTEGER NOT NULL, `serialized` TEXT NOT NULL);");
            Block genesisHeader = params.getGenesisBlock().cloneAsHeader();
            StoredBlock storedGenesis = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
            put(storedGenesis);
            setChainHead(storedGenesis);
            this.params = params;
        } catch (BlockStoreException | VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }


    public synchronized final void put(StoredBlock block) throws BlockStoreException {
        if (conn == null) throw new BlockStoreException("Not opened");
        try {
            PreparedStatement addBlock = conn.prepareStatement("INSERT OR IGNORE INTO blockStore VALUES (?,?,?,?)");
            addBlock.setString(1, block.getHeader().getHashAsString());
            addBlock.setLong(2, Integer.parseInt(String.valueOf(block.getChainWork())));
            addBlock.setInt(3, block.getHeight());
            addBlock.setBytes(4, block.getHeader().bitcoinSerialize());

            addBlock.execute();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }


    public synchronized StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        if (conn == null) throw new BlockStoreException("Not opened");
        StoredBlock block = null;

        try {
            PreparedStatement getBlock = conn.prepareStatement("SELECT * FROM blockStore where hash=?");
            getBlock.setString(1, hash.toString());
            ResultSet result = getBlock.executeQuery();
            if (result.next()){
                Block blockHeader= new Block(params, result.getBytes(4));
                block = new StoredBlock(blockHeader, new BigInteger(String.valueOf(result.getLong(2))), result.getInt(3));
            } else {

            }
            getBlock.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return block;
    }


    public StoredBlock getChainHead() throws BlockStoreException {
            if (conn == null) throw new BlockStoreException("Not opened");
            return chainHead;
    }

  
    public final void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        if (conn == null) throw new BlockStoreException("Not opened");
        this.chainHead = chainHead;
    }


    public void close() {
        try {
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public NetworkParameters getParams() {
        return params;
    }
}
