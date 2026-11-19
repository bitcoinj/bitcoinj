package org.bitcoinj.store;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.DatabaseFullPrunedBlockStore;

public class OracleFullPrunedBlockStore extends DatabaseFullPrunedBlockStore {
    private static final String DATABASE_DRIVER_CLASS = "oracle.jdbc.OracleDriver";
    private static final String DATABASE_CONNECTION_URL_PREFIX = "jdbc:oracle:thin:@";
    
    // create table SQL
    private static final String CREATE_SETTINGS_TABLE = "CREATE TABLE settings (\n" +
            "    name VARCHAR2(32) NOT NULL,\n" +
            "    value BLOB,\n" +
            "    CONSTRAINT setting_pk PRIMARY KEY (name) \n" +
            ")\n";

    private static final String CREATE_HEADERS_TABLE = "CREATE TABLE headers (\n" +
            "    hash RAW(28) NOT NULL,\n" +
            "    chainwork RAW(12) NOT NULL,\n" +
            "    height NUMBER(10,0) NOT NULL,\n" +
            "    header RAW(80) NOT NULL,\n" +
            "    wasundoable NUMBER(3,0) NOT NULL,\n" +
            "    CONSTRAINT headers_pk PRIMARY KEY (hash) \n" +
            ")\n";

    private static final String CREATE_UNDOABLE_TABLE = "CREATE TABLE undoableblocks (\n" +
            "    hash RAW(28) NOT NULL,\n" +
            "    height NUMBER(10, 0) NOT NULL,\n" +
            "    txoutchanges BLOB,\n" +
            "    transactions BLOB,\n" +
            "    CONSTRAINT undoableblocks_pk PRIMARY KEY (hash) \n" +
            ")\n";

    private static final String CREATE_OPEN_OUTPUT_TABLE = "CREATE TABLE openoutputs (\n" +
            "    hash RAW(32) NOT NULL,\n" +
            "    \"INDEX\" NUMBER(10, 0) NOT NULL,\n" +
            "    height NUMBER(10, 0) NOT NULL,\n" +
            "    value NUMBER(19, 0) NOT NULL,\n" +
            "    scriptbytes BLOB NOT NULL,\n" +
            "    toaddress VARCHAR2(35),\n" +
            "    addresstargetable NUMBER(3, 0),\n" +
            "    coinbase NUMBER(3,0),\n" +
            "    CONSTRAINT openoutputs_pk PRIMARY KEY (hash, \"INDEX\") \n" +
            ")\n";
    
    // Some indexes to speed up inserts
    private static final String CREATE_OUTPUTS_ADDRESS_MULTI_INDEX              = "CREATE INDEX openoutputsi2 ON openoutputs (hash, \"INDEX\", height, toaddress)";
    private static final String CREATE_OUTPUTS_TOADDRESS_INDEX                  = "CREATE INDEX openoutputsi3 ON openoutputs (toaddress)";
    private static final String CREATE_OUTPUTS_ADDRESSTARGETABLE_INDEX          = "CREATE INDEX openoutputsi4 ON openoutputs (addresstargetable)";
    private static final String CREATE_OUTPUTS_HASH_INDEX                       = "CREATE INDEX openoutputsi5 ON openoutputs (hash)";
    private static final String CREATE_UNDOABLE_TABLE_INDEX                     = "CREATE INDEX undoableblocksi2 ON undoableBlocks (height)";

    // SQL involving index column (table openOutputs) overridden as it is a reserved word and must be back quoted in Oracle.
    private static final String SELECT_OPENOUTPUTS_SQL                          = "SELECT height, value, scriptBytes, coinbase, toaddress, addresstargetable FROM openOutputs WHERE hash = ? AND \"INDEX\" = ?";
    private static final String INSERT_OPENOUTPUTS_SQL                          = "INSERT INTO openOutputs (hash, \"INDEX\", height, value, scriptBytes, toAddress, addressTargetable, coinbase) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String DELETE_OPENOUTPUTS_SQL                          = "DELETE FROM openOutputs WHERE hash = ? AND \"INDEX\"= ?";

    private static final String SELECT_TRANSACTION_OUTPUTS_SQL                  = "SELECT hash, value, scriptBytes, height, \"INDEX\", coinbase, toaddress, addresstargetable FROM openOutputs where toaddress = ?";
	private static final String ORACLE_DUPLICATE_KEY_ERROR_CODE = "23000";
    
    /**
     * Creates a new OracleFullPrunedBlockStore.
     *
     * @param params A copy of the NetworkParameters used
     * @param fullStoreDepth The number of blocks of history stored in full (something like 1000 is pretty safe)
     * @param username The database username
     * @param password The password to the database
     * @param tnsAlias The TNS alias for the database
     * @throws BlockStoreException if the database fails to open for any reason
     */
    public OracleFullPrunedBlockStore(NetworkParameters params, int fullStoreDepth, String username, String password, String tnsAlias) throws BlockStoreException {
        super(params, DATABASE_CONNECTION_URL_PREFIX + tnsAlias, fullStoreDepth, username, password, null);
    }
    
	@Override
	protected String getDatabaseDriverClass() {
		return DATABASE_DRIVER_CLASS;
	}

	@Override
	protected List<String> getCreateSchemeSQL() {
        // do nothing
        return Collections.emptyList();
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
	protected String getDuplicateKeyErrorCode() {
		return ORACLE_DUPLICATE_KEY_ERROR_CODE;
	}

}
