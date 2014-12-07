package org.bitcoinj.core;

/**
 * The Context object holds various objects that are scoped to a specific instantiation of bitcoinj for a specific
 * network. You can get an instance of this class through {@link AbstractBlockChain#getContext()}. At the momemnt it
 * only contains a {@link org.bitcoinj.core.TxConfidenceTable} but in future it will likely contain file paths and
 * other global configuration of use.
 */
public class Context {
    protected TxConfidenceTable confidenceTable;

    protected Context() {
        confidenceTable = new TxConfidenceTable();
    }

    /**
     * Returns the {@link TxConfidenceTable} created by this context. The pool tracks advertised
     * and downloaded transactions so their confidence can be measured as a proportion of how many peers announced it.
     * With an un-tampered with internet connection, the more peers announce a transaction the more confidence you can
     * have that it's really valid.
     */
    public TxConfidenceTable getConfidenceTable() {
        return confidenceTable;
    }
}
