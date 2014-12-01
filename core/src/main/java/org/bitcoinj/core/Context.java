package org.bitcoinj.core;

/**
 * The Context object holds various objects that are relevant to the global state of our
 * view of the Bitcoin network.  You can get an instance of this class
 * through {@link AbstractBlockChain#getContext()}.
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
