package org.bitcoinj.core;

import javax.annotation.Nullable;

/**
 * The Context object holds various objects that are scoped to a specific instantiation of bitcoinj for a specific
 * network. You can get an instance of this class through {@link PeerGroup#getContext()}. At the momemnt it
 * only contains a {@link org.bitcoinj.core.TxConfidenceTable} but in future it will likely contain file paths and
 * other global configuration of use.
 */
public class Context {
    protected TxConfidenceTable confidenceTable;
    private AbstractBlockChain chain;

    // The only reason this constructor is not protected is so TestWithNetworkConections can use it.
    public Context(@Nullable AbstractBlockChain chain) {
        this.chain = chain;
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

    /**
     * Returns the BlockChain associated with this Context, or null.
     */
    public AbstractBlockChain getBlockChain() {
        return chain;
    }
}
