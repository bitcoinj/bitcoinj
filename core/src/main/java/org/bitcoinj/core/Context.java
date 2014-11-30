package org.bitcoinj.core;

/**
 * The Context object holds various objects that are relevant to the global state of our
 * view of the Bitcoin network.
 */
public class Context {
    protected TxConfidencePool confidencePool;

    protected Context() {
        confidencePool = new TxConfidencePool();
    }

    /**
     * Returns the {@link TxConfidencePool} created by this context. The pool tracks advertised
     * and downloaded transactions so their confidence can be measured as a proportion of how many peers announced it.
     * With an un-tampered with internet connection, the more peers announce a transaction the more confidence you can
     * have that it's really valid.
     */
    public TxConfidencePool getConfidencePool() {
        return confidencePool;
    }
}
