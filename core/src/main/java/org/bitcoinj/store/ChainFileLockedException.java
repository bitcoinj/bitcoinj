package org.bitcoinj.store;

/**
 * Thrown by {@link SPVBlockStore} when the process cannot gain exclusive access to the chain file.
 */
public class ChainFileLockedException extends BlockStoreException {
    public ChainFileLockedException(String message) {
        super(message);
    }

    public ChainFileLockedException(Throwable t) {
        super(t);
    }
}
