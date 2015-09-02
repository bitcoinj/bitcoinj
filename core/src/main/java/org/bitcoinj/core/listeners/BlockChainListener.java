package org.bitcoinj.core.listeners;

/**
 * Old interface for backwards compatibility. Implement the more specific interfaces instead.
 */
@Deprecated
public interface BlockChainListener extends NewBestBlockListener, TransactionReceivedInBlockListener, ReorganizeListener {
}
