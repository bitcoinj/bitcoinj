package com.google.bitcoin.core;

import java.math.BigInteger;

/**
 * Implementing WalletEventListener allows you to learn when a wallets balance has changed.
 */
public interface WalletEventListener {
    /**
     * This is called on a Peer thread when a block is received that sends some coins to you. Note that this will
     * also be called when downloading the block chain as the wallet balance catches up,
     * so if you don't want that register the event listener after the chain is downloaded. It's safe to use methods
     * of wallet during the execution of this callback.
     *
     * @param wallet The wallet object that received the coins/
     * @param tx The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance Current balance of the wallet.
     */
    public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance);
}
