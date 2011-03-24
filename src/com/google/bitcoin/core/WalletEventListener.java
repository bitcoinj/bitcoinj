package com.google.bitcoin.core;

import java.math.BigInteger;

/**
 * Implementing a subclass WalletEventListener allows you to learn when the contents of the wallet changes due to
 * receiving money or a block chain re-organize. Methods are called with the event listener object locked so your
 * implementation does not have to be thread safe. The default method implementations do nothing.
 */
public abstract class WalletEventListener {
    /**
     * This is called on a Peer thread when a block is received that sends some coins to you. Note that this will
     * also be called when downloading the block chain as the wallet balance catches up so if you don't want that
     * register the event listener after the chain is downloaded. It's safe to use methods of wallet during the
     * execution of this callback.
     *
     * @param wallet The wallet object that received the coins/
     * @param tx The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance Current balance of the wallet.
     */
    public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
    }

    /**
     * This is called on a Peer thread when a block is received that triggers a block chain re-organization.<p>
     *
     * A re-organize means that the consensus (chain) of the network has diverged and now changed from what we
     * believed it was previously. Usually this won't matter because the new consensus will include all our old
     * transactions assuming we are playing by the rules. However it's theoretically possible for our balance to
     * change in arbitrary ways, most likely, we could lose some money we thought we had.<p>
     *
     * It is safe to use methods of wallet whilst inside this callback.
     *
     * TODO: Finish this interface.
     */
    public void onReorganize() {
    }
}
