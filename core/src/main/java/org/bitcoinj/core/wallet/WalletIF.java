package org.bitcoinj.core.wallet;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.FilteredBlock;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerFilterProvider;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionBag;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.core.listeners.NewBestBlockListener;
import org.bitcoinj.core.listeners.ReorganizeListener;
import org.bitcoinj.core.listeners.TransactionReceivedInBlockListener;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.listeners.KeyChainEventListener;
import org.bitcoinj.listeners.ScriptsChangeEventListener;
import org.bitcoinj.listeners.WalletCoinsReceivedEventListener;
import org.bitcoinj.listeners.WalletCoinsSentEventListener;
import org.bitcoinj.signers.TransactionSigner;

import javax.annotation.Nullable;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executor;

/**
 *
 */
public interface WalletIF extends PeerFilterProvider, TransactionBag, NewBestBlockListener, TransactionReceivedInBlockListener, KeyBag, ReorganizeListener {
    NetworkParameters getNetworkParameters();

    /**
     * Returns address for a {@link org.bitcoinj.wallet.Wallet#freshKey(KeyChain.KeyPurpose)}
     */
    Address freshAddress(KeyChain.KeyPurpose purpose);

    void receivePending(Transaction tx, @Nullable List<Transaction> dependencies, boolean overrideIsRelevant) throws VerificationException;
    void receivePending(Transaction tx, @Nullable List<Transaction> dependencies) throws VerificationException;
    boolean isPendingTransactionRelevant(Transaction tx) throws ScriptException;

    /** Returns the hash of the last seen best-chain block, or null if the wallet is too old to store this data. */
    @Nullable
    Sha256Hash getLastBlockSeenHash();

    /**
     * Returns the UNIX time in seconds since the epoch extracted from the last best seen block header. This timestamp
     * is <b>not</b> the local time at which the block was first observed by this application but rather what the block
     * (i.e. miner) self declares. It is allowed to have some significant drift from the real time at which the block
     * was found, although most miners do use accurate times. If this wallet is old and does not have a recorded
     * time then this method returns zero.
     */
    long getLastBlockSeenTimeSecs();

    /**
     * Returns a {@link Date} representing the time extracted from the last best seen block header. This timestamp
     * is <b>not</b> the local time at which the block was first observed by this application but rather what the block
     * (i.e. miner) self declares. It is allowed to have some significant drift from the real time at which the block
     * was found, although most miners do use accurate times. If this wallet is old and does not have a recorded
     * time then this method returns null.
     */
    @Nullable
    Date getLastBlockSeenTime();

    /**
     * Returns the height of the last seen best-chain block. Can be 0 if a wallet is brand new or -1 if the wallet
     * is old and doesn't have that data.
     */
    int getLastBlockSeenHeight();

    boolean checkForFilterExhaustion(FilteredBlock block);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
    boolean removeCoinsReceivedEventListener(WalletCoinsReceivedEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
    boolean removeCoinsSentEventListener(WalletCoinsSentEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
    boolean removeKeyChainEventListener(KeyChainEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
    boolean removeScriptsChangeEventListener(ScriptsChangeEventListener listener);

    @Nullable
    Transaction getTransaction(Sha256Hash hash);
    void setTransactionBroadcaster(@Nullable org.bitcoinj.core.TransactionBroadcaster broadcaster);

    void addCoinsReceivedEventListener(WalletCoinsReceivedEventListener listener);

    void addCoinsReceivedEventListener(Executor executor, WalletCoinsReceivedEventListener listener);

    void addCoinsSentEventListener(WalletCoinsSentEventListener listener);

    void addCoinsSentEventListener(Executor executor, WalletCoinsSentEventListener listener);

    void addKeyChainEventListener(KeyChainEventListener listener);

    void addKeyChainEventListener(Executor executor, KeyChainEventListener listener);
    void addScriptsChangeEventListener(ScriptsChangeEventListener listener);
    void addScriptsChangeEventListener(Executor executor, ScriptsChangeEventListener listener);

    /**
     * Enumerates possible resolutions for missing signatures.
     */
    enum MissingSigsMode {
        /** Input script will have OP_0 instead of missing signatures */
        USE_OP_ZERO,
        /**
         * Missing signatures will be replaced by dummy sigs. This is useful when you'd like to know the fee for
         * a transaction without knowing the user's password, as fee depends on size.
         */
        USE_DUMMY_SIG,
        /**
         * If signature is missing, {@link TransactionSigner.MissingSignatureException}
         * will be thrown for P2SH and {@link ECKey.MissingPrivateKeyException} for other tx types.
         */
        THROW
    }
}
