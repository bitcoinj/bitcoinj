/**
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.core;

import com.google.bitcoin.core.TransactionConfidence.ConfidenceType;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterException;
import com.google.bitcoin.crypto.KeyCrypterScrypt;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.script.ScriptChunk;
import com.google.bitcoin.store.UnreadableWalletException;
import com.google.bitcoin.store.WalletProtobufSerializer;
import com.google.bitcoin.utils.ListenerRegistration;
import com.google.bitcoin.utils.Threading;
import com.google.bitcoin.wallet.*;
import com.google.bitcoin.wallet.WalletTransaction.Pool;
import com.google.common.collect.*;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.bitcoin.core.Utils.bitcoinValueToFriendlyString;
import static com.google.bitcoin.core.Utils.bitcoinValueToPlainString;
import static com.google.common.base.Preconditions.*;

// To do list:
//
// This whole class has evolved over a period of years and needs a ground-up rewrite.
//
// - Take all wallet-relevant data out of Transaction and put it into WalletTransaction. Make Transaction immutable.
// - Only store relevant transaction outputs, don't bother storing the rest of the data.
// - Split block chain and tx output tracking into a superclass that doesn't have any key or spending related code.
// - Simplify how transactions are tracked and stored: in particular, have the wallet maintain positioning information
//   for transactions independent of the transactions themselves, so the timeline can be walked without having to
//   process and sort every single transaction.
// - Decompose the class where possible: break logic out into classes that can be customized/replaced by the user.
//     - [Auto]saving to a backing store
//     - Key management
//     - just generally make Wallet smaller and easier to work with
// - Make clearing of transactions able to only rewind the wallet a certain distance instead of all blocks.
// - Make it scale:
//     - eliminate all the algorithms with quadratic complexity (or worse)
//     - don't require everything to be held in RAM at once
//     - consider allowing eviction of no longer re-orgable transactions or keys that were used up

/**
 * <p>A Wallet stores keys and a record of transactions that send and receive value from those keys. Using these,
 * it is able to create new transactions that spend the recorded transactions, and this is the fundamental operation
 * of the Bitcoin protocol.</p>
 *
 * <p>To learn more about this class, read <b><a href="http://code.google.com/p/bitcoinj/wiki/WorkingWithTheWallet">
 *     working with the wallet.</a></b></p>
 *
 * <p>To fill up a Wallet with transactions, you need to use it in combination with a {@link BlockChain} and various
 * other objects, see the <a href="http://code.google.com/p/bitcoinj/wiki/GettingStarted">Getting started</a> tutorial
 * on the website to learn more about how to set everything up.</p>
 *
 * <p>Wallets can be serialized using either Java serialization - this is not compatible across versions of bitcoinj,
 * or protocol buffer serialization. You need to save the wallet whenever it changes, there is an auto-save feature
 * that simplifies this for you although you're still responsible for manually triggering a save when your app is about
 * to quit because the auto-save feature waits a moment before actually committing to disk to avoid IO thrashing when
 * the wallet is changing very fast (eg due to a block chain sync). See
 * {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, com.google.bitcoin.wallet.WalletFiles.Listener)}
 * for more information about this.</p>
 */
public class Wallet implements Serializable, BlockChainListener, PeerFilterProvider {
    private static final Logger log = LoggerFactory.getLogger(Wallet.class);
    private static final long serialVersionUID = 2L;
    private static final int MINIMUM_BLOOM_DATA_LENGTH = 8;

    protected final ReentrantLock lock = Threading.lock("wallet");

    // The various pools below give quick access to wallet-relevant transactions by the state they're in:
    //
    // Pending:  Transactions that didn't make it into the best chain yet. Pending transactions can be killed if a
    //           double-spend against them appears in the best chain, in which case they move to the dead pool.
    //           If a double-spend appears in the pending state as well, currently we just ignore the second
    //           and wait for the miners to resolve the race.
    // Unspent:  Transactions that appeared in the best chain and have outputs we can spend. Note that we store the
    //           entire transaction in memory even though for spending purposes we only really need the outputs, the
    //           reason being that this simplifies handling of re-orgs. It would be worth fixing this in future.
    // Spent:    Transactions that appeared in the best chain but don't have any spendable outputs. They're stored here
    //           for history browsing/auditing reasons only and in future will probably be flushed out to some other
    //           kind of cold storage or just removed.
    // Dead:     Transactions that we believe will never confirm get moved here, out of pending. Note that the Satoshi
    //           client has no notion of dead-ness: the assumption is that double spends won't happen so there's no
    //           need to notify the user about them. We take a more pessimistic approach and try to track the fact that
    //           transactions have been double spent so applications can do something intelligent (cancel orders, show
    //           to the user in the UI, etc). A transaction can leave dead and move into spent/unspent if there is a
    //           re-org to a chain that doesn't include the double spend.

    final Map<Sha256Hash, Transaction> pending;
    final Map<Sha256Hash, Transaction> unspent;
    final Map<Sha256Hash, Transaction> spent;
    final Map<Sha256Hash, Transaction> dead;

    // All transactions together.
    final Map<Sha256Hash, Transaction> transactions;

    // Transactions that were dropped by the risk analysis system. These are not in any pools and not serialized
    // to disk. We have to keep them around because if we ignore a tx because we think it will never confirm, but
    // then it actually does confirm and does so within the same network session, remote peers will not resend us
    // the tx data along with the Bloom filtered block, as they know we already received it once before
    // (so it would be wasteful to repeat). Thus we keep them around here for a while. If we drop our network
    // connections then the remote peers will forget that we were sent the tx data previously and send it again
    // when relaying a filtered merkleblock.
    private final LinkedHashMap<Sha256Hash, Transaction> riskDropped = new LinkedHashMap<Sha256Hash, Transaction>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Sha256Hash, Transaction> eldest) {
            return size() > 1000;
        }
    };

    // A list of public/private EC keys owned by this user. Access it using addKey[s], hasKey[s] and findPubKeyFromHash.
    private ArrayList<ECKey> keychain;

    // A list of scripts watched by this wallet.
    private Set<Script> watchedScripts;

    private final NetworkParameters params;

    @Nullable private Sha256Hash lastBlockSeenHash;
    private int lastBlockSeenHeight;
    private long lastBlockSeenTimeSecs;

    private transient CopyOnWriteArrayList<ListenerRegistration<WalletEventListener>> eventListeners;

    // A listener that relays confidence changes from the transaction confidence object to the wallet event listener,
    // as a convenience to API users so they don't have to register on every transaction themselves.
    private transient TransactionConfidence.Listener txConfidenceListener;

    // If a TX hash appears in this set then notifyNewBestBlock will ignore it, as its confidence was already set up
    // in receive() via Transaction.setBlockAppearance(). As the BlockChain always calls notifyNewBestBlock even if
    // it sent transactions to the wallet, without this we'd double count.
    private transient HashSet<Sha256Hash> ignoreNextNewBlock;
    // Whether or not to ignore nLockTime > 0 transactions that are received to the mempool.
    private boolean acceptRiskyTransactions;

    // Stuff for notifying transaction objects that we changed their confidences. The purpose of this is to avoid
    // spuriously sending lots of repeated notifications to listeners that API users aren't really interested in as a
    // side effect of how the code is written (e.g. during re-orgs confidence data gets adjusted multiple times).
    private int onWalletChangedSuppressions;
    private boolean insideReorg;
    private Map<Transaction, TransactionConfidence.Listener.ChangeReason> confidenceChanged;
    private volatile WalletFiles vFileManager;
    // Object that is used to send transactions asynchronously when the wallet requires it.
    private volatile TransactionBroadcaster vTransactionBroadcaster;
    // UNIX time in seconds. Money controlled by keys created before this time will be automatically respent to a key
    // that was created after it. Useful when you believe some keys have been compromised.
    private volatile long vKeyRotationTimestamp;
    private volatile boolean vKeyRotationEnabled;

    private transient CoinSelector coinSelector = new DefaultCoinSelector();

    // The keyCrypter for the wallet. This specifies the algorithm used for encrypting and decrypting the private keys.
    private KeyCrypter keyCrypter;
    // The wallet version. This is an int that can be used to track breaking changes in the wallet format.
    // You can also use it to detect wallets that come from the future (ie they contain features you
    // do not know how to deal with).
    private int version;
    // User-provided description that may help people keep track of what a wallet is for.
    private String description;
    // Stores objects that know how to serialize/unserialize themselves to byte streams and whether they're mandatory
    // or not. The string key comes from the extension itself.
    private final HashMap<String, WalletExtension> extensions;
    // Object that performs risk analysis of received pending transactions. We might reject transactions that seem like
    // a high risk of being a double spending attack.
    private RiskAnalysis.Analyzer riskAnalyzer = DefaultRiskAnalysis.FACTORY;

    /**
     * Creates a new, empty wallet with no keys and no transactions. If you want to restore a wallet from disk instead,
     * see loadFromFile.
     */
    public Wallet(NetworkParameters params) {
        this.params = checkNotNull(params);
        keychain = new ArrayList<ECKey>();
        watchedScripts = Sets.newHashSet();
        unspent = new HashMap<Sha256Hash, Transaction>();
        spent = new HashMap<Sha256Hash, Transaction>();
        pending = new HashMap<Sha256Hash, Transaction>();
        dead = new HashMap<Sha256Hash, Transaction>();
        transactions = new HashMap<Sha256Hash, Transaction>();
        eventListeners = new CopyOnWriteArrayList<ListenerRegistration<WalletEventListener>>();
        extensions = new HashMap<String, WalletExtension>();
        confidenceChanged = new HashMap<Transaction, TransactionConfidence.Listener.ChangeReason>();
        createTransientState();
    }

    /**
     * Create a wallet with a keyCrypter to use in encrypting and decrypting keys.
     */
    public Wallet(NetworkParameters params, KeyCrypter keyCrypter) {
        this(params);
        this.keyCrypter = checkNotNull(keyCrypter);
    }

    private void createTransientState() {
        ignoreNextNewBlock = new HashSet<Sha256Hash>();
        txConfidenceListener = new TransactionConfidence.Listener() {
            @Override
            public void onConfidenceChanged(Transaction tx, TransactionConfidence.Listener.ChangeReason reason) {
                // This will run on the user code thread so we shouldn't do anything too complicated here.
                // We only want to queue a wallet changed event and auto-save if the number of peers announcing
                // the transaction has changed, as that confidence change is made by the networking code which
                // doesn't necessarily know at that point which wallets contain which transactions, so it's up
                // to us to listen for that. Other types of confidence changes (type, etc) are triggered by us,
                // so we'll queue up a wallet change event in other parts of the code.
                if (reason == ChangeReason.SEEN_PEERS) {
                    lock.lock();
                    try {
                        checkBalanceFuturesLocked(null);
                        queueOnTransactionConfidenceChanged(tx);
                        maybeQueueOnWalletChanged();
                    } finally {
                        lock.unlock();
                    }
                }
            }
        };
        acceptRiskyTransactions = false;
    }

    public NetworkParameters getNetworkParameters() {
        return params;
    }

    /**
     * Returns a snapshot of the keychain. This view is not live.
     */
    public List<ECKey> getKeys() {
        lock.lock();
        try {
            return new ArrayList<ECKey>(keychain);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a snapshot of the watched scripts. This view is not live.
     */
    public List<Script> getWatchedScripts() {
        lock.lock();
        try {
            return new ArrayList<Script>(watchedScripts);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Removes the given key from the keychain. Be very careful with this - losing a private key <b>destroys the
     * money associated with it</b>.
     * @return Whether the key was removed or not.
     */
    public boolean removeKey(ECKey key) {
        lock.lock();
        try {
            return keychain.remove(key);
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * Returns the number of keys in the keychain.
     */
    public int getKeychainSize() {
        lock.lock();
        try {
            return keychain.size();
        } finally {
            lock.unlock();
        }
    }

    /** Saves the wallet first to the given temp file, then renames to the dest file. */
    public void saveToFile(File temp, File destFile) throws IOException {
        FileOutputStream stream = null;
        lock.lock();
        try {
            stream = new FileOutputStream(temp);
            saveToFileStream(stream);
            // Attempt to force the bits to hit the disk. In reality the OS or hard disk itself may still decide
            // to not write through to physical media for at least a few seconds, but this is the best we can do.
            stream.flush();
            stream.getFD().sync();
            stream.close();
            stream = null;
            if (Utils.isWindows()) {
                // Work around an issue on Windows whereby you can't rename over existing files.
                File canonical = destFile.getCanonicalFile();
                if (canonical.exists() && !canonical.delete())
                    throw new IOException("Failed to delete canonical wallet file for replacement with autosave");
                if (temp.renameTo(canonical))
                    return;  // else fall through.
                throw new IOException("Failed to rename " + temp + " to " + canonical);
            } else if (!temp.renameTo(destFile)) {
                throw new IOException("Failed to rename " + temp + " to " + destFile);
            }
        } catch (RuntimeException e) {
            log.error("Failed whilst saving wallet", e);
            throw e;
        } finally {
            lock.unlock();
            if (stream != null) {
                stream.close();
            }
            if (temp.exists()) {
                log.warn("Temp file still exists after failed save.");
            }
        }
    }

    /**
     * Uses protobuf serialization to save the wallet to the given file. To learn more about this file format, see
     * {@link WalletProtobufSerializer}. Writes out first to a temporary file in the same directory and then renames
     * once written.
     */
    public void saveToFile(File f) throws IOException {
        File directory = f.getAbsoluteFile().getParentFile();
        File temp = File.createTempFile("wallet", null, directory);
        saveToFile(temp, f);
    }

    /**
     * <p>Whether or not the wallet will ignore received pending transactions that fail the selected
     * {@link RiskAnalysis}. By default, if a transaction is considered risky then it won't enter the wallet
     * and won't trigger any event listeners. If you set this property to true, then all transactions will
     * be allowed in regardless of risk. Currently, the {@link DefaultRiskAnalysis} checks for non-finality of
     * transactions. You should not encounter these outside of special protocols.</p>
     *
     * <p>Note that this property is not serialized. You have to set it each time a Wallet object is constructed,
     * even if it's loaded from a protocol buffer.</p>
     */
    public void setAcceptRiskyTransactions(boolean acceptRiskyTransactions) {
        lock.lock();
        try {
            this.acceptRiskyTransactions = acceptRiskyTransactions;
        } finally {
            lock.unlock();
        }
    }

    /**
     * See {@link Wallet#setAcceptRiskyTransactions(boolean)} for an explanation of this property.
     */
    public boolean doesAcceptRiskyTransactions() {
        lock.lock();
        try {
            return acceptRiskyTransactions;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets the {@link RiskAnalysis} implementation to use for deciding whether received pending transactions are risky
     * or not. If the analyzer says a transaction is risky, by default it will be dropped. You can customize this
     * behaviour with {@link #setAcceptRiskyTransactions(boolean)}.
     */
    public void setRiskAnalyzer(RiskAnalysis.Analyzer analyzer) {
        lock.lock();
        try {
            this.riskAnalyzer = checkNotNull(analyzer);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Gets the current {@link RiskAnalysis} implementation. The default is {@link DefaultRiskAnalysis}.
     */
    public RiskAnalysis.Analyzer getRiskAnalyzer() {
        lock.lock();
        try {
            return riskAnalyzer;
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Sets up the wallet to auto-save itself to the given file, using temp files with atomic renames to ensure
     * consistency. After connecting to a file, you no longer need to save the wallet manually, it will do it
     * whenever necessary. Protocol buffer serialization will be used.</p>
     *
     * <p>If delayTime is set, a background thread will be created and the wallet will only be saved to
     * disk every so many time units. If no changes have occurred for the given time period, nothing will be written.
     * In this way disk IO can be rate limited. It's a good idea to set this as otherwise the wallet can change very
     * frequently, eg if there are a lot of transactions in it or during block sync, and there will be a lot of redundant
     * writes. Note that when a new key is added, that always results in an immediate save regardless of
     * delayTime. <b>You should still save the wallet manually when your program is about to shut down as the JVM
     * will not wait for the background thread.</b></p>
     *
     * <p>An event listener can be provided. If a delay >0 was specified, it will be called on a background thread
     * with the wallet locked when an auto-save occurs. If delay is zero or you do something that always triggers
     * an immediate save, like adding a key, the event listener will be invoked on the calling threads.</p>
     *
     * @param f The destination file to save to.
     * @param delayTime How many time units to wait until saving the wallet on a background thread.
     * @param timeUnit the unit of measurement for delayTime.
     * @param eventListener callback to be informed when the auto-save thread does things, or null
     */
    public WalletFiles autosaveToFile(File f, long delayTime, TimeUnit timeUnit,
                                      @Nullable WalletFiles.Listener eventListener) {
        lock.lock();
        try {
            checkState(vFileManager == null, "Already auto saving this wallet.");
            WalletFiles manager = new WalletFiles(this, f, delayTime, timeUnit);
            if (eventListener != null)
                manager.setListener(eventListener);
            vFileManager = manager;
            return manager;
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>
     * Disables auto-saving, after it had been enabled with
     * {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, com.google.bitcoin.wallet.WalletFiles.Listener)}
     * before. This method blocks until finished.
     * </p>
     */
    public void shutdownAutosaveAndWait() {
        lock.lock();
        try {
            WalletFiles files = vFileManager;
            vFileManager = null;
            checkState(files != null, "Auto saving not enabled.");
            files.shutdownAndWait();
        } finally {
            lock.unlock();
        }
    }

    private void saveLater() {
        WalletFiles files = vFileManager;
        if (files != null)
            files.saveLater();
    }

    /** If auto saving is enabled, do an immediate sync write to disk ignoring any delays. */
    private void saveNow() {
        WalletFiles files = vFileManager;
        if (files != null) {
            try {
                files.saveNow();  // This calls back into saveToFile().
            } catch (IOException e) {
                // Can't really do much at this point, just let the API user know.
                log.error("Failed to save wallet to disk!", e);
                Thread.UncaughtExceptionHandler handler = Threading.uncaughtExceptionHandler;
                if (handler != null)
                    handler.uncaughtException(Thread.currentThread(), e);
            }
        }
    }

    /**
     * Uses protobuf serialization to save the wallet to the given file stream. To learn more about this file format, see
     * {@link WalletProtobufSerializer}.
     */
    public void saveToFileStream(OutputStream f) throws IOException {
        lock.lock();
        try {
            new WalletProtobufSerializer().writeWallet(this, f);
        } finally {
            lock.unlock();
        }
    }

    /** Returns the parameters this wallet was created with. */
    public NetworkParameters getParams() {
        return params;
    }

    /**
     * Returns a wallet deserialized from the given file.
     */
    public static Wallet loadFromFile(File f) throws UnreadableWalletException {
        try {
            FileInputStream stream = null;
            try {
                stream = new FileInputStream(f);
                return loadFromFileStream(stream);
            } finally {
                if (stream != null) stream.close();
            }
        } catch (IOException e) {
            throw new UnreadableWalletException("Could not open file", e);
        }
    }
    
    public boolean isConsistent() {
        lock.lock();
        try {
            boolean success = true;
            Set<Transaction> transactions = getTransactions(true);

            Set<Sha256Hash> hashes = new HashSet<Sha256Hash>();
            for (Transaction tx : transactions) {
                hashes.add(tx.getHash());
            }

            int size1 = transactions.size();

            if (size1 != hashes.size()) {
                log.error("Two transactions with same hash");
                success = false;
            }

            int size2 = unspent.size() + spent.size() + pending.size() + dead.size();
            if (size1 != size2) {
                log.error("Inconsistent wallet sizes: {} {}", size1, size2);
                success = false;
            }

            for (Transaction tx : unspent.values()) {
                if (!tx.isConsistent(this, false)) {
                    success = false;
                    log.error("Inconsistent unspent tx {}", tx.getHashAsString());
                }
            }

            for (Transaction tx : spent.values()) {
                if (!tx.isConsistent(this, true)) {
                    success = false;
                    log.error("Inconsistent spent tx {}", tx.getHashAsString());
                }
            }

            if (!success) {
                try {
                    log.error(toString());
                } catch (RuntimeException x) {
                    log.error("Printing inconsistent wallet failed", x);
                }
            }
            return success;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a wallet deserialized from the given input stream.
     */
    public static Wallet loadFromFileStream(InputStream stream) throws UnreadableWalletException {
        Wallet wallet = new WalletProtobufSerializer().readWallet(stream);
        if (!wallet.isConsistent()) {
            log.error("Loaded an inconsistent wallet");
        }
        return wallet;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        createTransientState();
    }
    
    /**
     * Called by the {@link BlockChain} when we receive a new filtered block that contains a transactions previously
     * received by a call to @{link receivePending}.<p>
     *
     * This is necessary for the internal book-keeping Wallet does. When a transaction is received that sends us
     * coins it is added to a pool so we can use it later to create spends. When a transaction is received that
     * consumes outputs they are marked as spent so they won't be used in future.<p>
     *
     * A transaction that spends our own coins can be received either because a spend we created was accepted by the
     * network and thus made it into a block, or because our keys are being shared between multiple instances and
     * some other node spent the coins instead. We still have to know about that to avoid accidentally trying to
     * double spend.<p>
     *
     * A transaction may be received multiple times if is included into blocks in parallel chains. The blockType
     * parameter describes whether the containing block is on the main/best chain or whether it's on a presently
     * inactive side chain. We must still record these transactions and the blocks they appear in because a future
     * block might change which chain is best causing a reorganize. A re-org can totally change our balance!
     */
    public boolean notifyTransactionIsInBlock(Sha256Hash txHash, StoredBlock block,
                                              BlockChain.NewBlockType blockType,
                                              int relativityOffset) throws VerificationException {
        lock.lock();
        try {
            Transaction tx = transactions.get(txHash);
            if (tx == null) {
                tx = riskDropped.get(txHash);
                if (tx != null) {
                    // If this happens our risk analysis is probably wrong and should be improved.
                    log.info("Risk analysis dropped tx {} but was included in block anyway", tx.getHash());
                } else {
                    // False positive that was broadcast to us and ignored by us because it was irrelevant to our keys.
                    return false;
                }
            }
            receive(tx, block, blockType, relativityOffset);
        } finally {
            lock.unlock();
        }
        if (blockType == AbstractBlockChain.NewBlockType.BEST_CHAIN) {
            // If some keys are considered to be bad, possibly move money assigned to them now.
            // This has to run outside the wallet lock as it may trigger broadcasting of new transactions.
            maybeRotateKeys();
        }
        return true;
    }

    /**
     * <p>Called when we have found a transaction (via network broadcast or otherwise) that is relevant to this wallet
     * and want to record it. Note that we <b>cannot verify these transactions at all</b>, they may spend fictional
     * coins or be otherwise invalid. They are useful to inform the user about coins they can expect to receive soon,
     * and if you trust the sender of the transaction you can choose to assume they are in fact valid and will not
     * be double spent as an optimization.</p>
     *
     * <p>This is the same as {@link Wallet#receivePending(Transaction, java.util.List)} but allows you to override the
     * {@link Wallet#isPendingTransactionRelevant(Transaction)} sanity-check to keep track of transactions that are not
     * spendable or spend our coins. This can be useful when you want to keep track of transaction confidence on
     * arbitrary transactions. Note that transactions added in this way will still be relayed to peers and appear in
     * transaction lists like any other pending transaction (even when not relevant).</p>
     */
    public void receivePending(Transaction tx, @Nullable List<Transaction> dependencies, boolean overrideIsRelevant) throws VerificationException {
        // Can run in a peer thread. This method will only be called if a prior call to isPendingTransactionRelevant
        // returned true, so we already know by this point that it sends coins to or from our wallet, or is a double
        // spend against one of our other pending transactions.
        lock.lock();
        try {
            tx.verify();
            // Ignore it if we already know about this transaction. Receiving a pending transaction never moves it
            // between pools.
            EnumSet<Pool> containingPools = getContainingPools(tx);
            if (!containingPools.equals(EnumSet.noneOf(Pool.class))) {
                log.debug("Received tx we already saw in a block or created ourselves: " + tx.getHashAsString());
                return;
            }
            // Repeat the check of relevancy here, even though the caller may have already done so - this is to avoid
            // race conditions where receivePending may be being called in parallel.
            if (!overrideIsRelevant && !isPendingTransactionRelevant(tx))
                return;
            if (isTransactionRisky(tx, dependencies) && !acceptRiskyTransactions) {
                // isTransactionRisky already logged the reason.
                riskDropped.put(tx.getHash(), tx);
                log.warn("There are now {} risk dropped transactions being kept in memory", riskDropped.size());
                return;
            }
            BigInteger valueSentToMe = tx.getValueSentToMe(this);
            BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
            if (log.isInfoEnabled()) {
                log.info(String.format("Received a pending transaction %s that spends %s BTC from our own wallet," +
                        " and sends us %s BTC", tx.getHashAsString(), Utils.bitcoinValueToFriendlyString(valueSentFromMe),
                        Utils.bitcoinValueToFriendlyString(valueSentToMe)));
            }
            if (tx.getConfidence().getSource().equals(TransactionConfidence.Source.UNKNOWN)) {
                log.warn("Wallet received transaction with an unknown source. Consider tagging it!");
            }
            // If this tx spends any of our unspent outputs, mark them as spent now, then add to the pending pool. This
            // ensures that if some other client that has our keys broadcasts a spend we stay in sync. Also updates the
            // timestamp on the transaction and registers/runs event listeners.
            commitTx(tx);
        } finally {
            lock.unlock();
        }
        // maybeRotateKeys() will ignore pending transactions so we don't bother calling it here (see the comments
        // in that function for an explanation of why).
    }

    /**
     * Given a transaction and an optional list of dependencies (recursive/flattened), returns true if the given
     * transaction would be rejected by the analyzer, or false otherwise. The result of this call is independent
     * of the value of {@link #doesAcceptRiskyTransactions()}. Risky transactions yield a logged warning. If you
     * want to know the reason why a transaction is risky, create an instance of the {@link RiskAnalysis} yourself
     * using the factory returned by {@link #getRiskAnalyzer()} and use it directly.
     */
    public boolean isTransactionRisky(Transaction tx, @Nullable List<Transaction> dependencies) {
        lock.lock();
        try {
            if (dependencies == null)
                dependencies = ImmutableList.of();
            RiskAnalysis analysis = riskAnalyzer.create(this, tx, dependencies);
            RiskAnalysis.Result result = analysis.analyze();
            if (result != RiskAnalysis.Result.OK) {
                log.warn("Pending transaction {} was considered risky: {}", tx.getHashAsString(), analysis);
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Called when we have found a transaction (via network broadcast or otherwise) that is relevant to this wallet
     * and want to record it. Note that we <b>cannot verify these transactions at all</b>, they may spend fictional
     * coins or be otherwise invalid. They are useful to inform the user about coins they can expect to receive soon,
     * and if you trust the sender of the transaction you can choose to assume they are in fact valid and will not
     * be double spent as an optimization.</p>
     *
     * <p>Before this method is called, {@link Wallet#isPendingTransactionRelevant(Transaction)} should have been
     * called to decide whether the wallet cares about the transaction - if it does, then this method expects the
     * transaction and any dependencies it has which are still in the memory pool.</p>
     */
    public void receivePending(Transaction tx, @Nullable List<Transaction> dependencies) throws VerificationException {
        receivePending(tx, dependencies, false);
    }

    /**
     * This method is used by a {@link Peer} to find out if a transaction that has been announced is interesting,
     * that is, whether we should bother downloading its dependencies and exploring the transaction to decide how
     * risky it is. If this method returns true then {@link Wallet#receivePending(Transaction, java.util.List)}
     * will soon be called with the transactions dependencies as well.
     */
    public boolean isPendingTransactionRelevant(Transaction tx) throws ScriptException {
        lock.lock();
        try {
            // Ignore it if we already know about this transaction. Receiving a pending transaction never moves it
            // between pools.
            EnumSet<Pool> containingPools = getContainingPools(tx);
            if (!containingPools.equals(EnumSet.noneOf(Pool.class))) {
                log.debug("Received tx we already saw in a block or created ourselves: " + tx.getHashAsString());
                return false;
            }
            // We only care about transactions that:
            //   - Send us coins
            //   - Spend our coins
            if (!isTransactionRelevant(tx)) {
                log.debug("Received tx that isn't relevant to this wallet, discarding.");
                return false;
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Returns true if the given transaction sends coins to any of our keys, or has inputs spending any of our outputs,
     * and if includeDoubleSpending is true, also returns true if tx has inputs that are spending outputs which are
     * not ours but which are spent by pending transactions.</p>
     *
     * <p>Note that if the tx has inputs containing one of our keys, but the connected transaction is not in the wallet,
     * it will not be considered relevant.</p>
     */
    public boolean isTransactionRelevant(Transaction tx) throws ScriptException {
        lock.lock();
        try {
            return tx.getValueSentFromMe(this).compareTo(BigInteger.ZERO) > 0 ||
                   tx.getValueSentToMe(this).compareTo(BigInteger.ZERO) > 0 ||
                   checkForDoubleSpendAgainstPending(tx, false);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Checks if "tx" is spending any inputs of pending transactions. Not a general check, but it can work even if
     * the double spent inputs are not ours. Returns the pending tx that was double spent or null if none found.
     */
    private boolean checkForDoubleSpendAgainstPending(Transaction tx, boolean takeAction) {
        checkState(lock.isHeldByCurrentThread());
        // Compile a set of outpoints that are spent by tx.
        HashSet<TransactionOutPoint> outpoints = new HashSet<TransactionOutPoint>();
        for (TransactionInput input : tx.getInputs()) {
            outpoints.add(input.getOutpoint());
        }
        // Now for each pending transaction, see if it shares any outpoints with this tx.
        LinkedList<Transaction> doubleSpentTxns = Lists.newLinkedList();
        for (Transaction p : pending.values()) {
            for (TransactionInput input : p.getInputs()) {
                // This relies on the fact that TransactionOutPoint equality is defined at the protocol not object
                // level - outpoints from two different inputs that point to the same output compare the same.
                TransactionOutPoint outpoint = input.getOutpoint();
                if (outpoints.contains(outpoint)) {
                    // It does, it's a double spend against the pending pool, which makes it relevant.
                    if (!doubleSpentTxns.isEmpty() && doubleSpentTxns.getLast() == p) continue;
                    doubleSpentTxns.add(p);
                }
            }
        }
        if (takeAction && !doubleSpentTxns.isEmpty()) {
            killTx(tx, doubleSpentTxns);
        }
        return !doubleSpentTxns.isEmpty();
    }

    /**
     * Called by the {@link BlockChain} when we receive a new block that sends coins to one of our addresses or
     * spends coins from one of our addresses (note that a single transaction can do both).<p>
     *
     * This is necessary for the internal book-keeping Wallet does. When a transaction is received that sends us
     * coins it is added to a pool so we can use it later to create spends. When a transaction is received that
     * consumes outputs they are marked as spent so they won't be used in future.<p>
     *
     * A transaction that spends our own coins can be received either because a spend we created was accepted by the
     * network and thus made it into a block, or because our keys are being shared between multiple instances and
     * some other node spent the coins instead. We still have to know about that to avoid accidentally trying to
     * double spend.<p>
     *
     * A transaction may be received multiple times if is included into blocks in parallel chains. The blockType
     * parameter describes whether the containing block is on the main/best chain or whether it's on a presently
     * inactive side chain. We must still record these transactions and the blocks they appear in because a future
     * block might change which chain is best causing a reorganize. A re-org can totally change our balance!
     */
    @Override
    public void receiveFromBlock(Transaction tx, StoredBlock block,
                                 BlockChain.NewBlockType blockType,
                                 int relativityOffset) throws VerificationException {
        lock.lock();
        try {
            receive(tx, block, blockType, relativityOffset);
        } finally {
            lock.unlock();
        }
        if (blockType == AbstractBlockChain.NewBlockType.BEST_CHAIN) {
            // If some keys are considered to be bad, possibly move money assigned to them now.
            // This has to run outside the wallet lock as it may trigger broadcasting of new transactions.
            maybeRotateKeys();
        }
    }

    private void receive(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType,
                         int relativityOffset) throws VerificationException {
        // Runs in a peer thread.
        checkState(lock.isHeldByCurrentThread());
        BigInteger prevBalance = getBalance();
        Sha256Hash txHash = tx.getHash();
        boolean bestChain = blockType == BlockChain.NewBlockType.BEST_CHAIN;
        boolean sideChain = blockType == BlockChain.NewBlockType.SIDE_CHAIN;

        BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
        BigInteger valueSentToMe = tx.getValueSentToMe(this);
        BigInteger valueDifference = valueSentToMe.subtract(valueSentFromMe);

        log.info("Received tx{} for {} BTC: {} [{}] in block {}", sideChain ? " on a side chain" : "",
                bitcoinValueToFriendlyString(valueDifference), tx.getHashAsString(), relativityOffset,
                block != null ? block.getHeader().getHash() : "(unit test)");

        onWalletChangedSuppressions++;

        // If this transaction is already in the wallet we may need to move it into a different pool. At the very
        // least we need to ensure we're manipulating the canonical object rather than a duplicate.
        {
            Transaction tmp = transactions.get(tx.getHash());
            if (tmp != null)
                tx = tmp;
        }

        boolean wasPending = pending.remove(txHash) != null;
        if (wasPending)
            log.info("  <-pending");

        if (bestChain) {
            if (wasPending) {
                // Was pending and is now confirmed. Disconnect the outputs in case we spent any already: they will be
                // re-connected by processTxFromBestChain below.
                for (TransactionOutput output : tx.getOutputs()) {
                    final TransactionInput spentBy = output.getSpentBy();
                    if (spentBy != null) spentBy.disconnect();
                }
            }
            processTxFromBestChain(tx, wasPending);
        } else {
            checkState(sideChain);
            // Transactions that appear in a side chain will have that appearance recorded below - we assume that
            // some miners are also trying to include the transaction into the current best chain too, so let's treat
            // it as pending, except we don't need to do any risk analysis on it.
            if (wasPending) {
                // Just put it back in without touching the connections or confidence.
                addWalletTransaction(Pool.PENDING, tx);
                log.info("  ->pending");
            } else {
                // Ignore the case where a tx appears on a side chain at the same time as the best chain (this is
                // quite normal and expected).
                Sha256Hash hash = tx.getHash();
                if (!unspent.containsKey(hash) && !spent.containsKey(hash)) {
                    // Otherwise put it (possibly back) into pending.
                    // Committing it updates the spent flags and inserts into the pool as well.
                    commitTx(tx);
                }
            }
        }

        if (block != null) {
            // Mark the tx as appearing in this block so we can find it later after a re-org. This also tells the tx
            // confidence object about the block and sets its work done/depth appropriately.
            tx.setBlockAppearance(block, bestChain, relativityOffset);
            if (bestChain) {
                // Don't notify this tx of work done in notifyNewBestBlock which will be called immediately after
                // this method has been called by BlockChain for all relevant transactions. Otherwise we'd double
                // count.
                ignoreNextNewBlock.add(txHash);
            }
        }

        onWalletChangedSuppressions--;

        // Side chains don't affect confidence.
        if (bestChain) {
            // notifyNewBestBlock will be invoked next and will then call maybeQueueOnWalletChanged for us.
            confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.TYPE);
        } else {
            maybeQueueOnWalletChanged();
        }

        // Inform anyone interested that we have received or sent coins but only if:
        //  - This is not due to a re-org.
        //  - The coins appeared on the best chain.
        //  - We did in fact receive some new money.
        //  - We have not already informed the user about the coins when we received the tx broadcast, or for our
        //    own spends. If users want to know when a broadcast tx becomes confirmed, they need to use tx confidence
        //    listeners.
        if (!insideReorg && bestChain) {
            BigInteger newBalance = getBalance();  // This is slow.
            log.info("Balance is now: " + bitcoinValueToFriendlyString(newBalance));
            if (!wasPending) {
                int diff = valueDifference.compareTo(BigInteger.ZERO);
                // We pick one callback based on the value difference, though a tx can of course both send and receive
                // coins from the wallet.
                if (diff > 0) {
                    queueOnCoinsReceived(tx, prevBalance, newBalance);
                } else if (diff < 0) {
                    queueOnCoinsSent(tx, prevBalance, newBalance);
                }
            }
            checkBalanceFuturesLocked(newBalance);
        }

        informConfidenceListenersIfNotReorganizing();
        checkState(isConsistent());
        saveNow();
    }

    private void informConfidenceListenersIfNotReorganizing() {
        if (insideReorg)
            return;
        for (Map.Entry<Transaction, TransactionConfidence.Listener.ChangeReason> entry : confidenceChanged.entrySet()) {
            final Transaction tx = entry.getKey();
            tx.getConfidence().queueListeners(entry.getValue());
            queueOnTransactionConfidenceChanged(tx);
        }
        confidenceChanged.clear();
    }

    /**
     * <p>Called by the {@link BlockChain} when a new block on the best chain is seen, AFTER relevant wallet
     * transactions are extracted and sent to us UNLESS the new block caused a re-org, in which case this will
     * not be called (the {@link Wallet#reorganize(StoredBlock, java.util.List, java.util.List)} method will
     * call this one in that case).</p>
     * <p/>
     * <p>Used to update confidence data in each transaction and last seen block hash. Triggers auto saving.
     * Invokes the onWalletChanged event listener if there were any affected transactions.</p>
     */
    public void notifyNewBestBlock(StoredBlock block) throws VerificationException {
        // Check to see if this block has been seen before.
        Sha256Hash newBlockHash = block.getHeader().getHash();
        if (newBlockHash.equals(getLastBlockSeenHash()))
            return;
        lock.lock();
        try {
            // Store the new block hash.
            setLastBlockSeenHash(newBlockHash);
            setLastBlockSeenHeight(block.getHeight());
            setLastBlockSeenTimeSecs(block.getHeader().getTimeSeconds());
            // TODO: Clarify the code below.
            // Notify all the BUILDING transactions of the new block.
            // This is so that they can update their work done and depth.
            Set<Transaction> transactions = getTransactions(true);
            for (Transaction tx : transactions) {
                if (ignoreNextNewBlock.contains(tx.getHash())) {
                    // tx was already processed in receive() due to it appearing in this block, so we don't want to
                    // notify the tx confidence of work done twice, it'd result in miscounting.
                    ignoreNextNewBlock.remove(tx.getHash());
                } else if (tx.getConfidence().getConfidenceType() == ConfidenceType.BUILDING) {
                    tx.getConfidence().notifyWorkDone(block.getHeader());
                    confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.DEPTH);
                }
            }

            informConfidenceListenersIfNotReorganizing();
            maybeQueueOnWalletChanged();
            // Coalesce writes to avoid throttling on disk access when catching up with the chain.
            saveLater();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Handle when a transaction becomes newly active on the best chain, either due to receiving a new block or a
     * re-org. Places the tx into the right pool, handles coinbase transactions, handles double-spends and so on.
     */
    private void processTxFromBestChain(Transaction tx, boolean forceAddToPool) throws VerificationException {
        checkState(lock.isHeldByCurrentThread());
        checkState(!pending.containsKey(tx.getHash()));

        // This TX may spend our existing outputs even though it was not pending. This can happen in unit
        // tests, if keys are moved between wallets, if we're catching up to the chain given only a set of keys,
        // or if a dead coinbase transaction has moved back onto the main chain.
        boolean isDeadCoinbase = tx.isCoinBase() && dead.containsKey(tx.getHash());
        if (isDeadCoinbase) {
            // There is a dead coinbase tx being received on the best chain. A coinbase tx is made dead when it moves
            // to a side chain but it can be switched back on a reorg and 'resurrected' back to spent or unspent.
            // So take it out of the dead pool.
            log.info("  coinbase tx {} <-dead: confidence {}", tx.getHashAsString(),
                    tx.getConfidence().getConfidenceType().name());
            dead.remove(tx.getHash());
        }

        // Update tx and other unspent/pending transactions by connecting inputs/outputs.
        updateForSpends(tx, true);

        // Now make sure it ends up in the right pool. Also, handle the case where this TX is double-spending
        // against our pending transactions. Note that a tx may double spend our pending transactions and also send
        // us money/spend our money.
        boolean hasOutputsToMe = tx.getValueSentToMe(this, true).compareTo(BigInteger.ZERO) > 0;
        if (hasOutputsToMe) {
            // Needs to go into either unspent or spent (if the outputs were already spent by a pending tx).
            if (tx.isEveryOwnedOutputSpent(this)) {
                log.info("  tx {} ->spent (by pending)", tx.getHashAsString());
                addWalletTransaction(Pool.SPENT, tx);
            } else {
                log.info("  tx {} ->unspent", tx.getHashAsString());
                addWalletTransaction(Pool.UNSPENT, tx);
            }
        } else if (tx.getValueSentFromMe(this).compareTo(BigInteger.ZERO) > 0) {
            // Didn't send us any money, but did spend some. Keep it around for record keeping purposes.
            log.info("  tx {} ->spent", tx.getHashAsString());
            addWalletTransaction(Pool.SPENT, tx);
        } else if (forceAddToPool) {
            // Was manually added to pending, so we should keep it to notify the user of confidence information
            log.info("  tx {} ->spent (manually added)", tx.getHashAsString());
            addWalletTransaction(Pool.SPENT, tx);
        }

        checkForDoubleSpendAgainstPending(tx, true);
    }

    /**
     * <p>Updates the wallet by checking if this TX spends any of our outputs, and marking them as spent if so. If
     * fromChain is true, also checks to see if any pending transaction spends outputs of this transaction and marks
     * the spent flags appropriately.</p>
     *
     * <p>It can be called in two contexts. One is when we receive a transaction on the best chain but it wasn't pending,
     * this most commonly happens when we have a set of keys but the wallet transactions were wiped and we are catching
     * up with the block chain. It can also happen if a block includes a transaction we never saw at broadcast time.
     * If this tx double spends, it takes precedence over our pending transactions and the pending tx goes dead.</p>
     *
     * <p>The other context it can be called is from {@link Wallet#receivePending(Transaction, java.util.List)},
     * ie we saw a tx be broadcast or one was submitted directly that spends our own coins. If this tx double spends
     * it does NOT take precedence because the winner will be resolved by the miners - we assume that our version will
     * win, if we are wrong then when a block appears the tx will go dead.</p>
     *
     * @param tx The transaction which is being updated.
     * @param fromChain If true, the tx appeared on the current best chain, if false it was pending.
     */
    private void updateForSpends(Transaction tx, boolean fromChain) throws VerificationException {
        checkState(lock.isHeldByCurrentThread());
        if (fromChain)
            checkState(!pending.containsKey(tx.getHash()));
        for (TransactionInput input : tx.getInputs()) {
            TransactionInput.ConnectionResult result = input.connect(unspent, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
            if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                // Not found in the unspent map. Try again with the spent map.
                result = input.connect(spent, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
                if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                    // Not found in the unspent and spent maps. Try again with the pending map.
                    result = input.connect(pending, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
                    if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                        // Doesn't spend any of our outputs or is coinbase.
                        continue;
                    }
                }
            }

            if (result == TransactionInput.ConnectionResult.ALREADY_SPENT) {
                if (fromChain) {
                    // Double spend from chain: this will be handled later by checkForDoubleSpendAgainstPending.
                    log.warn("updateForSpends: saw double spend from chain, handling later.");
                } else {
                    // We saw two pending transactions that double spend each other. We don't know which will win.
                    // This can happen in the case of bad network nodes that mutate transactions. Do a hex dump
                    // so the exact nature of the mutation can be examined.
                    log.warn("Saw two pending transactions double spend each other");
                    log.warn("  offending input is input {}", tx.getInputs().indexOf(input));
                    log.warn("{}: {}", tx.getHash(), new String(Hex.encode(tx.unsafeBitcoinSerialize())));
                    Transaction other = input.getConnectedOutput().getSpentBy().getParentTransaction();
                    log.warn("{}: {}", other.getHash(), new String(Hex.encode(tx.unsafeBitcoinSerialize())));
                }
            } else if (result == TransactionInput.ConnectionResult.SUCCESS) {
                // Otherwise we saw a transaction spend our coins, but we didn't try and spend them ourselves yet.
                // The outputs are already marked as spent by the connect call above, so check if there are any more for
                // us to use. Move if not.
                Transaction connected = checkNotNull(input.getOutpoint().fromTx);
                log.info("  marked {} as spent", input.getOutpoint());
                maybeMovePool(connected, "prevtx");
            }
        }
        // Now check each output and see if there is a pending transaction which spends it. This shouldn't normally
        // ever occur because we expect transactions to arrive in temporal order, but this assumption can be violated
        // when we receive a pending transaction from the mempool that is relevant to us, which spends coins that we
        // didn't see arrive on the best chain yet. For instance, because of a chain replay or because of our keys were
        // used by another wallet somewhere else.
        if (fromChain) {
            for (Transaction pendingTx : pending.values()) {
                for (TransactionInput input : pendingTx.getInputs()) {
                    TransactionInput.ConnectionResult result = input.connect(tx, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
                    // This TX is supposed to have just appeared on the best chain, so its outputs should not be marked
                    // as spent yet. If they are, it means something is happening out of order.
                    checkState(result != TransactionInput.ConnectionResult.ALREADY_SPENT);
                    if (result == TransactionInput.ConnectionResult.SUCCESS) {
                        log.info("Connected pending tx input {}:{}",
                                pendingTx.getHashAsString(), pendingTx.getInputs().indexOf(input));
                    }
                }
                // If the transactions outputs are now all spent, it will be moved into the spent pool by the
                // processTxFromBestChain method.
            }
        }
    }

    private void killCoinbase(Transaction coinbase) {
        log.warn("Coinbase killed by re-org: {}", coinbase.getHashAsString());
        coinbase.getConfidence().setOverridingTransaction(null);
        confidenceChanged.put(coinbase, TransactionConfidence.Listener.ChangeReason.TYPE);
        final Sha256Hash hash = coinbase.getHash();
        pending.remove(hash);
        unspent.remove(hash);
        spent.remove(hash);
        addWalletTransaction(Pool.DEAD, coinbase);
        // TODO: Properly handle the recursive nature of killing transactions here.
    }

    // Updates the wallet when a double spend occurs. overridingTx/overridingInput can be null for the case of coinbases
    private void killTx(Transaction overridingTx, List<Transaction> killedTx) {
        for (Transaction tx : killedTx) {
            log.warn("Saw double spend from chain override pending tx {}", tx.getHashAsString());
            log.warn("  <-pending ->dead   killed by {}", overridingTx.getHashAsString());
            log.warn("Disconnecting each input and moving connected transactions.");
            pending.remove(tx.getHash());
            addWalletTransaction(Pool.DEAD, tx);
            for (TransactionInput deadInput : tx.getInputs()) {
                Transaction connected = deadInput.getOutpoint().fromTx;
                if (connected == null) continue;
                deadInput.disconnect();
                maybeMovePool(connected, "kill");
            }
            tx.getConfidence().setOverridingTransaction(overridingTx);
            confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.TYPE);
        }
        log.warn("Now attempting to connect the inputs of the overriding transaction.");
        for (TransactionInput input : overridingTx.getInputs()) {
            TransactionInput.ConnectionResult result = input.connect(unspent, TransactionInput.ConnectMode.DISCONNECT_ON_CONFLICT);
            if (result == TransactionInput.ConnectionResult.SUCCESS) {
                maybeMovePool(input.getOutpoint().fromTx, "kill");
            } else {
                result = input.connect(spent, TransactionInput.ConnectMode.DISCONNECT_ON_CONFLICT);
                if (result == TransactionInput.ConnectionResult.SUCCESS) {
                    maybeMovePool(input.getOutpoint().fromTx, "kill");
                }
            }
        }
        // TODO: Recursively kill other transactions that were double spent.
    }

    /**
     * If the transactions outputs are all marked as spent, and it's in the unspent map, move it.
     * If the owned transactions outputs are not all marked as spent, and it's in the spent map, move it.
     */
    private void maybeMovePool(Transaction tx, String context) {
        checkState(lock.isHeldByCurrentThread());
        if (tx.isEveryOwnedOutputSpent(this)) {
            // There's nothing left I can spend in this transaction.
            if (unspent.remove(tx.getHash()) != null) {
                if (log.isInfoEnabled()) {
                    log.info("  {} {} <-unspent ->spent", tx.getHashAsString(), context);
                }
                spent.put(tx.getHash(), tx);
            }
        } else {
            if (spent.remove(tx.getHash()) != null) {
                if (log.isInfoEnabled()) {
                    log.info("  {} {} <-spent ->unspent", tx.getHashAsString(), context);
                }
                unspent.put(tx.getHash(), tx);
            }
        }
    }

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money. Runs the listener methods in the user thread.
     */
    public void addEventListener(WalletEventListener listener) {
        addEventListener(listener, Threading.USER_THREAD);
    }

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money. The listener is executed by the given executor.
     */
    public void addEventListener(WalletEventListener listener, Executor executor) {
        eventListeners.add(new ListenerRegistration<WalletEventListener>(listener, executor));
    }

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
    public boolean removeEventListener(WalletEventListener listener) {
        return ListenerRegistration.removeFromList(listener, eventListeners);
    }

    /**
     * Calls {@link Wallet#commitTx} if tx is not already in the pending pool
     *
     * @return true if the tx was added to the wallet, or false if it was already in the pending pool
     */
    public boolean maybeCommitTx(Transaction tx) throws VerificationException {
        tx.verify();
        lock.lock();
        try {
            if (pending.containsKey(tx.getHash()))
                return false;
            log.info("commitTx of {}", tx.getHashAsString());
            BigInteger balance = getBalance();
            tx.setUpdateTime(Utils.now());
            // Mark the outputs we're spending as spent so we won't try and use them in future creations. This will also
            // move any transactions that are now fully spent to the spent map so we can skip them when creating future
            // spends.
            updateForSpends(tx, false);
            // Add to the pending pool. It'll be moved out once we receive this transaction on the best chain.
            // This also registers txConfidenceListener so wallet listeners get informed.
            log.info("->pending: {}", tx.getHashAsString());
            tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
            confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.TYPE);
            addWalletTransaction(Pool.PENDING, tx);

            try {
                BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
                BigInteger valueSentToMe = tx.getValueSentToMe(this);
                BigInteger newBalance = balance.add(valueSentToMe).subtract(valueSentFromMe);
                if (valueSentToMe.compareTo(BigInteger.ZERO) > 0) {
                    checkBalanceFuturesLocked(null);
                    queueOnCoinsReceived(tx, balance, newBalance);
                }
                if (valueSentFromMe.compareTo(BigInteger.ZERO) > 0)
                    queueOnCoinsSent(tx, balance, newBalance);

                maybeQueueOnWalletChanged();
            } catch (ScriptException e) {
                // Cannot happen as we just created this transaction ourselves.
                throw new RuntimeException(e);
            }

            checkState(isConsistent());
            informConfidenceListenersIfNotReorganizing();
            saveNow();
        } finally {
            lock.unlock();
        }
        return true;
    }

    /**
     * <p>Updates the wallet with the given transaction: puts it into the pending pool, sets the spent flags and runs
     * the onCoinsSent/onCoinsReceived event listener. Used in two situations:</p>
     *
     * <ol>
     *     <li>When we have just successfully transmitted the tx we created to the network.</li>
     *     <li>When we receive a pending transaction that didn't appear in the chain yet, and we did not create it.</li>
     * </ol>
     *
     * <p>Triggers an auto save.</p>
     */
    public void commitTx(Transaction tx) throws VerificationException {
        checkArgument(maybeCommitTx(tx), "commitTx called on the same transaction twice");
    }

    /**
     * Returns a set of all transactions in the wallet.
     * @param includeDead     If true, transactions that were overridden by a double spend are included.
     */
    public Set<Transaction> getTransactions(boolean includeDead) {
        lock.lock();
        try {
            Set<Transaction> all = new HashSet<Transaction>();
            all.addAll(unspent.values());
            all.addAll(spent.values());
            all.addAll(pending.values());
            if (includeDead)
                all.addAll(dead.values());
            return all;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a set of all WalletTransactions in the wallet.
     */
    public Iterable<WalletTransaction> getWalletTransactions() {
        lock.lock();
        try {
            Set<WalletTransaction> all = new HashSet<WalletTransaction>();
            addWalletTransactionsToSet(all, Pool.UNSPENT, unspent.values());
            addWalletTransactionsToSet(all, Pool.SPENT, spent.values());
            addWalletTransactionsToSet(all, Pool.DEAD, dead.values());
            addWalletTransactionsToSet(all, Pool.PENDING, pending.values());
            return all;
        } finally {
            lock.unlock();
        }
    }

    private static void addWalletTransactionsToSet(Set<WalletTransaction> txs,
                                                   Pool poolType, Collection<Transaction> pool) {
        for (Transaction tx : pool) {
            txs.add(new WalletTransaction(poolType, tx));
        }
    }

    /**
     * Adds a transaction that has been associated with a particular wallet pool. This is intended for usage by
     * deserialization code, such as the {@link WalletProtobufSerializer} class. It isn't normally useful for
     * applications. It does not trigger auto saving.
     */
    public void addWalletTransaction(WalletTransaction wtx) {
        lock.lock();
        try {
            addWalletTransaction(wtx.getPool(), wtx.getTransaction());
        } finally {
            lock.unlock();
        }
    }

    /**
     * Adds the given transaction to the given pools and registers a confidence change listener on it.
     */
    private void addWalletTransaction(Pool pool, Transaction tx) {
        checkState(lock.isHeldByCurrentThread());
        transactions.put(tx.getHash(), tx);
        switch (pool) {
        case UNSPENT:
            checkState(unspent.put(tx.getHash(), tx) == null);
            break;
        case SPENT:
            checkState(spent.put(tx.getHash(), tx) == null);
            break;
        case PENDING:
            checkState(pending.put(tx.getHash(), tx) == null);
            break;
        case DEAD:
            checkState(dead.put(tx.getHash(), tx) == null);
            break;
        default:
            throw new RuntimeException("Unknown wallet transaction type " + pool);
        }
        // This is safe even if the listener has been added before, as TransactionConfidence ignores duplicate
        // registration requests. That makes the code in the wallet simpler.
        tx.getConfidence().addEventListener(txConfidenceListener, Threading.SAME_THREAD);
    }

    /**
     * Returns all non-dead, active transactions ordered by recency.
     */
    public List<Transaction> getTransactionsByTime() {
        return getRecentTransactions(0, false);
    }

    /**
     * Returns an list of N transactions, ordered by increasing age. Transactions on side chains are not included.
     * Dead transactions (overridden by double spends) are optionally included. <p>
     * <p/>
     * Note: the current implementation is O(num transactions in wallet). Regardless of how many transactions are
     * requested, the cost is always the same. In future, requesting smaller numbers of transactions may be faster
     * depending on how the wallet is implemented (eg if backed by a database).
     */
    public List<Transaction> getRecentTransactions(int numTransactions, boolean includeDead) {
        lock.lock();
        try {
            checkArgument(numTransactions >= 0);
            // Firstly, put all transactions into an array.
            int size = getPoolSize(Pool.UNSPENT) +
                    getPoolSize(Pool.SPENT) +
                    getPoolSize(Pool.PENDING);
            if (numTransactions > size || numTransactions == 0) {
                numTransactions = size;
            }
            ArrayList<Transaction> all = new ArrayList<Transaction>(getTransactions(includeDead));
            // Order by date.
            Collections.sort(all, Collections.reverseOrder(new Comparator<Transaction>() {
                public int compare(Transaction t1, Transaction t2) {
                    return t1.getUpdateTime().compareTo(t2.getUpdateTime());
                }
            }));
            if (numTransactions == all.size()) {
                return all;
            } else {
                all.subList(numTransactions, all.size()).clear();
                return all;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a transaction object given its hash, if it exists in this wallet, or null otherwise.
     */
    @Nullable
    public Transaction getTransaction(Sha256Hash hash) {
        lock.lock();
        try {
            return transactions.get(hash);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Deletes transactions which appeared above the given block height from the wallet, but does not touch the keys.
     * This is useful if you have some keys and wish to replay the block chain into the wallet in order to pick them up.
     * Triggers auto saving.
     */
    public void clearTransactions(int fromHeight) {
        lock.lock();
        try {
            if (fromHeight == 0) {
                unspent.clear();
                spent.clear();
                pending.clear();
                dead.clear();
                transactions.clear();
                saveLater();
            } else {
                throw new UnsupportedOperationException();
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Clean up the wallet. Currently, it only removes risky pending transaction from the wallet and only if their
     * outputs have not been spent.
     */
    public void cleanup() {
        lock.lock();
        try {
            boolean dirty = false;
            for (Iterator<Transaction> i = pending.values().iterator(); i.hasNext();) {
                Transaction tx = i.next();
                if (isTransactionRisky(tx, null) && !acceptRiskyTransactions) {
                    log.debug("Found risky transaction {} in wallet during cleanup.", tx.getHashAsString());
                    if (!tx.isAnyOutputSpent()) {
                        tx.disconnectInputs();
                        i.remove();
                        transactions.remove(tx.getHash());
                        dirty = true;
                        log.info("Removed transaction {} from pending pool during cleanup.", tx.getHashAsString());
                    } else {
                        log.info(
                                "Cannot remove transaction {} from pending pool during cleanup, as it's already spent partially.",
                                tx.getHashAsString());
                    }
                }
            }
            if (dirty) {
                checkState(isConsistent());
                saveLater();
            }
        } finally {
            lock.unlock();
        }
    }

    EnumSet<Pool> getContainingPools(Transaction tx) {
        lock.lock();
        try {
            EnumSet<Pool> result = EnumSet.noneOf(Pool.class);
            Sha256Hash txHash = tx.getHash();
            if (unspent.containsKey(txHash)) {
                result.add(Pool.UNSPENT);
            }
            if (spent.containsKey(txHash)) {
                result.add(Pool.SPENT);
            }
            if (pending.containsKey(txHash)) {
                result.add(Pool.PENDING);
            }
            if (dead.containsKey(txHash)) {
                result.add(Pool.DEAD);
            }
            return result;
        } finally {
            lock.unlock();
        }
    }

    int getPoolSize(WalletTransaction.Pool pool) {
        lock.lock();
        try {
            switch (pool) {
                case UNSPENT:
                    return unspent.size();
                case SPENT:
                    return spent.size();
                case PENDING:
                    return pending.size();
                case DEAD:
                    return dead.size();
            }
            throw new RuntimeException("Unreachable");
        } finally {
            lock.unlock();
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    //  SEND APIS
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /** A SendResult is returned to you as part of sending coins to a recipient. */
    public static class SendResult {
        /** The Bitcoin transaction message that moves the money. */
        public Transaction tx;
        /** A future that will complete once the tx message has been successfully broadcast to the network. */
        public ListenableFuture<Transaction> broadcastComplete;
    }

    /**
     * A SendRequest gives the wallet information about precisely how to send money to a recipient or set of recipients.
     * Static methods are provided to help you create SendRequests and there are a few helper methods on the wallet that
     * just simplify the most common use cases. You may wish to customize a SendRequest if you want to attach a fee or
     * modify the change address.
     */
    public static class SendRequest {
        /**
         * <p>A transaction, probably incomplete, that describes the outline of what you want to do. This typically will
         * mean it has some outputs to the intended destinations, but no inputs or change address (and therefore no
         * fees) - the wallet will calculate all that for you and update tx later.</p>
         *
         * <p>Be careful when adding outputs that you check the min output value
         * ({@link TransactionOutput#getMinNonDustValue(BigInteger)}) to avoid the whole transaction being rejected
         * because one output is dust.</p>
         *
         * <p>If there are already inputs to the transaction, make sure their out point has a connected output,
         * otherwise their value will be added to fee.  Also ensure they are either signed or are spendable by a wallet
         * key, otherwise the behavior of {@link Wallet#completeTx(Wallet.SendRequest)} is undefined (likely
         * RuntimeException).</p>
         */
        public Transaction tx;

        /**
         * When emptyWallet is set, all coins selected by the coin selector are sent to the first output in tx
         * (its value is ignored and set to {@link com.google.bitcoin.core.Wallet#getBalance()} - the fees required
         * for the transaction). Any additional outputs are removed.
         */
        public boolean emptyWallet = false;

        /**
         * "Change" means the difference between the value gathered by a transactions inputs (the size of which you
         * don't really control as it depends on who sent you money), and the value being sent somewhere else. The
         * change address should be selected from this wallet, normally. <b>If null this will be chosen for you.</b>
         */
        public Address changeAddress = null;

        /**
         * <p>A transaction can have a fee attached, which is defined as the difference between the input values
         * and output values. Any value taken in that is not provided to an output can be claimed by a miner. This
         * is how mining is incentivized in later years of the Bitcoin system when inflation drops. It also provides
         * a way for people to prioritize their transactions over others and is used as a way to make denial of service
         * attacks expensive.</p>
         *
         * <p>This is a constant fee (in satoshis) which will be added to the transaction. It is recommended that it be
         * at least {@link Transaction#REFERENCE_DEFAULT_MIN_TX_FEE} if it is set, as default reference clients will
         * otherwise simply treat the transaction as if there were no fee at all.</p>
         *
         * <p>Once {@link Wallet#completeTx(com.google.bitcoin.core.Wallet.SendRequest)} is called, this is set to the
         * value of the fee that was added.</p>
         *
         * <p>You might also consider adding a {@link SendRequest#feePerKb} to set the fee per kb of transaction size
         * (rounded down to the nearest kb) as that is how transactions are sorted when added to a block by miners.</p>
         */
        public BigInteger fee = null;

        /**
         * <p>A transaction can have a fee attached, which is defined as the difference between the input values
         * and output values. Any value taken in that is not provided to an output can be claimed by a miner. This
         * is how mining is incentivized in later years of the Bitcoin system when inflation drops. It also provides
         * a way for people to prioritize their transactions over others and is used as a way to make denial of service
         * attacks expensive.</p>
         *
         * <p>This is a dynamic fee (in satoshis) which will be added to the transaction for each kilobyte in size
         * including the first. This is useful as as miners usually sort pending transactions by their fee per unit size
         * when choosing which transactions to add to a block. Note that, to keep this equivalent to the reference
         * client definition, a kilobyte is defined as 1000 bytes, not 1024.</p>
         *
         * <p>You might also consider using a {@link SendRequest#fee} to set the fee added for the first kb of size.</p>
         */
        public BigInteger feePerKb = DEFAULT_FEE_PER_KB;

        /**
         * If you want to modify the default fee for your entire app without having to change each SendRequest you make,
         * you can do it here. This is primarily useful for unit tests.
         */
        public static BigInteger DEFAULT_FEE_PER_KB = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;

        /**
         * <p>Requires that there be enough fee for a default reference client to at least relay the transaction.
         * (ie ensure the transaction will not be outright rejected by the network). Defaults to true, you should
         * only set this to false if you know what you're doing.</p>
         *
         * <p>Note that this does not enforce certain fee rules that only apply to transactions which are larger than
         * 26,000 bytes. If you get a transaction which is that large, you should set a fee and feePerKb of at least
         * {@link Transaction#REFERENCE_DEFAULT_MIN_TX_FEE}.</p>
         */
        public boolean ensureMinRequiredFee = true;

        /**
         * The AES key to use to decrypt the private keys before signing.
         * If null then no decryption will be performed and if decryption is required an exception will be thrown.
         * You can get this from a password by doing wallet.getKeyCrypter().deriveKey(password).
         */
        public KeyParameter aesKey = null;

        /**
         * If not null, the {@link com.google.bitcoin.wallet.CoinSelector} to use instead of the wallets default. Coin selectors are
         * responsible for choosing which transaction outputs (coins) in a wallet to use given the desired send value
         * amount.
         */
        public CoinSelector coinSelector = null;

        // Tracks if this has been passed to wallet.completeTx already: just a safety check.
        private boolean completed;

        private SendRequest() {}

        /**
         * <p>Creates a new SendRequest to the given address for the given value.</p>
         *
         * <p>Be very careful when value is smaller than {@link Transaction#MIN_NONDUST_OUTPUT} as the transaction will
         * likely be rejected by the network in this case.</p>
         */
        public static SendRequest to(Address destination, BigInteger value) {
            SendRequest req = new SendRequest();
            final NetworkParameters parameters = destination.getParameters();
            checkNotNull(parameters, "Address is for an unknown network");
            req.tx = new Transaction(parameters);
            req.tx.addOutput(value, destination);
            return req;
        }

        /**
         * <p>Creates a new SendRequest to the given pubkey for the given value.</p>
         *
         * <p>Be careful to check the output's value is reasonable using
         * {@link TransactionOutput#getMinNonDustValue(BigInteger)} afterwards or you risk having the transaction
         * rejected by the network. Note that using {@link SendRequest#to(Address, java.math.BigInteger)} will result
         * in a smaller output, and thus the ability to use a smaller output value without rejection.</p>
         */
        public static SendRequest to(NetworkParameters params, ECKey destination, BigInteger value) {
            SendRequest req = new SendRequest();
            req.tx = new Transaction(params);
            req.tx.addOutput(value, destination);
            return req;
        }

        /** Simply wraps a pre-built incomplete transaction provided by you. */
        public static SendRequest forTx(Transaction tx) {
            SendRequest req = new SendRequest();
            req.tx = tx;
            return req;
        }

        public static SendRequest emptyWallet(Address destination) {
            SendRequest req = new SendRequest();
            final NetworkParameters parameters = destination.getParameters();
            checkNotNull(parameters, "Address is for an unknown network");
            req.tx = new Transaction(parameters);
            req.tx.addOutput(BigInteger.ZERO, destination);
            req.emptyWallet = true;
            return req;
        }
    }

    /**
     * <p>Statelessly creates a transaction that sends the given value to address. The change is sent to
     * {@link Wallet#getChangeAddress()}, so you must have added at least one key.</p>
     *
     * <p>If you just want to send money quickly, you probably want
     * {@link Wallet#sendCoins(TransactionBroadcaster, Address, java.math.BigInteger)} instead. That will create the sending
     * transaction, commit to the wallet and broadcast it to the network all in one go. This method is lower level
     * and lets you see the proposed transaction before anything is done with it.</p>
     *
     * <p>This is a helper method that is equivalent to using {@link Wallet.SendRequest#to(Address, java.math.BigInteger)}
     * followed by {@link Wallet#completeTx(Wallet.SendRequest)} and returning the requests transaction object.
     * Note that this means a fee may be automatically added if required, if you want more control over the process,
     * just do those two steps yourself.</p>
     *
     * <p>IMPORTANT: This method does NOT update the wallet. If you call createSend again you may get two transactions
     * that spend the same coins. You have to call {@link Wallet#commitTx(Transaction)} on the created transaction to
     * prevent this, but that should only occur once the transaction has been accepted by the network. This implies
     * you cannot have more than one outstanding sending tx at once.</p>
     *
     * <p>You MUST ensure that nanocoins is not smaller than {@link Transaction#MIN_NONDUST_OUTPUT} or the transaction
     * will almost certainly be rejected by the network as dust.</p>
     *
     * @param address       The Bitcoin address to send the money to.
     * @param nanocoins     How much currency to send, in nanocoins.
     * @return either the created Transaction or null if there are insufficient coins.
     * coins as spent until commitTx is called on the result.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     */
    public Transaction createSend(Address address, BigInteger nanocoins) throws InsufficientMoneyException {
        SendRequest req = SendRequest.to(address, nanocoins);
        completeTx(req);
        return req.tx;
    }

    /**
     * Sends coins to the given address but does not broadcast the resulting pending transaction. It is still stored
     * in the wallet, so when the wallet is added to a {@link PeerGroup} or {@link Peer} the transaction will be
     * announced to the network. The given {@link SendRequest} is completed first using
     * {@link Wallet#completeTx(Wallet.SendRequest)} to make it valid.
     *
     * @return the Transaction that was created
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     */
    public Transaction sendCoinsOffline(SendRequest request) throws InsufficientMoneyException {
        lock.lock();
        try {
            completeTx(request);
            commitTx(request.tx);
            return request.tx;
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Sends coins to the given address, via the given {@link PeerGroup}. Change is returned to
     * {@link Wallet#getChangeAddress()}. Note that a fee may be automatically added if one may be required for the
     * transaction to be confirmed.</p>
     *
     * <p>The returned object provides both the transaction, and a future that can be used to learn when the broadcast
     * is complete. Complete means, if the PeerGroup is limited to only one connection, when it was written out to
     * the socket. Otherwise when the transaction is written out and we heard it back from a different peer.</p>
     *
     * <p>Note that the sending transaction is committed to the wallet immediately, not when the transaction is
     * successfully broadcast. This means that even if the network hasn't heard about your transaction you won't be
     * able to spend those same coins again.</p>
     *
     * <p>You MUST ensure that value is not smaller than {@link Transaction#MIN_NONDUST_OUTPUT} or the transaction will
     * almost certainly be rejected by the network as dust.</p>
     *
     * @param broadcaster a {@link TransactionBroadcaster} to use to send the transactions out.
     * @param to        Which address to send coins to.
     * @param value     How much value to send. You can use Utils.toNanoCoins() to calculate this.
     * @return An object containing the transaction that was created, and a future for the broadcast of it.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     */
    public SendResult sendCoins(TransactionBroadcaster broadcaster, Address to, BigInteger value) throws InsufficientMoneyException {
        SendRequest request = SendRequest.to(to, value);
        return sendCoins(broadcaster, request);
    }

    /**
     * <p>Sends coins according to the given request, via the given {@link TransactionBroadcaster}.</p>
     *
     * <p>The returned object provides both the transaction, and a future that can be used to learn when the broadcast
     * is complete. Complete means, if the PeerGroup is limited to only one connection, when it was written out to
     * the socket. Otherwise when the transaction is written out and we heard it back from a different peer.</p>
     *
     * <p>Note that the sending transaction is committed to the wallet immediately, not when the transaction is
     * successfully broadcast. This means that even if the network hasn't heard about your transaction you won't be
     * able to spend those same coins again.</p>
     *
     * @param broadcaster the target to use for broadcast.
     * @param request the SendRequest that describes what to do, get one using static methods on SendRequest itself.
     * @return An object containing the transaction that was created, and a future for the broadcast of it.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     */
    public SendResult sendCoins(TransactionBroadcaster broadcaster, SendRequest request) throws InsufficientMoneyException {
        // Should not be locked here, as we're going to call into the broadcaster and that might want to hold its
        // own lock. sendCoinsOffline handles everything that needs to be locked.
        checkState(!lock.isHeldByCurrentThread());

        // Commit the TX to the wallet immediately so the spent coins won't be reused.
        // TODO: We should probably allow the request to specify tx commit only after the network has accepted it.
        Transaction tx = sendCoinsOffline(request);
        SendResult result = new SendResult();
        result.tx = tx;
        // The tx has been committed to the pending pool by this point (via sendCoinsOffline -> commitTx), so it has
        // a txConfidenceListener registered. Once the tx is broadcast the peers will update the memory pool with the
        // count of seen peers, the memory pool will update the transaction confidence object, that will invoke the
        // txConfidenceListener which will in turn invoke the wallets event listener onTransactionConfidenceChanged
        // method.
        result.broadcastComplete = broadcaster.broadcastTransaction(tx);
        return result;
    }

    /**
     * Satisfies the given {@link SendRequest} using the default transaction broadcaster configured either via
     * {@link PeerGroup#addWallet(Wallet)} or directly with {@link #setTransactionBroadcaster(TransactionBroadcaster)}.
     *
     * @param request the SendRequest that describes what to do, get one using static methods on SendRequest itself.
     * @return An object containing the transaction that was created, and a future for the broadcast of it.
     * @throws IllegalStateException if no transaction broadcaster has been configured.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     */
    public SendResult sendCoins(SendRequest request) throws InsufficientMoneyException {
        TransactionBroadcaster broadcaster = vTransactionBroadcaster;
        checkState(broadcaster != null, "No transaction broadcaster is configured");
        return sendCoins(broadcaster, request);
    }

    /**
     * Sends coins to the given address, via the given {@link Peer}. Change is returned to {@link Wallet#getChangeAddress()}.
     * If an exception is thrown by {@link Peer#sendMessage(Message)} the transaction is still committed, so the
     * pending transaction must be broadcast <b>by you</b> at some other time. Note that a fee may be automatically added
     * if one may be required for the transaction to be confirmed.
     *
     * @return The {@link Transaction} that was created or null if there was insufficient balance to send the coins.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     */
    public Transaction sendCoins(Peer peer, SendRequest request) throws InsufficientMoneyException {
        Transaction tx = sendCoinsOffline(request);
        peer.sendMessage(tx);
        return tx;
    }

    /**
     * Given a spend request containing an incomplete transaction, makes it valid by adding outputs and signed inputs
     * according to the instructions in the request. The transaction in the request is modified by this method, as is
     * the fee parameter.
     *
     * @param req a SendRequest that contains the incomplete transaction and details for how to make it valid.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice, or if the given send request
     *         cannot be completed without violating the protocol rules.
     */
    public void completeTx(SendRequest req) throws InsufficientMoneyException {
        lock.lock();
        try {
            checkArgument(!req.completed, "Given SendRequest has already been completed.");
            // Calculate the amount of value we need to import.
            BigInteger value = BigInteger.ZERO;
            for (TransactionOutput output : req.tx.getOutputs()) {
                value = value.add(output.getValue());
            }
            BigInteger totalOutput = value;

            log.info("Completing send tx with {} outputs totalling {} satoshis (not including fees)",
                    req.tx.getOutputs().size(), value);

            // If any inputs have already been added, we don't need to get their value from wallet
            BigInteger totalInput = BigInteger.ZERO;
            for (TransactionInput input : req.tx.getInputs())
                if (input.getConnectedOutput() != null)
                    totalInput = totalInput.add(input.getConnectedOutput().getValue());
                else
                    log.warn("SendRequest transaction already has inputs but we don't know how much they are worth - they will be added to fee.");
            value = value.subtract(totalInput);

            List<TransactionInput> originalInputs = new ArrayList<TransactionInput>(req.tx.getInputs());

            // We need to know if we need to add an additional fee because one of our values are smaller than 0.01 BTC
            boolean needAtLeastReferenceFee = false;
            if (req.ensureMinRequiredFee && !req.emptyWallet) { // min fee checking is handled later for emptyWallet
                for (TransactionOutput output : req.tx.getOutputs())
                    if (output.getValue().compareTo(Utils.CENT) < 0) {
                        if (output.getValue().compareTo(output.getMinNonDustValue()) < 0)
                            throw new IllegalArgumentException("Tried to send dust with ensureMinRequiredFee set - no way to complete this");
                        needAtLeastReferenceFee = true;
                        break;
                    }
            }

            // Calculate a list of ALL potential candidates for spending and then ask a coin selector to provide us
            // with the actual outputs that'll be used to gather the required amount of value. In this way, users
            // can customize coin selection policies.
            //
            // Note that this code is poorly optimized: the spend candidates only alter when transactions in the wallet
            // change - it could be pre-calculated and held in RAM, and this is probably an optimization worth doing.
            // Note that output.isMine(this) needs to test the keychain which is currently an array, so it's
            // O(candidate outputs ^ keychain.size())! There's lots of low hanging fruit here.
            LinkedList<TransactionOutput> candidates = calculateAllSpendCandidates(true);
            CoinSelection bestCoinSelection;
            TransactionOutput bestChangeOutput = null;
            if (!req.emptyWallet) {
                // This can throw InsufficientMoneyException.
                FeeCalculation feeCalculation;
                feeCalculation = new FeeCalculation(req, value, originalInputs, needAtLeastReferenceFee, candidates);
                bestCoinSelection = feeCalculation.bestCoinSelection;
                bestChangeOutput = feeCalculation.bestChangeOutput;
            } else {
                // We're being asked to empty the wallet. What this means is ensuring "tx" has only a single output
                // of the total value we can currently spend as determined by the selector, and then subtracting the fee.
                checkState(req.tx.getOutputs().size() == 1, "Empty wallet TX must have a single output only.");
                CoinSelector selector = req.coinSelector == null ? coinSelector : req.coinSelector;
                bestCoinSelection = selector.select(NetworkParameters.MAX_MONEY, candidates);
                req.tx.getOutput(0).setValue(bestCoinSelection.valueGathered);
                totalOutput = bestCoinSelection.valueGathered;
            }

            for (TransactionOutput output : bestCoinSelection.gathered)
                req.tx.addInput(output);

            if (req.ensureMinRequiredFee && req.emptyWallet) {
                final BigInteger baseFee = req.fee == null ? BigInteger.ZERO : req.fee;
                final BigInteger feePerKb = req.feePerKb == null ? BigInteger.ZERO : req.feePerKb;
                Transaction tx = req.tx;
                if (!adjustOutputDownwardsForFee(tx, bestCoinSelection, baseFee, feePerKb))
                    throw new InsufficientMoneyException.CouldNotAdjustDownwards();
            }

            totalInput = totalInput.add(bestCoinSelection.valueGathered);

            if (bestChangeOutput != null) {
                req.tx.addOutput(bestChangeOutput);
                totalOutput = totalOutput.add(bestChangeOutput.getValue());
                log.info("  with {} coins change", bitcoinValueToFriendlyString(bestChangeOutput.getValue()));
            }
            final BigInteger calculatedFee = totalInput.subtract(totalOutput);
            if (calculatedFee.compareTo(BigInteger.ZERO) > 0) {
                log.info("  with a fee of {}", bitcoinValueToFriendlyString(calculatedFee));
            }

            // Now sign the inputs, thus proving that we are entitled to redeem the connected outputs.
            req.tx.signInputs(Transaction.SigHash.ALL, this, req.aesKey);

            // Check size.
            int size = req.tx.bitcoinSerialize().length;
            if (size > Transaction.MAX_STANDARD_TX_SIZE) {
                throw new IllegalArgumentException(
                        String.format("Transaction could not be created without exceeding max size: %d vs %d", size,
                            Transaction.MAX_STANDARD_TX_SIZE));
            }

            // Label the transaction as being self created. We can use this later to spend its change output even before
            // the transaction is confirmed. We deliberately won't bother notifying listeners here as there's not much
            // point - the user isn't interested in a confidence transition they made themselves.
            req.tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
            // Label the transaction as being a user requested payment. This can be used to render GUI wallet
            // transaction lists more appropriately, especially when the wallet starts to generate transactions itself
            // for internal purposes.
            req.tx.setPurpose(Transaction.Purpose.USER_PAYMENT);
            req.completed = true;
            req.fee = calculatedFee;
            log.info("  completed: {}", req.tx);
        } finally {
            lock.unlock();
        }
    }

    /** Reduce the value of the first output of a transaction to pay the given feePerKb as appropriate for its size. */
    private boolean adjustOutputDownwardsForFee(Transaction tx, CoinSelection coinSelection, BigInteger baseFee, BigInteger feePerKb) {
        TransactionOutput output = tx.getOutput(0);
        // Check if we need additional fee due to the transaction's size
        int size = tx.bitcoinSerialize().length;
        size += estimateBytesForSigning(coinSelection);
        BigInteger fee = baseFee.add(BigInteger.valueOf((size / 1000) + 1).multiply(feePerKb));
        output.setValue(output.getValue().subtract(fee));
        // Check if we need additional fee due to the output's value
        if (output.getValue().compareTo(Utils.CENT) < 0 && fee.compareTo(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE) < 0)
            output.setValue(output.getValue().subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.subtract(fee)));
        return output.getMinNonDustValue().compareTo(output.getValue()) <= 0;
    }

    /**
     * Returns a list of all possible outputs we could possibly spend, potentially even including immature coinbases
     * (which the protocol may forbid us from spending). In other words, return all outputs that this wallet holds
     * keys for and which are not already marked as spent.
     */
    public LinkedList<TransactionOutput> calculateAllSpendCandidates(boolean excludeImmatureCoinbases) {
        lock.lock();
        try {
            LinkedList<TransactionOutput> candidates = Lists.newLinkedList();
            for (Transaction tx : Iterables.concat(unspent.values(), pending.values())) {
                // Do not try and spend coinbases that were mined too recently, the protocol forbids it.
                if (excludeImmatureCoinbases && !tx.isMature()) continue;
                for (TransactionOutput output : tx.getOutputs()) {
                    if (!output.isAvailableForSpending()) continue;
                    if (!output.isMine(this)) continue;
                    candidates.add(output);
                }
            }
            return candidates;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns all the outputs that match addresses or scripts added via {@link #addWatchedAddress(Address)} or
     * {@link #addWatchedScripts(java.util.List)}.
     * @param excludeImmatureCoinbases Whether to ignore outputs that are unspendable due to being immature.
     */
    public LinkedList<TransactionOutput> getWatchedOutputs(boolean excludeImmatureCoinbases) {
        lock.lock();
        try {
            LinkedList<TransactionOutput> candidates = Lists.newLinkedList();
            for (Transaction tx : Iterables.concat(unspent.values(), pending.values())) {
                if (excludeImmatureCoinbases && !tx.isMature()) continue;
                for (TransactionOutput output : tx.getOutputs()) {
                    if (!output.isAvailableForSpending()) continue;
                    try {
                        Script scriptPubKey = output.getScriptPubKey();
                        if (!watchedScripts.contains(scriptPubKey)) continue;
                        candidates.add(output);
                    } catch (ScriptException e) {
                        // Ignore
                    }
                }
            }
            return candidates;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the address used for change outputs. Note: this will probably go away in future. */
    public Address getChangeAddress() {
        lock.lock();
        try {
            // For now let's just pick the first key in our keychain. In future we might want to do something else to
            // give the user better privacy here, eg in incognito mode.
            checkState(keychain.size() > 0, "Can't send value without an address to use for receiving change");
            ECKey first = keychain.get(0);
            return first.toAddress(params);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Adds the given ECKey to the wallet. There is currently no way to delete keys (that would result in coin loss).
     * If {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, com.google.bitcoin.wallet.WalletFiles.Listener)}
     * has been called, triggers an auto save bypassing the normal coalescing delay and event handlers.
     * If the key already exists in the wallet, does nothing and returns false.
     */
    public boolean addKey(final ECKey key) {
        return addKeys(Lists.newArrayList(key)) == 1;
    }

    /**
     * Adds the given keys to the wallet. There is currently no way to delete keys (that would result in coin loss).
     * If {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, com.google.bitcoin.wallet.WalletFiles.Listener)}
     * has been called, triggers an auto save bypassing the normal coalescing delay and event handlers.
     * Returns the number of keys added, after duplicates are ignored. The onKeyAdded event will be called for each key
     * in the list that was not already present.
     */
    public int addKeys(final List<ECKey> keys) {
        lock.lock();
        try {
            int added = 0;
            // TODO: Consider making keys a sorted list or hashset so membership testing is faster.
            for (final ECKey key : keys) {
                if (keychain.contains(key)) continue;

                // If the key has a keyCrypter that does not match the Wallet's then a KeyCrypterException is thrown.
                // This is done because only one keyCrypter is persisted per Wallet and hence all the keys must be homogenous.
                if (isEncrypted() && (!key.isEncrypted() || !keyCrypter.equals(key.getKeyCrypter()))) {
                    throw new KeyCrypterException("Cannot add key " + key.toString() + " because the keyCrypter does not match the wallets. Keys must be homogenous.");
                } else if (key.isEncrypted() && !isEncrypted()) {
                    throw new KeyCrypterException("Cannot add key because it's encrypted and this wallet is not.");
                }
                keychain.add(key);
                added++;
            }
            queueOnKeysAdded(keys);
            // Force an auto-save immediately rather than queueing one, as keys are too important to risk losing.
            saveNow();
            return added;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Return true if we are watching this address.
     */
    public boolean isAddressWatched(Address address) {
        Script script = ScriptBuilder.createOutputScript(address);
        return isWatchedScript(script);
    }

    /**
     * Same as {@link #addWatchedAddress(Address, long)} with the current time as the creation time.
     */
    public boolean addWatchedAddress(final Address address) {
        long now = Utils.currentTimeMillis() / 1000;
        return addWatchedAddresses(Lists.newArrayList(address), now) == 1;
    }

    /**
     * Adds the given address to the wallet to be watched. Outputs can be retrieved by {@link #getWatchedOutputs(boolean)}.
     *
     * @param creationTime creation time in seconds since the epoch, for scanning the blockchain
     * @return whether the address was added successfully (not already present)
     */
    public boolean addWatchedAddress(final Address address, long creationTime) {
        return addWatchedAddresses(Lists.newArrayList(address), creationTime) == 1;
    }

    /**
     * Adds the given address to the wallet to be watched. Outputs can be retrieved
     * by {@link #getWatchedOutputs(boolean)}.
     *
     * @return how many addresses were added successfully
     */
    public int addWatchedAddresses(final List<Address> addresses, long creationTime) {
        List<Script> scripts = Lists.newArrayList();

        for (Address address : addresses) {
            Script script = ScriptBuilder.createOutputScript(address);
            script.setCreationTimeSeconds(creationTime);
            scripts.add(script);
        }

        return addWatchedScripts(scripts);
    }

    /**
     * Adds the given output scripts to the wallet to be watched. Outputs can be retrieved
     * by {@link #getWatchedOutputs(boolean)}.
     *
     * @return how many scripts were added successfully
     */
    public int addWatchedScripts(final List<Script> scripts) {
        lock.lock();
        try {
            int added = 0;
            for (final Script script : scripts) {
                if (watchedScripts.contains(script)) continue;

                watchedScripts.add(script);
                added++;
            }

            queueOnScriptsAdded(scripts);
            saveNow();
            return added;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Locates a keypair from the keychain given the hash of the public key. This is needed when finding out which
     * key we need to use to redeem a transaction output.
     *
     * @return ECKey object or null if no such key was found.
     */
    @Nullable
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        lock.lock();
        try {
            for (ECKey key : keychain) {
                if (Arrays.equals(key.getPubKeyHash(), pubkeyHash)) return key;
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    /** Returns true if the given key is in the wallet, false otherwise. Currently an O(N) operation. */
    public boolean hasKey(ECKey key) {
        lock.lock();
        try {
            return keychain.contains(key);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns true if this wallet contains a public key which hashes to the given hash.
     */
    public boolean isPubKeyHashMine(byte[] pubkeyHash) {
        return findKeyFromPubHash(pubkeyHash) != null;
    }

    /** Returns true if this wallet is watching transactions for outputs with the script. */
    public boolean isWatchedScript(Script script) {
        lock.lock();
        try {
            return watchedScripts.contains(script);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Locates a keypair from the keychain given the raw public key bytes.
     * @return ECKey or null if no such key was found.
     */
    @Nullable
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        lock.lock();
        try {
            for (ECKey key : keychain) {
                if (Arrays.equals(key.getPubKey(), pubkey)) return key;
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns true if this wallet contains a keypair with the given public key.
     */
    public boolean isPubKeyMine(byte[] pubkey) {
        return findKeyFromPubKey(pubkey) != null;
    }

    /**
     * <p>It's possible to calculate a wallets balance from multiple points of view. This enum selects which
     * getBalance() should use.</p>
     *
     * <p>Consider a real-world example: you buy a snack costing $5 but you only have a $10 bill. At the start you have
     * $10 viewed from every possible angle. After you order the snack you hand over your $10 bill. From the
     * perspective of your wallet you have zero dollars (AVAILABLE). But you know in a few seconds the shopkeeper
     * will give you back $5 change so most people in practice would say they have $5 (ESTIMATED).</p>
     */
    public enum BalanceType {
        /**
         * Balance calculated assuming all pending transactions are in fact included into the best chain by miners.
         * This includes the value of immature coinbase transactions.
         */
        ESTIMATED,

        /**
         * Balance that can be safely used to create new spends. This is whatever the default coin selector would
         * make available, which by default means transaction outputs with at least 1 confirmation and pending
         * transactions created by our own wallet which have been propagated across the network.
         */
        AVAILABLE
    }

    /**
     * Returns the AVAILABLE balance of this wallet. See {@link BalanceType#AVAILABLE} for details on what this
     * means.
     */
    public BigInteger getBalance() {
        return getBalance(BalanceType.AVAILABLE);
    }

    /**
     * Returns the balance of this wallet as calculated by the provided balanceType.
     */
    public BigInteger getBalance(BalanceType balanceType) {
        lock.lock();
        try {
            if (balanceType == BalanceType.AVAILABLE) {
                return getBalance(coinSelector);
            } else if (balanceType == BalanceType.ESTIMATED) {
                LinkedList<TransactionOutput> all = calculateAllSpendCandidates(false);
                BigInteger value = BigInteger.ZERO;
                for (TransactionOutput out : all) value = value.add(out.getValue());
                return value;
            } else {
                throw new AssertionError("Unknown balance type");  // Unreachable.
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the balance that would be considered spendable by the given coin selector. Just asks it to select
     * as many coins as possible and returns the total.
     */
    public BigInteger getBalance(CoinSelector selector) {
        lock.lock();
        try {
            checkNotNull(selector);
            LinkedList<TransactionOutput> candidates = calculateAllSpendCandidates(true);
            CoinSelection selection = selector.select(NetworkParameters.MAX_MONEY, candidates);
            return selection.valueGathered;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the available balance, including any unspent balance at watched addresses */
    public BigInteger getWatchedBalance() {
        return getWatchedBalance(coinSelector);
    }

     /**
     * Returns the balance that would be considered spendable by the given coin selector, including
     * any unspent balance at watched addresses.
     */
    public BigInteger getWatchedBalance(CoinSelector selector) {
        lock.lock();
        try {
            checkNotNull(selector);
            LinkedList<TransactionOutput> candidates = getWatchedOutputs(true);
            CoinSelection selection = selector.select(NetworkParameters.MAX_MONEY, candidates);
            return selection.valueGathered;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public String toString() {
        return toString(false, true, true, null);
    }

    private static final Comparator<Transaction> SORT_ORDER_BY_UPDATE_TIME = new Comparator<Transaction>() {

        @Override
        public int compare(final Transaction tx1, final Transaction tx2) {

            final long time1 = tx1.getUpdateTime().getTime();
            final long time2 = tx2.getUpdateTime().getTime();

            return -(Longs.compare(time1, time2));
        }
    };

    private static final Comparator<Transaction> SORT_ORDER_BY_HEIGHT = new Comparator<Transaction>() {

        @Override
        public int compare(final Transaction tx1, final Transaction tx2) {

            final int height1 = tx1.getConfidence().getAppearedAtChainHeight();
            final int height2 = tx2.getConfidence().getAppearedAtChainHeight();

            return -(Ints.compare(height1, height2));
        }
    };

    /**
     * Formats the wallet as a human readable piece of text. Intended for debugging, the format is not meant to be
     * stable or human readable.
     * @param includePrivateKeys Whether raw private key data should be included.
     * @param includeTransactions Whether to print transaction data.
     * @param includeExtensions Whether to print extension data.
     * @param chain If set, will be used to estimate lock times for block timelocked transactions.
     */
    public String toString(boolean includePrivateKeys, boolean includeTransactions, boolean includeExtensions,
                           @Nullable AbstractBlockChain chain) {
        lock.lock();
        try {
            StringBuilder builder = new StringBuilder();
            BigInteger estimatedBalance = getBalance(BalanceType.ESTIMATED);
            BigInteger availableBalance = getBalance(BalanceType.AVAILABLE);
            builder.append(String.format("Wallet containing %s BTC (available: %s BTC) in:%n",
                    bitcoinValueToPlainString(estimatedBalance), bitcoinValueToPlainString(availableBalance)));
            builder.append(String.format("  %d pending transactions%n", pending.size()));
            builder.append(String.format("  %d unspent transactions%n", unspent.size()));
            builder.append(String.format("  %d spent transactions%n", spent.size()));
            builder.append(String.format("  %d dead transactions%n", dead.size()));
            final Date lastBlockSeenTime = getLastBlockSeenTime();
            final String lastBlockSeenTimeStr = lastBlockSeenTime == null ? "time unknown" : lastBlockSeenTime.toString();
            builder.append(String.format("Last seen best block: %d (%s): %s%n",
                    getLastBlockSeenHeight(), lastBlockSeenTimeStr, getLastBlockSeenHash()));
            if (this.keyCrypter != null) {
                builder.append(String.format("Encryption: %s%n", keyCrypter.toString()));
            }
            // Do the keys.
            builder.append("\nKeys:\n");
            for (ECKey key : keychain) {
                final Address address = key.toAddress(params);
                builder.append("  addr:");
                builder.append(address.toString());
                builder.append(" hash160:");
                builder.append(Utils.bytesToHexString(address.getHash160()));
                builder.append(" ");
                builder.append(includePrivateKeys ? key.toStringWithPrivate() : key.toString());
                builder.append("\n");
            }

            if (!watchedScripts.isEmpty()) {
                builder.append("\nWatched scripts:\n");
                for (Script script : watchedScripts) {
                    builder.append("  ");
                    builder.append(script.toString());
                    builder.append("\n");
                }
            }

            if (includeTransactions) {
                // Print the transactions themselves
                if (pending.size() > 0) {
                    builder.append("\n>>> PENDING:\n");
                    toStringHelper(builder, pending, chain, SORT_ORDER_BY_UPDATE_TIME);
                }
                if (unspent.size() > 0) {
                    builder.append("\n>>> UNSPENT:\n");
                    toStringHelper(builder, unspent, chain, SORT_ORDER_BY_HEIGHT);
                }
                if (spent.size() > 0) {
                    builder.append("\n>>> SPENT:\n");
                    toStringHelper(builder, spent, chain, SORT_ORDER_BY_HEIGHT);
                }
                if (dead.size() > 0) {
                    builder.append("\n>>> DEAD:\n");
                    toStringHelper(builder, dead, chain, SORT_ORDER_BY_HEIGHT);
                }
            }
            if (includeExtensions && extensions.size() > 0) {
                builder.append("\n>>> EXTENSIONS:\n");
                for (WalletExtension extension : extensions.values()) {
                    builder.append(extension).append("\n\n");
                }
            }
            return builder.toString();
        } finally {
            lock.unlock();
        }
    }

    private void toStringHelper(StringBuilder builder, Map<Sha256Hash, Transaction> transactionMap,
                                @Nullable AbstractBlockChain chain, @Nullable Comparator<Transaction> sortOrder) {
        checkState(lock.isHeldByCurrentThread());

        final Collection<Transaction> txns;
        if (sortOrder != null) {
            txns = new TreeSet<Transaction>(sortOrder);
            txns.addAll(transactionMap.values());
        } else {
            txns = transactionMap.values();
        }

        for (Transaction tx : txns) {
            try {
                builder.append("Sends ");
                builder.append(Utils.bitcoinValueToFriendlyString(tx.getValueSentFromMe(this)));
                builder.append(" and receives ");
                builder.append(Utils.bitcoinValueToFriendlyString(tx.getValueSentToMe(this)));
                builder.append(", total value ");
                builder.append(Utils.bitcoinValueToFriendlyString(tx.getValue(this)));
                builder.append(".\n");
            } catch (ScriptException e) {
                // Ignore and don't print this line.
            }
            builder.append(tx.toString(chain));
        }
    }

    private static class TxOffsetPair implements Comparable<TxOffsetPair> {
        public final Transaction tx;
        public final int offset;

        public TxOffsetPair(Transaction tx, int offset) {
            this.tx = tx;
            this.offset = offset;
        }

        @Override public int compareTo(TxOffsetPair o) {
            return Ints.compare(offset, o.offset);
        }
    }

    /**
     * <p>Don't call this directly. It's not intended for API users.</p>
     *
     * <p>Called by the {@link BlockChain} when the best chain (representing total work done) has changed. This can
     * cause the number of confirmations of a transaction to go higher, lower, drop to zero and can even result in
     * a transaction going dead (will never confirm) due to a double spend.</p>
     *
     * <p>The oldBlocks/newBlocks lists are ordered height-wise from top first to bottom last.</p>
     */
    public void reorganize(StoredBlock splitPoint, List<StoredBlock> oldBlocks, List<StoredBlock> newBlocks) throws VerificationException {
        lock.lock();
        try {
            // This runs on any peer thread with the block chain locked.
            //
            // The reorganize functionality of the wallet is tested in ChainSplitTest.java
            //
            // receive() has been called on the block that is triggering the re-org before this is called, with type
            // of SIDE_CHAIN.
            //
            // Note that this code assumes blocks are not invalid - if blocks contain duplicated transactions,
            // transactions that double spend etc then we can calculate the incorrect result. This could open up
            // obscure DoS attacks if someone successfully mines a throwaway invalid block and feeds it to us, just
            // to try and corrupt the internal data structures. We should try harder to avoid this but it's tricky
            // because there are so many ways the block can be invalid.

            // Avoid spuriously informing the user of wallet/tx confidence changes whilst we're re-organizing.
            checkState(confidenceChanged.size() == 0);
            checkState(!insideReorg);
            insideReorg = true;
            checkState(onWalletChangedSuppressions == 0);
            onWalletChangedSuppressions++;

            // Map block hash to transactions that appear in it. We ensure that the map values are sorted according
            // to their relative position within those blocks.
            ArrayListMultimap<Sha256Hash, TxOffsetPair> mapBlockTx = ArrayListMultimap.create();
            for (Transaction tx : getTransactions(true)) {
                Map<Sha256Hash, Integer> appearsIn = tx.getAppearsInHashes();
                if (appearsIn == null) continue;  // Pending.
                for (Map.Entry<Sha256Hash, Integer> block : appearsIn.entrySet())
                    mapBlockTx.put(block.getKey(), new TxOffsetPair(tx, block.getValue()));
            }
            for (Sha256Hash blockHash : mapBlockTx.keySet())
                Collections.sort(mapBlockTx.get(blockHash));

            List<Sha256Hash> oldBlockHashes = new ArrayList<Sha256Hash>(oldBlocks.size());
            log.info("Old part of chain (top to bottom):");
            for (StoredBlock b : oldBlocks) {
                log.info("  {}", b.getHeader().getHashAsString());
                oldBlockHashes.add(b.getHeader().getHash());
            }
            log.info("New part of chain (top to bottom):");
            for (StoredBlock b : newBlocks) {
                log.info("  {}", b.getHeader().getHashAsString());
            }

            Collections.reverse(newBlocks);  // Need bottom-to-top but we get top-to-bottom.

            // For each block in the old chain, disconnect the transactions in reverse order.
            LinkedList<Transaction> oldChainTxns = Lists.newLinkedList();
            for (Sha256Hash blockHash : oldBlockHashes) {
                for (TxOffsetPair pair : mapBlockTx.get(blockHash)) {
                    Transaction tx = pair.tx;
                    final Sha256Hash txHash = tx.getHash();
                    if (tx.isCoinBase()) {
                        // All the transactions that we have in our wallet which spent this coinbase are now invalid
                        // and will never confirm. Hopefully this should never happen - that's the point of the maturity
                        // rule that forbids spending of coinbase transactions for 100 blocks.
                        //
                        // This could be recursive, although of course because we don't have the full transaction
                        // graph we can never reliably kill all transactions we might have that were rooted in
                        // this coinbase tx. Some can just go pending forever, like the Satoshi client. However we
                        // can do our best.
                        //
                        // TODO: Is it better to try and sometimes fail, or not try at all?
                        killCoinbase(tx);
                    } else {
                        for (TransactionOutput output : tx.getOutputs()) {
                            TransactionInput input = output.getSpentBy();
                            if (input != null) input.disconnect();
                        }
                        for (TransactionInput input : tx.getInputs()) {
                            input.disconnect();
                        }
                        oldChainTxns.add(tx);
                        unspent.remove(txHash);
                        spent.remove(txHash);
                        checkState(!pending.containsKey(txHash));
                        checkState(!dead.containsKey(txHash));
                    }
                }
            }

            // Put all the disconnected transactions back into the pending pool and re-connect them.
            for (Transaction tx : oldChainTxns) {
                // Coinbase transactions on the old part of the chain are dead for good and won't come back unless
                // there's another re-org.
                if (tx.isCoinBase()) continue;
                log.info("  ->pending {}", tx.getHash());
                tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);  // Wipe height/depth/work data.
                confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.TYPE);
                addWalletTransaction(Pool.PENDING, tx);
                updateForSpends(tx, false);
            }

            // Note that dead transactions stay dead. Consider a chain that Finney attacks T1 and replaces it with
            // T2, so we move T1 into the dead pool. If there's now a re-org to a chain that doesn't include T2, it
            // doesn't matter - the miners deleted T1 from their mempool, will resurrect T2 and put that into the
            // mempool and so T1 is still seen as a losing double spend.

            // The old blocks have contributed to the depth and work done for all the transactions in the
            // wallet that are in blocks up to and including the chain split block.
            // The total depth and work done is calculated here and then subtracted from the appropriate transactions.
            int depthToSubtract = oldBlocks.size();
            BigInteger workDoneToSubtract = BigInteger.ZERO;
            for (StoredBlock b : oldBlocks) {
                workDoneToSubtract = workDoneToSubtract.add(b.getHeader().getWork());
            }
            log.info("depthToSubtract = " + depthToSubtract + ", workDoneToSubtract = " + workDoneToSubtract);
            // Remove depthToSubtract and workDoneToSubtract from all transactions in the wallet except for pending.
            subtractDepthAndWorkDone(depthToSubtract, workDoneToSubtract, spent.values());
            subtractDepthAndWorkDone(depthToSubtract, workDoneToSubtract, unspent.values());
            subtractDepthAndWorkDone(depthToSubtract, workDoneToSubtract, dead.values());

            // The effective last seen block is now the split point so set the lastSeenBlockHash.
            setLastBlockSeenHash(splitPoint.getHeader().getHash());

            // For each block in the new chain, work forwards calling receive() and notifyNewBestBlock().
            // This will pull them back out of the pending pool, or if the tx didn't appear in the old chain and
            // does appear in the new chain, will treat it as such and possibly kill pending transactions that
            // conflict.
            for (StoredBlock block : newBlocks) {
                log.info("Replaying block {}", block.getHeader().getHashAsString());
                for (TxOffsetPair pair : mapBlockTx.get(block.getHeader().getHash())) {
                    log.info("  tx {}", pair.tx.getHash());
                    try {
                        receive(pair.tx, block, BlockChain.NewBlockType.BEST_CHAIN, pair.offset);
                    } catch (ScriptException e) {
                        throw new RuntimeException(e);  // Cannot happen as these blocks were already verified.
                    }
                }
                notifyNewBestBlock(block);
            }
            checkState(isConsistent());
            final BigInteger balance = getBalance();
            log.info("post-reorg balance is {}", Utils.bitcoinValueToFriendlyString(balance));
            // Inform event listeners that a re-org took place.
            queueOnReorganize();
            insideReorg = false;
            onWalletChangedSuppressions--;
            maybeQueueOnWalletChanged();
            checkBalanceFuturesLocked(balance);
            informConfidenceListenersIfNotReorganizing();
            saveLater();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Subtract the supplied depth and work done from the given transactions.
     */
    private void subtractDepthAndWorkDone(int depthToSubtract, BigInteger workDoneToSubtract,
                                          Collection<Transaction> transactions) {
        for (Transaction tx : transactions) {
            if (tx.getConfidence().getConfidenceType() == ConfidenceType.BUILDING) {
                tx.getConfidence().setDepthInBlocks(tx.getConfidence().getDepthInBlocks() - depthToSubtract);
                tx.getConfidence().setWorkDone(tx.getConfidence().getWorkDone().subtract(workDoneToSubtract));
                confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.DEPTH);
            }
        }
    }

    /**
     * Returns an immutable view of the transactions currently waiting for network confirmations.
     */
    public Collection<Transaction> getPendingTransactions() {
        lock.lock();
        try {
            return Collections.unmodifiableCollection(pending.values());
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the earliest creation time of keys or watched scripts in this wallet, in seconds since the epoch, ie the min
     * of {@link com.google.bitcoin.core.ECKey#getCreationTimeSeconds()}. This can return zero if at least one key does
     * not have that data (was created before key timestamping was implemented). <p>
     *     
     * This method is most often used in conjunction with {@link PeerGroup#setFastCatchupTimeSecs(long)} in order to
     * optimize chain download for new users of wallet apps. Backwards compatibility notice: if you get zero from this
     * method, you can instead use the time of the first release of your software, as it's guaranteed no users will
     * have wallets pre-dating this time. <p>
     * 
     * If there are no keys in the wallet, the current time is returned.
     */
    @Override
    public long getEarliestKeyCreationTime() {
        lock.lock();
        try {
            long earliestTime = Long.MAX_VALUE;
            for (ECKey key : keychain)
                earliestTime = Math.min(key.getCreationTimeSeconds(), earliestTime);
            for (Script script : watchedScripts)
                earliestTime = Math.min(script.getCreationTimeSeconds(), earliestTime);
            if (earliestTime == Long.MAX_VALUE)
                return Utils.currentTimeMillis() / 1000;
            return earliestTime;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the hash of the last seen best-chain block, or null if the wallet is too old to store this data. */
    @Nullable
    public Sha256Hash getLastBlockSeenHash() {
        lock.lock();
        try {
            return lastBlockSeenHash;
        } finally {
            lock.unlock();
        }
    }

    public void setLastBlockSeenHash(@Nullable Sha256Hash lastBlockSeenHash) {
        lock.lock();
        try {
            this.lastBlockSeenHash = lastBlockSeenHash;
        } finally {
            lock.unlock();
        }
    }

    public void setLastBlockSeenHeight(int lastBlockSeenHeight) {
        lock.lock();
        try {
            this.lastBlockSeenHeight = lastBlockSeenHeight;
        } finally {
            lock.unlock();
        }
    }

    public void setLastBlockSeenTimeSecs(long timeSecs) {
        lock.lock();
        try {
            lastBlockSeenTimeSecs = timeSecs;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the UNIX time in seconds since the epoch extracted from the last best seen block header. This timestamp
     * is <b>not</b> the local time at which the block was first observed by this application but rather what the block
     * (i.e. miner) self declares. It is allowed to have some significant drift from the real time at which the block
     * was found, although most miners do use accurate times. If this wallet is old and does not have a recorded
     * time then this method returns zero.
     */
    public long getLastBlockSeenTimeSecs() {
        lock.lock();
        try {
            return lastBlockSeenTimeSecs;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a {@link Date} representing the time extracted from the last best seen block header. This timestamp
     * is <b>not</b> the local time at which the block was first observed by this application but rather what the block
     * (i.e. miner) self declares. It is allowed to have some significant drift from the real time at which the block
     * was found, although most miners do use accurate times. If this wallet is old and does not have a recorded
     * time then this method returns null.
     */
    @Nullable
    public Date getLastBlockSeenTime() {
        final long secs = getLastBlockSeenTimeSecs();
        if (secs == 0)
            return null;
        else
            return new Date(secs * 1000);
    }

    /**
     * Returns the height of the last seen best-chain block. Can be 0 if a wallet is brand new or -1 if the wallet
     * is old and doesn't have that data.
     */
    public int getLastBlockSeenHeight() {
        lock.lock();
        try {
            return lastBlockSeenHeight;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Convenience wrapper around {@link Wallet#encrypt(com.google.bitcoin.crypto.KeyCrypter,
     * org.spongycastle.crypto.params.KeyParameter)} which uses the default Scrypt key derivation algorithm and
     * parameters, derives a key from the given password and returns the created key.
     */
    public KeyParameter encrypt(CharSequence password) {
        checkNotNull(password);
        checkArgument(password.length() > 0);
        KeyCrypter scrypt = new KeyCrypterScrypt();
        KeyParameter derivedKey = scrypt.deriveKey(password);
        encrypt(scrypt, derivedKey);
        return derivedKey;
    }

    /**
     * Encrypt the wallet using the KeyCrypter and the AES key. A good default KeyCrypter to use is
     * {@link com.google.bitcoin.crypto.KeyCrypterScrypt}.
     *
     * @param keyCrypter The KeyCrypter that specifies how to encrypt/ decrypt a key
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming to create from a password)
     * @throws KeyCrypterException Thrown if the wallet encryption fails. If so, the wallet state is unchanged.
     */
    public void encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        lock.lock();
        try {
            checkNotNull(keyCrypter);
            checkState(getEncryptionType() == EncryptionType.UNENCRYPTED, "Wallet is already encrypted");
            // Create a new arraylist that will contain the encrypted keys
            ArrayList<ECKey> encryptedKeyChain = new ArrayList<ECKey>();
            for (ECKey key : keychain) {
                if (key.isEncrypted()) {
                    // Key is already encrypted - add as is.
                    encryptedKeyChain.add(key);
                } else {
                    // Encrypt the key.
                    ECKey encryptedKey = key.encrypt(keyCrypter, aesKey);

                    // Check that the encrypted key can be successfully decrypted.
                    // This is done as it is a critical failure if the private key cannot be decrypted successfully
                    // (all bitcoin controlled by that private key is lost forever).
                    // For a correctly constructed keyCrypter the encryption should always be reversible so it is just being as cautious as possible.
                    if (!ECKey.encryptionIsReversible(key, encryptedKey, keyCrypter, aesKey)) {
                        // Abort encryption
                        throw new KeyCrypterException("The key " + key.toString() + " cannot be successfully decrypted after encryption so aborting wallet encryption.");
                    }

                    encryptedKeyChain.add(encryptedKey);
                }
            }

            // Now ready to use the encrypted keychain so go through the old keychain clearing all the unencrypted private keys.
            // (This is to avoid the possibility of key recovery from memory).
            for (ECKey key : keychain) {
                if (!key.isEncrypted()) {
                    key.clearPrivateKey();
                }
            }

            // Replace the old keychain with the encrypted one.
            keychain = encryptedKeyChain;

            // The wallet is now encrypted.
            this.keyCrypter = keyCrypter;

            saveNow();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Decrypt the wallet with the wallets keyCrypter and AES key.
     *
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming to create from a password)
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
    public void decrypt(KeyParameter aesKey) {
        lock.lock();
        try {
            // Check the wallet is already encrypted - you cannot decrypt an unencrypted wallet.
            checkState(getEncryptionType() != EncryptionType.UNENCRYPTED, "Wallet is already decrypted");
            // Check that the wallet keyCrypter is non-null.
            // This is set either at construction (if an encrypted wallet is created) or by wallet encryption.
            checkNotNull(keyCrypter);

            // Create a new arraylist that will contain the decrypted keys
            ArrayList<ECKey> decryptedKeyChain = new ArrayList<ECKey>();

            for (ECKey key : keychain) {
                // Decrypt the key.
                if (!key.isEncrypted()) {
                    // Not encrypted - add to chain as is.
                    decryptedKeyChain.add(key);
                } else {
                    ECKey decryptedECKey = key.decrypt(keyCrypter, aesKey);
                    decryptedKeyChain.add(decryptedECKey);
                }
            }

            // Replace the old keychain with the unencrypted one.
            keychain = decryptedKeyChain;

            // The wallet is now unencrypted.
            keyCrypter = null;
            saveNow();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Create a new, random encrypted ECKey and add it to the wallet.
     *
     * @param keyCrypter The keyCrypter to use in encrypting the new key
     * @param aesKey The AES key to use to encrypt the new key
     * @return ECKey the new, encrypted ECKey
     */
    public ECKey addNewEncryptedKey(KeyCrypter keyCrypter, KeyParameter aesKey) {
        ECKey newKey = (new ECKey()).encrypt(checkNotNull(keyCrypter), checkNotNull(aesKey));
        addKey(newKey);
        return newKey;
    }

    /**
     * <p>Convenience wrapper around {@link Wallet#addNewEncryptedKey(com.google.bitcoin.crypto.KeyCrypter,
     * org.spongycastle.crypto.params.KeyParameter)} which just derives the key afresh and uses the pre-set
     * keycrypter. The wallet must have been encrypted using one of the encrypt methods previously.</p>
     *
     * <p>Note that key derivation is deliberately very slow! So if you plan to add multiple keys, it can be
     * faster to use the other method instead and re-use the {@link KeyParameter} object instead.</p>
     */
    public ECKey addNewEncryptedKey(CharSequence password) {
        lock.lock();
        try {
            checkNotNull(keyCrypter, "Wallet is not encrypted, you must call encrypt() first.");
            return addNewEncryptedKey(keyCrypter, keyCrypter.deriveKey(password));
        } finally {
            lock.unlock();
        }
    }

    /**
     *  Check whether the password can decrypt the first key in the wallet.
     *  This can be used to check the validity of an entered password.
     *
     *  @return boolean true if password supplied can decrypt the first private key in the wallet, false otherwise.
     */
    public boolean checkPassword(CharSequence password) {
        lock.lock();
        try {
            return keyCrypter != null && checkAESKey(keyCrypter.deriveKey(checkNotNull(password)));
        } finally {
            lock.unlock();
        }
    }

    /**
     *  Check whether the AES key can decrypt the first encrypted key in the wallet.
     *
     *  @return boolean true if AES key supplied can decrypt the first encrypted private key in the wallet, false otherwise.
     */
    public boolean checkAESKey(KeyParameter aesKey) {
        lock.lock();
        try {
            // If no keys then cannot decrypt.
            if (!getKeys().iterator().hasNext())
                return false;
            // Find the first encrypted key in the wallet.
            ECKey firstEncryptedECKey = null;
            Iterator<ECKey> iterator = getKeys().iterator();
            while (iterator.hasNext() && firstEncryptedECKey == null) {
                ECKey loopECKey = iterator.next();
                if (loopECKey.isEncrypted()) {
                    firstEncryptedECKey = loopECKey;
                }
            }
            // There are no encrypted keys in the wallet.
            if (firstEncryptedECKey == null)
                return false;
            String originalAddress = firstEncryptedECKey.toAddress(getNetworkParameters()).toString();
            if (firstEncryptedECKey.isEncrypted() && firstEncryptedECKey.getEncryptedPrivateKey() != null) {
                try {
                    ECKey rebornKey = firstEncryptedECKey.decrypt(keyCrypter, aesKey);

                    // Check that the decrypted private key's address is correct ie it decrypted accurately.
                    String rebornAddress = rebornKey.toAddress(getNetworkParameters()).toString();
                    return originalAddress.equals(rebornAddress);
                } catch (KeyCrypterException ede) {
                    // The AES key supplied is incorrect.
                    return false;
                }
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Get the wallet's KeyCrypter.
     * (Used in encrypting/ decrypting an ECKey).
     */
    public KeyCrypter getKeyCrypter() {
        lock.lock();
        try {
            return keyCrypter;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets the wallet's KeyCrypter.
     * Note that this does not encrypt the wallet, and should only be used if the keyCrypter can not be included in the
     * constructor during initial wallet loading.
     * Note that if the keyCrypter was not properly set during wallet load, {@link Wallet#getEncryptionType()} and
     * {@link Wallet#isEncrypted()} will not return the correct results.
     */
    public void setKeyCrypter(KeyCrypter keyCrypter) {
        lock.lock();
        try {
            checkState(this.keyCrypter == null);
            this.keyCrypter = keyCrypter;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Get the type of encryption used for this wallet.
     *
     * (This is a convenience method - the encryption type is actually stored in the keyCrypter).
     */
    public EncryptionType getEncryptionType() {
        lock.lock();
        try {
            if (keyCrypter == null) {
                // Unencrypted wallet.
                return EncryptionType.UNENCRYPTED;
            } else {
                return keyCrypter.getUnderstoodEncryptionType();
            }
        } finally {
            lock.unlock();
        }
    }

    /** Returns true if the wallet is encrypted using any scheme, false if not. */
    public boolean isEncrypted() {
        return getEncryptionType() != EncryptionType.UNENCRYPTED;
    }

    /**
     * Get the version of the Wallet.
     * This is an int you can use to indicate which versions of wallets your code understands,
     * and which come from the future (and hence cannot be safely loaded).
     */
    public int getVersion() {
        return version;
    }

    /**
     * Set the version number of the wallet. See {@link Wallet#getVersion()}.
     */
    public void setVersion(int version) {
        this.version = version;
    }

    /**
     * Set the description of the wallet.
     * This is a Unicode encoding string typically entered by the user as descriptive text for the wallet.
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Get the description of the wallet. See {@link Wallet#setDescription(String))}
     */
    public String getDescription() {
        return description;
    }

    @Override
    public int getBloomFilterElementCount() {
        int size = getKeychainSize() * 2;
        for (Transaction tx : getTransactions(false)) {
            for (TransactionOutput out : tx.getOutputs()) {
                try {
                    if (isTxOutputBloomFilterable(out))
                        size++;
                } catch (ScriptException e) {
                    throw new RuntimeException(e); // If it is ours, we parsed the script correctly, so this shouldn't happen
                }
            }
        }

        // Some scripts may have more than one bloom element.  That should normally be okay,
        // because under-counting just increases false-positive rate.
        size += watchedScripts.size();

        return size;
    }

    /**
     * If we are watching any scripts, the bloom filter must update on peers whenever an output is
     * identified.  This is because we don't necessarily have the associated pubkey, so we can't
     * watch for it on spending transactions.
     */
    @Override
    public boolean isRequiringUpdateAllBloomFilter() {
        return !watchedScripts.isEmpty();
    }

    /**
     * Gets a bloom filter that contains all of the public keys from this wallet, and which will provide the given
     * false-positive rate. See the docs for {@link BloomFilter} for a brief explanation of anonymity when using filters.
     */
    public BloomFilter getBloomFilter(double falsePositiveRate) {
        return getBloomFilter(getBloomFilterElementCount(), falsePositiveRate, (long)(Math.random()*Long.MAX_VALUE));
    }

    /**
     * Gets a bloom filter that contains all of the public keys from this wallet,
     * and which will provide the given false-positive rate if it has size elements.
     * Keep in mind that you will get 2 elements in the bloom filter for each key in the wallet.
     * 
     * This is used to generate a BloomFilter which can be #{link BloomFilter.merge}d with another.
     * It could also be used if you have a specific target for the filter's size.
     * 
     * See the docs for {@link BloomFilter(int, double)} for a brief explanation of anonymity when using bloom filters.
     */
    @Override
    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
        BloomFilter filter = new BloomFilter(size, falsePositiveRate, nTweak);
        lock.lock();
        try {
            for (ECKey key : keychain) {
                filter.insert(key.getPubKey());
                filter.insert(key.getPubKeyHash());
            }

            for (Script script : watchedScripts) {
                for (ScriptChunk chunk : script.getChunks()) {
                    // Only add long (at least 64 bit) data to the bloom filter.
                    // If any long constants become popular in scripts, we will need logic
                    // here to exclude them.
                    if (!chunk.isOpCode() && chunk.data.length >= MINIMUM_BLOOM_DATA_LENGTH) {
                        filter.insert(chunk.data);
                    }
                }
            }
        } finally {
            lock.unlock();
        }
        for (Transaction tx : getTransactions(false)) {
            for (int i = 0; i < tx.getOutputs().size(); i++) {
                TransactionOutput out = tx.getOutputs().get(i);
                try {
                    if (isTxOutputBloomFilterable(out)) {
                        TransactionOutPoint outPoint = new TransactionOutPoint(params, i, tx);
                        filter.insert(outPoint.bitcoinSerialize());
                    }
                } catch (ScriptException e) {
                    throw new RuntimeException(e); // If it is ours, we parsed the script correctly, so this shouldn't happen
                }
            }
        }

        return filter;
    }

    private boolean isTxOutputBloomFilterable(TransactionOutput out) {
        return (out.isMine(this) && out.getScriptPubKey().isSentToRawPubKey()) ||
                out.isWatched(this);
    }

    /** Returns the {@link CoinSelector} object which controls which outputs can be spent by this wallet. */
    public CoinSelector getCoinSelector() {
        lock.lock();
        try {
            return coinSelector;
        } finally {
            lock.unlock();
        }
    }

    /**
     * A coin selector is responsible for choosing which outputs to spend when creating transactions. The default
     * selector implements a policy of spending transactions that appeared in the best chain and pending transactions
     * that were created by this wallet, but not others. You can override the coin selector for any given send
     * operation by changing {@link Wallet.SendRequest#coinSelector}.
     */
    public void setCoinSelector(@Nonnull CoinSelector coinSelector) {
        lock.lock();
        try {
            this.coinSelector = checkNotNull(coinSelector);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Convenience wrapper for <tt>setCoinSelector(Wallet.AllowUnconfirmedCoinSelector.get())</tt>. If this method
     * is called on the wallet then transactions will be used for spending regardless of their confidence. This can
     * be dangerous - only use this if you absolutely know what you're doing!
     */
    public void allowSpendingUnconfirmedTransactions() {
        setCoinSelector(AllowUnconfirmedCoinSelector.get());
    }

    private static class BalanceFutureRequest {
        public SettableFuture<BigInteger> future;
        public BigInteger value;
        public BalanceType type;
    }
    @GuardedBy("lock") private List<BalanceFutureRequest> balanceFutureRequests = Lists.newLinkedList();

    /**
     * <p>Returns a future that will complete when the balance of the given type has becom equal or larger to the given
     * value. If the wallet already has a large enough balance the future is returned in a pre-completed state. Note
     * that this method is not blocking, if you want to actually wait immediately, you have to call .get() on
     * the result.</p>
     *
     * <p>Also note that by the time the future completes, the wallet may have changed yet again if something else
     * is going on in parallel, so you should treat the returned balance as advisory and be prepared for sending
     * money to fail! Finally please be aware that any listeners on the future will run either on the calling thread
     * if it completes immediately, or eventually on a background thread if the balance is not yet at the right
     * level. If you do something that means you know the balance should be sufficient to trigger the future,
     * you can use {@link com.google.bitcoin.utils.Threading#waitForUserCode()} to block until the future had a
     * chance to be updated.</p>
     */
    public ListenableFuture<BigInteger> getBalanceFuture(final BigInteger value, final BalanceType type) {
        lock.lock();
        try {
            final SettableFuture<BigInteger> future = SettableFuture.create();
            final BigInteger current = getBalance(type);
            if (current.compareTo(value) >= 0) {
                // Already have enough.
                future.set(current);
            } else {
                // Will be checked later in checkBalanceFutures. We don't just add an event listener for ourselves
                // here so that running getBalanceFuture().get() in the user code thread works - generally we must
                // avoid giving the user back futures that require the user code thread to be free.
                BalanceFutureRequest req = new BalanceFutureRequest();
                req.future = future;
                req.value = value;
                req.type = type;
                balanceFutureRequests.add(req);
            }
            return future;
        } finally {
            lock.unlock();
        }
    }

    // Runs any balance futures in the user code thread.
    private void checkBalanceFuturesLocked(@Nullable BigInteger avail) {
        checkState(lock.isHeldByCurrentThread());
        BigInteger estimated = null;
        final ListIterator<BalanceFutureRequest> it = balanceFutureRequests.listIterator();
        while (it.hasNext()) {
            final BalanceFutureRequest req = it.next();
            BigInteger val = null;
            if (req.type == BalanceType.AVAILABLE) {
                if (avail == null) avail = getBalance(BalanceType.AVAILABLE);
                if (avail.compareTo(req.value) < 0) continue;
                val = avail;
            } else if (req.type == BalanceType.ESTIMATED) {
                if (estimated == null) estimated = getBalance(BalanceType.ESTIMATED);
                if (estimated.compareTo(req.value) < 0) continue;
                val = estimated;
            }
            // Found one that's finished.
            it.remove();
            final BigInteger v = checkNotNull(val);
            // Don't run any user-provided future listeners with our lock held.
            Threading.USER_THREAD.execute(new Runnable() {
                @Override public void run() {
                    req.future.set(v);
                }
            });
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Extensions to the wallet format.

    /**
     * By providing an object implementing the {@link WalletExtension} interface, you can save and load arbitrary
     * additional data that will be stored with the wallet. Each extension is identified by an ID, so attempting to
     * add the same extension twice (or two different objects that use the same ID) will throw an IllegalStateException.
     */
    public void addExtension(WalletExtension extension) {
        String id = checkNotNull(extension).getWalletExtensionID();
        lock.lock();
        try {
            if (extensions.containsKey(id))
                throw new IllegalStateException("Cannot add two extensions with the same ID: " + id);
            extensions.put(id, extension);
            saveNow();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically adds extension or returns an existing extension if there is one with the same id alreadypresent.
     */
    public WalletExtension addOrGetExistingExtension(WalletExtension extension) {
        String id = checkNotNull(extension).getWalletExtensionID();
        lock.lock();
        try {
            WalletExtension previousExtension = extensions.get(id);
            if (previousExtension != null)
                return previousExtension;
            extensions.put(id, extension);
            saveNow();
            return extension;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Either adds extension as a new extension or replaces the existing extension if one already exists with the same
     * id. This also triggers wallet auto-saving, so may be useful even when called with the same extension as is
     * already present.
     */
    public void addOrUpdateExtension(WalletExtension extension) {
        String id = checkNotNull(extension).getWalletExtensionID();
        lock.lock();
        try {
            extensions.put(id, extension);
            saveNow();
        } finally {
            lock.unlock();
        }
    }

    /** Returns a snapshot of all registered extension objects. The extensions themselves are not copied. */
    public Map<String, WalletExtension> getExtensions() {
        lock.lock();
        try {
            return ImmutableMap.copyOf(extensions);
        } finally {
            lock.unlock();
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Boilerplate for running event listeners - dispatches events onto the user code thread (where we don't do
    // anything and hold no locks).

    private void queueOnTransactionConfidenceChanged(final Transaction tx) {
        checkState(lock.isHeldByCurrentThread());
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            if (registration.executor == Threading.SAME_THREAD) {
                registration.listener.onTransactionConfidenceChanged(this, tx);
            } else {
                registration.executor.execute(new Runnable() {
                    @Override
                    public void run() {
                        registration.listener.onTransactionConfidenceChanged(Wallet.this, tx);
                    }
                });
            }
        }
    }

    private void maybeQueueOnWalletChanged() {
        // Don't invoke the callback in some circumstances, eg, whilst we are re-organizing or fiddling with
        // transactions due to a new block arriving. It will be called later instead.
        checkState(lock.isHeldByCurrentThread());
        checkState(onWalletChangedSuppressions >= 0);
        if (onWalletChangedSuppressions > 0) return;
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onWalletChanged(Wallet.this);
                }
            });
        }
    }

    private void queueOnCoinsReceived(final Transaction tx, final BigInteger balance, final BigInteger newBalance) {
        checkState(lock.isHeldByCurrentThread());
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onCoinsReceived(Wallet.this, tx, balance, newBalance);
                }
            });
        }
    }

    private void queueOnCoinsSent(final Transaction tx, final BigInteger prevBalance, final BigInteger newBalance) {
        checkState(lock.isHeldByCurrentThread());
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onCoinsSent(Wallet.this, tx, prevBalance, newBalance);
                }
            });
        }
    }

    private void queueOnReorganize() {
        checkState(lock.isHeldByCurrentThread());
        checkState(insideReorg);
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onReorganize(Wallet.this);
                }
            });
        }
    }

    private void queueOnKeysAdded(final List<ECKey> keys) {
        checkState(lock.isHeldByCurrentThread());
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onKeysAdded(Wallet.this, keys);
                }
            });
        }
    }

    private void queueOnScriptsAdded(final List<Script> scripts) {
        checkState(lock.isHeldByCurrentThread());
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onScriptsAdded(Wallet.this, scripts);
                }
            });
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Fee calculation code.

    private class FeeCalculation {
        private CoinSelection bestCoinSelection;
        private TransactionOutput bestChangeOutput;

        public FeeCalculation(SendRequest req, BigInteger value, List<TransactionInput> originalInputs,
                              boolean needAtLeastReferenceFee, LinkedList<TransactionOutput> candidates) throws InsufficientMoneyException {
            checkState(lock.isHeldByCurrentThread());
            // There are 3 possibilities for what adding change might do:
            // 1) No effect
            // 2) Causes increase in fee (change < 0.01 COINS)
            // 3) Causes the transaction to have a dust output or change < fee increase (ie change will be thrown away)
            // If we get either of the last 2, we keep note of what the inputs looked like at the time and try to
            // add inputs as we go up the list (keeping track of minimum inputs for each category).  At the end, we pick
            // the best input set as the one which generates the lowest total fee.
            BigInteger additionalValueForNextCategory = null;
            CoinSelection selection3 = null;
            CoinSelection selection2 = null;
            TransactionOutput selection2Change = null;
            CoinSelection selection1 = null;
            TransactionOutput selection1Change = null;
            // We keep track of the last size of the transaction we calculated but only if the act of adding inputs and
            // change resulted in the size crossing a 1000 byte boundary. Otherwise it stays at zero.
            int lastCalculatedSize = 0;
            BigInteger valueNeeded, valueMissing = null;
            while (true) {
                resetTxInputs(req, originalInputs);

                BigInteger fees = req.fee == null ? BigInteger.ZERO : req.fee;
                if (lastCalculatedSize > 0) {
                    // If the size is exactly 1000 bytes then we'll over-pay, but this should be rare.
                    fees = fees.add(BigInteger.valueOf((lastCalculatedSize / 1000) + 1).multiply(req.feePerKb));
                } else {
                    fees = fees.add(req.feePerKb);  // First time around the loop.
                }
                if (needAtLeastReferenceFee && fees.compareTo(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE) < 0)
                    fees = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;

                valueNeeded = value.add(fees);
                if (additionalValueForNextCategory != null)
                    valueNeeded = valueNeeded.add(additionalValueForNextCategory);
                BigInteger additionalValueSelected = additionalValueForNextCategory;

                // Of the coins we could spend, pick some that we actually will spend.
                CoinSelector selector = req.coinSelector == null ? coinSelector : req.coinSelector;
                CoinSelection selection = selector.select(valueNeeded, candidates);
                // Can we afford this?
                if (selection.valueGathered.compareTo(valueNeeded) < 0) {
                    valueMissing = valueNeeded.subtract(selection.valueGathered);
                    break;
                }
                checkState(selection.gathered.size() > 0 || originalInputs.size() > 0);

                // We keep track of an upper bound on transaction size to calculate fees that need to be added.
                // Note that the difference between the upper bound and lower bound is usually small enough that it
                // will be very rare that we pay a fee we do not need to.
                //
                // We can't be sure a selection is valid until we check fee per kb at the end, so we just store
                // them here temporarily.
                boolean eitherCategory2Or3 = false;
                boolean isCategory3 = false;

                BigInteger change = selection.valueGathered.subtract(valueNeeded);
                if (additionalValueSelected != null)
                    change = change.add(additionalValueSelected);

                // If change is < 0.01 BTC, we will need to have at least minfee to be accepted by the network
                if (req.ensureMinRequiredFee && !change.equals(BigInteger.ZERO) &&
                        change.compareTo(Utils.CENT) < 0 && fees.compareTo(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE) < 0) {
                    // This solution may fit into category 2, but it may also be category 3, we'll check that later
                    eitherCategory2Or3 = true;
                    additionalValueForNextCategory = Utils.CENT;
                    // If the change is smaller than the fee we want to add, this will be negative
                    change = change.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.subtract(fees));
                }

                int size = 0;
                TransactionOutput changeOutput = null;
                if (change.compareTo(BigInteger.ZERO) > 0) {
                    // The value of the inputs is greater than what we want to send. Just like in real life then,
                    // we need to take back some coins ... this is called "change". Add another output that sends the change
                    // back to us. The address comes either from the request or getChangeAddress() as a default.
                    Address changeAddress = req.changeAddress;
                    if (changeAddress == null)
                        changeAddress = getChangeAddress();
                    changeOutput = new TransactionOutput(params, req.tx, change, changeAddress);
                    // If the change output would result in this transaction being rejected as dust, just drop the change and make it a fee
                    if (req.ensureMinRequiredFee && Transaction.MIN_NONDUST_OUTPUT.compareTo(change) >= 0) {
                        // This solution definitely fits in category 3
                        isCategory3 = true;
                        additionalValueForNextCategory = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(
                                                         Transaction.MIN_NONDUST_OUTPUT.add(BigInteger.ONE));
                    } else {
                        size += changeOutput.bitcoinSerialize().length + VarInt.sizeOf(req.tx.getOutputs().size()) - VarInt.sizeOf(req.tx.getOutputs().size() - 1);
                        // This solution is either category 1 or 2
                        if (!eitherCategory2Or3) // must be category 1
                            additionalValueForNextCategory = null;
                    }
                } else {
                    if (eitherCategory2Or3) {
                        // This solution definitely fits in category 3 (we threw away change because it was smaller than MIN_TX_FEE)
                        isCategory3 = true;
                        additionalValueForNextCategory = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(BigInteger.ONE);
                    }
                }

                // Now add unsigned inputs for the selected coins.
                for (TransactionOutput output : selection.gathered) {
                    TransactionInput input = req.tx.addInput(output);
                    // If the scriptBytes don't default to none, our size calculations will be thrown off.
                    checkState(input.getScriptBytes().length == 0);
                }

                // Estimate transaction size and loop again if we need more fee per kb. The serialized tx doesn't
                // include things we haven't added yet like input signatures/scripts or the change output.
                size += req.tx.bitcoinSerialize().length;
                size += estimateBytesForSigning(selection);
                if (size/1000 > lastCalculatedSize/1000 && req.feePerKb.compareTo(BigInteger.ZERO) > 0) {
                    lastCalculatedSize = size;
                    // We need more fees anyway, just try again with the same additional value
                    additionalValueForNextCategory = additionalValueSelected;
                    continue;
                }

                if (isCategory3) {
                    if (selection3 == null)
                        selection3 = selection;
                } else if (eitherCategory2Or3) {
                    // If we are in selection2, we will require at least CENT additional. If we do that, there is no way
                    // we can end up back here because CENT additional will always get us to 1
                    checkState(selection2 == null);
                    checkState(additionalValueForNextCategory.equals(Utils.CENT));
                    selection2 = selection;
                    selection2Change = checkNotNull(changeOutput); // If we get no change in category 2, we are actually in category 3
                } else {
                    // Once we get a category 1 (change kept), we should break out of the loop because we can't do better
                    checkState(selection1 == null);
                    checkState(additionalValueForNextCategory == null);
                    selection1 = selection;
                    selection1Change = changeOutput;
                }

                if (additionalValueForNextCategory != null) {
                    if (additionalValueSelected != null)
                        checkState(additionalValueForNextCategory.compareTo(additionalValueSelected) > 0);
                    continue;
                }
                break;
            }

            resetTxInputs(req, originalInputs);

            if (selection3 == null && selection2 == null && selection1 == null) {
                checkNotNull(valueMissing);
                log.warn("Insufficient value in wallet for send: needed {} more", bitcoinValueToFriendlyString(valueMissing));
                throw new InsufficientMoneyException(valueMissing);
            }

            BigInteger lowestFee = null;
            bestCoinSelection = null;
            bestChangeOutput = null;
            if (selection1 != null) {
                if (selection1Change != null)
                    lowestFee = selection1.valueGathered.subtract(selection1Change.getValue());
                else
                    lowestFee = selection1.valueGathered;
                bestCoinSelection = selection1;
                bestChangeOutput = selection1Change;
            }

            if (selection2 != null) {
                BigInteger fee = selection2.valueGathered.subtract(checkNotNull(selection2Change).getValue());
                if (lowestFee == null || fee.compareTo(lowestFee) < 0) {
                    lowestFee = fee;
                    bestCoinSelection = selection2;
                    bestChangeOutput = selection2Change;
                }
            }

            if (selection3 != null) {
                if (lowestFee == null || selection3.valueGathered.compareTo(lowestFee) < 0) {
                    bestCoinSelection = selection3;
                    bestChangeOutput = null;
                }
            }
        }

        private void resetTxInputs(SendRequest req, List<TransactionInput> originalInputs) {
            req.tx.clearInputs();
            for (TransactionInput input : originalInputs)
                req.tx.addInput(input);
        }
    }

    private int estimateBytesForSigning(CoinSelection selection) {
        int size = 0;
        for (TransactionOutput output : selection.gathered) {
            try {
                if (output.getScriptPubKey().isSentToAddress()) {
                    // Send-to-address spends usually take maximum pubkey.length (as it may be compressed or not) + 75 bytes
                    final ECKey key = findKeyFromPubHash(output.getScriptPubKey().getPubKeyHash());
                    size += checkNotNull(key, "Coin selection includes unspendable outputs").getPubKey().length + 75;
                } else if (output.getScriptPubKey().isSentToRawPubKey())
                    size += 74; // Send-to-pubkey spends usually take maximum 74 bytes to spend
                else
                    throw new IllegalStateException("Unknown output type returned in coin selection");
            } catch (ScriptException e) {
                // If this happens it means an output script in a wallet tx could not be understood. That should never
                // happen, if it does it means the wallet has got into an inconsistent state.
                throw new IllegalStateException(e);
            }
        }
        return size;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Managing wallet-triggered transaction broadcast and key rotation.

    /**
     * <p>Specifies that the given {@link TransactionBroadcaster}, typically a {@link PeerGroup}, should be used for
     * sending transactions to the Bitcoin network by default. Some sendCoins methods let you specify a broadcaster
     * explicitly, in that case, they don't use this broadcaster. If null is specified then the wallet won't attempt
     * to broadcast transactions itself.</p>
     *
     * <p>You don't normally need to call this. A {@link PeerGroup} will automatically set itself as the wallets
     * broadcaster when you use {@link PeerGroup#addWallet(Wallet)}. A wallet can use the broadcaster when you ask
     * it to send money, but in future also at other times to implement various features that may require asynchronous
     * re-organisation of the wallet contents on the block chain. For instance, in future the wallet may choose to
     * optimise itself to reduce fees or improve privacy.</p>
     */
    public void setTransactionBroadcaster(@Nullable com.google.bitcoin.core.TransactionBroadcaster broadcaster) {
        Transaction[] toBroadcast = {};
        lock.lock();
        try {
            if (vTransactionBroadcaster == broadcaster)
                return;
            vTransactionBroadcaster = broadcaster;
            if (broadcaster == null)
                return;
            toBroadcast = pending.values().toArray(toBroadcast);
        } finally {
            lock.unlock();
        }
        // Now use it to upload any pending transactions we have that are marked as not being seen by any peers yet.
        // Don't hold the wallet lock whilst doing this, so if the broadcaster accesses the wallet at some point there
        // is no inversion.
        for (Transaction tx : toBroadcast) {
            checkState(tx.getConfidence().getConfidenceType() == ConfidenceType.PENDING);
            // Re-broadcast even if it's marked as already seen for two reasons
            // 1) Old wallets may have transactions marked as broadcast by 1 peer when in reality the network
            //    never saw it, due to bugs.
            // 2) It can't really hurt.
            log.info("New broadcaster so uploading waiting tx {}", tx.getHash());
            broadcaster.broadcastTransaction(tx);
        }
    }

    /**
     * When a key rotation time is set, and money controlled by keys created before the given timestamp T will be
     * automatically respent to any key that was created after T. This can be used to recover from a situation where
     * a set of keys is believed to be compromised. Once the time is set transactions will be created and broadcast
     * immediately. New coins that come in after calling this method will be automatically respent immediately. The
     * rotation time is persisted to the wallet. You can stop key rotation by calling this method again with zero
     * as the argument.
     */
    public void setKeyRotationTime(Date time) {
        setKeyRotationTime(time.getTime() / 1000);
    }

    /**
     * Returns a UNIX time since the epoch in seconds, or zero if unconfigured.
     */
    public Date getKeyRotationTime() {
        return new Date(vKeyRotationTimestamp * 1000);
    }

    /**
     * <p>When a key rotation time is set, and money controlled by keys created before the given timestamp T will be
     * automatically respent to any key that was created after T. This can be used to recover from a situation where
     * a set of keys is believed to be compromised. Once the time is set transactions will be created and broadcast
     * immediately. New coins that come in after calling this method will be automatically respent immediately. The
     * rotation time is persisted to the wallet. You can stop key rotation by calling this method again with zero
     * as the argument, or by using {@link #setKeyRotationEnabled(boolean)}.</p>
     *
     * <p>Note that this method won't do anything unless you call {@link #setKeyRotationEnabled(boolean)} first.</p>
     */
    public void setKeyRotationTime(long unixTimeSeconds) {
        vKeyRotationTimestamp = unixTimeSeconds;
        if (unixTimeSeconds > 0) {
            log.info("Key rotation time set: {}", unixTimeSeconds);
            maybeRotateKeys();
        }
        saveNow();
    }

    /** Toggles key rotation on and off. Note that this state is not serialized. Activating it can trigger tx sends. */
    public void setKeyRotationEnabled(boolean enabled) {
        vKeyRotationEnabled = enabled;
        if (enabled)
            maybeRotateKeys();
    }

    /** Returns whether the keys creation time is before the key rotation time, if one was set. */
    public boolean isKeyRotating(ECKey key) {
        long time = vKeyRotationTimestamp;
        return time != 0 && key.getCreationTimeSeconds() < time;
    }

    // Checks to see if any coins are controlled by rotating keys and if so, spends them.
    private void maybeRotateKeys() {
        checkState(!lock.isHeldByCurrentThread());
        // TODO: Handle chain replays and encrypted wallets here.
        if (!vKeyRotationEnabled) return;
        // Snapshot volatiles so this method has an atomic view.
        long keyRotationTimestamp = vKeyRotationTimestamp;
        if (keyRotationTimestamp == 0) return;  // Nothing to do.
        TransactionBroadcaster broadcaster = vTransactionBroadcaster;

        // Because transactions are size limited, we might not be able to re-key the entire wallet in one go. So
        // loop around here until we no longer produce transactions with the max number of inputs. That means we're
        // fully done, at least for now (we may still get more transactions later and this method will be reinvoked).
        Transaction tx;
        do {
            tx = rekeyOneBatch(keyRotationTimestamp, broadcaster);
        } while (tx != null && tx.getInputs().size() == KeyTimeCoinSelector.MAX_SIMULTANEOUS_INPUTS);
    }

    @Nullable
    private Transaction rekeyOneBatch(long keyRotationTimestamp, final TransactionBroadcaster broadcaster) {
        final Transaction rekeyTx;

        lock.lock();
        try {
            // Firstly, see if we have any keys that are beyond the rotation time, and any before.
            ECKey safeKey = null;
            boolean haveRotatingKeys = false;
            for (ECKey key : keychain) {
                final long t = key.getCreationTimeSeconds();
                if (t < keyRotationTimestamp) {
                    haveRotatingKeys = true;
                } else {
                    safeKey = key;
                }
            }
            if (!haveRotatingKeys)
                return null;
            if (safeKey == null) {
                log.warn("Key rotation requested but no keys newer than the timestamp are available.");
                return null;
            }
            // Build the transaction using some custom logic for our special needs. Last parameter to
            // KeyTimeCoinSelector is whether to ignore pending transactions or not.
            //
            // We ignore pending outputs because trying to rotate these is basically racing an attacker, and
            // we're quite likely to lose and create stuck double spends. Also, some users who have 0.9 wallets
            // have already got stuck double spends in their wallet due to the Bloom-filtering block reordering
            // bug that was fixed in 0.10, thus, making a re-key transaction depend on those would cause it to
            // never confirm at all.
            CoinSelector selector = new KeyTimeCoinSelector(this, keyRotationTimestamp, true);
            CoinSelection toMove = selector.select(BigInteger.ZERO, calculateAllSpendCandidates(true));
            if (toMove.valueGathered.equals(BigInteger.ZERO)) return null;  // Nothing to do.
            rekeyTx = new Transaction(params);
            for (TransactionOutput output : toMove.gathered) {
                rekeyTx.addInput(output);
            }
            rekeyTx.addOutput(toMove.valueGathered, safeKey);
            if (!adjustOutputDownwardsForFee(rekeyTx, toMove, BigInteger.ZERO, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE)) {
                log.error("Failed to adjust rekey tx for fees.");
                return null;
            }
            rekeyTx.getConfidence().setSource(TransactionConfidence.Source.SELF);
            rekeyTx.setPurpose(Transaction.Purpose.KEY_ROTATION);
            rekeyTx.signInputs(Transaction.SigHash.ALL, this);
            // KeyTimeCoinSelector should never select enough inputs to push us oversize.
            checkState(rekeyTx.bitcoinSerialize().length < Transaction.MAX_STANDARD_TX_SIZE);
            commitTx(rekeyTx);
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } finally {
            lock.unlock();
        }
        if (broadcaster == null)
            return rekeyTx;

        log.info("Attempting to send key rotation tx: {}", rekeyTx);
        // We must broadcast the tx in a separate thread to avoid inverting any locks. Otherwise we may be running
        // with the blockchain lock held (whilst receiving a block) and thus re-entering the peerGroup would invert
        // blockchain <-> peergroup.
        new Thread() {
            @Override
            public void run() {
                // Handle the future results just for logging.
                try {
                    Futures.addCallback(broadcaster.broadcastTransaction(rekeyTx), new FutureCallback<Transaction>() {
                        @Override
                        public void onSuccess(Transaction transaction) {
                            log.info("Successfully broadcast key rotation tx: {}", transaction);
                        }

                        @Override
                        public void onFailure(Throwable throwable) {
                            log.error("Failed to broadcast key rotation tx", throwable);
                        }
                    });
                } catch (Exception e) {
                    log.error("Failed to broadcast rekey tx, will try again later", e);
                }
            }
        }.start();
        return rekeyTx;
    }

    /**
     * Returns the wallet lock under which most operations happen. This is here to satisfy the
     * {@link com.google.bitcoin.core.PeerFilterProvider} interface and generally should not be used directly by apps.
     * In particular, do <b>not</b> hold this lock if you're display a send confirm screen to the user or for any other
     * long length of time, as it may cause processing holdups elsewhere. Instead, for the "confirm payment screen"
     * use case you should complete a candidate transaction, present it to the user (e.g. for fee purposes) and then
     * when they confirm - which may be quite some time later - recalculate the transaction and check if it's the same.
     * If not, redisplay the confirm window and try again.
     */
    public ReentrantLock getLock() {
        return lock;
    }
}
