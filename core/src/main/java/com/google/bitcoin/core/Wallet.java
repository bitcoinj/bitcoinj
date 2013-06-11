/**
 * Copyright 2011 Google Inc.
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
import com.google.bitcoin.core.WalletTransaction.Pool;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterException;
import com.google.bitcoin.crypto.KeyCrypterScrypt;
import com.google.bitcoin.store.WalletProtobufSerializer;
import com.google.bitcoin.utils.Locks;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.collect.*;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.bitcoin.core.Utils.bitcoinValueToFriendlyString;
import static com.google.common.base.Preconditions.*;

// To do list:
//
// - Make the keychain member protected and switch it to be a hashmap of some kind so key lookup ops are faster.
// - Refactor how keys are managed to better handle things like deterministic wallets in future.
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
 * {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, com.google.bitcoin.core.Wallet.AutosaveEventListener)}
 * for more information about this.</p>
 */
public class Wallet implements Serializable, BlockChainListener {
    private static final Logger log = LoggerFactory.getLogger(Wallet.class);
    private static final long serialVersionUID = 2L;

    protected final ReentrantLock lock = Locks.lock("wallet");

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

    // A list of public/private EC keys owned by this user. Access it using addKey[s], hasKey[s] and findPubKeyFromHash.
    private ArrayList<ECKey> keychain;

    private final NetworkParameters params;

    private Sha256Hash lastBlockSeenHash;
    private int lastBlockSeenHeight = -1;

    private transient CopyOnWriteArrayList<WalletEventListener> eventListeners;

    // Auto-save code. This all should be generalized in future to not be file specific so you can easily store the
    // wallet into a database using the same mechanism. However we need to inform stores of each specific change with
    // some objects representing those changes, which is more complex. To avoid poor performance in 0.6 on phones that
    // have a lot of transactions in their wallet, we use the simpler approach. It's needed because the wallet stores
    // the number of confirmations and accumulated work done for each transaction, so each block changes each tx.
    private transient File autosaveToFile;
    private transient boolean dirty;  // Is a write of the wallet necessary?
    private transient AutosaveEventListener autosaveEventListener;
    private transient long autosaveDelayMs;

    // A listener that relays confidence changes from the transaction confidence object to the wallet event listener,
    // as a convenience to API users so they don't have to register on every transaction themselves.
    private transient TransactionConfidence.Listener txConfidenceListener;

    // If a TX hash appears in this set then notifyNewBestBlock will ignore it, as its confidence was already set up
    // in receive() via Transaction.setBlockAppearance(). As the BlockChain always calls notifyNewBestBlock even if
    // it sent transactions to the wallet, without this we'd double count.
    private transient HashSet<Sha256Hash> ignoreNextNewBlock;
    // Whether or not to ignore nLockTime > 0 transactions that are received to the mempool.
    private boolean acceptTimeLockedTransactions;

    /** Represents the results of a {@link CoinSelector#select(java.math.BigInteger, java.util.LinkedList)}  operation */
    public static class CoinSelection {
        public BigInteger valueGathered;
        public Set<TransactionOutput> gathered;
        public CoinSelection(BigInteger valueGathered, Set<TransactionOutput> gathered) {
            this.valueGathered = valueGathered;
            this.gathered = gathered;
        }
    }

    /**
     * A CoinSelector is responsible for picking some outputs to spend, from the list of all spendable outputs. It
     * allows you to customize the policies for creation of transactions to suit your needs. The select operation
     * may return a {@link CoinSelection} that has a valueGathered lower than the requested target, if there's not
     * enough money in the wallet.
     */
    public interface CoinSelector {
        public CoinSelection select(BigInteger target, LinkedList<TransactionOutput> candidates);
    }

    /**
     * This class implements a {@link CoinSelector} which attempts to get the highest priority possible. This means that
     * the transaction is the most likely to get confirmed
     * Note that this means we may end up "spending" more priority than would be required to get the transaction we are
     * creating confirmed.
     */
    public static class DefaultCoinSelector implements CoinSelector {
        public CoinSelection select(BigInteger biTarget, LinkedList<TransactionOutput> candidates) {
            long target = biTarget.longValue();
            HashSet<TransactionOutput> selected = new HashSet<TransactionOutput>();
            // Sort the inputs by age*value so we get the highest "coindays" spent.
            // TODO: Consider changing the wallets internal format to track just outputs and keep them ordered.
            ArrayList<TransactionOutput> sortedOutputs = new ArrayList<TransactionOutput>(candidates);
            // When calculating the wallet balance, we may be asked to select all possible coins, if so, avoid sorting
            // them in order to improve performance.
            if (!biTarget.equals(NetworkParameters.MAX_MONEY)) {
                Collections.sort(sortedOutputs, new Comparator<TransactionOutput>() {
                    public int compare(TransactionOutput a, TransactionOutput b) {
                        int depth1 = 0;
                        int depth2 = 0;
                        TransactionConfidence conf1 = a.parentTransaction.getConfidence();
                        TransactionConfidence conf2 = b.parentTransaction.getConfidence();
                        if (conf1.getConfidenceType() == ConfidenceType.BUILDING) depth1 = conf1.getDepthInBlocks();
                        if (conf2.getConfidenceType() == ConfidenceType.BUILDING) depth2 = conf2.getDepthInBlocks();
                        BigInteger aValue = a.getValue();
                        BigInteger bValue = b.getValue();
                        BigInteger aCoinDepth = aValue.multiply(BigInteger.valueOf(depth1));
                        BigInteger bCoinDepth = bValue.multiply(BigInteger.valueOf(depth2));
                        int c1 = bCoinDepth.compareTo(aCoinDepth);
                        if (c1 != 0) return c1;
                        // The "coin*days" destroyed are equal, sort by value alone to get the lowest transaction size.
                        int c2 = bValue.compareTo(aValue);
                        if (c2 != 0) return c2;
                        // They are entirely equivalent (possibly pending) so sort by hash to ensure a total ordering.
                        BigInteger aHash = a.parentTransaction.getHash().toBigInteger();
                        BigInteger bHash = b.parentTransaction.getHash().toBigInteger();
                        return aHash.compareTo(bHash);
                    }
                });
            }
            // Now iterate over the sorted outputs until we have got as close to the target as possible or a little
            // bit over (excessive value will be change).
            long total = 0;
            for (TransactionOutput output : sortedOutputs) {
                if (total >= target) break;
                // Only pick chain-included transactions, or transactions that are ours and pending.
                if (!shouldSelect(output.parentTransaction)) continue;
                selected.add(output);
                total += output.getValue().longValue();
            }
            // Total may be lower than target here, if the given candidates were insufficient to create to requested
            // transaction.
            return new CoinSelection(BigInteger.valueOf(total), selected);
        }

        /** Sub-classes can override this to just customize whether transactions are usable, but keep age sorting. */
        protected boolean shouldSelect(Transaction tx) {
            return isSelectable(tx);
        }

        public static boolean isSelectable(Transaction tx) {
            // Only pick chain-included transactions, or transactions that are ours and pending.
            TransactionConfidence confidence = tx.getConfidence();
            ConfidenceType type = confidence.getConfidenceType();
            if (type.equals(ConfidenceType.BUILDING)) return true;
            return type.equals(ConfidenceType.PENDING) &&
                   confidence.getSource().equals(TransactionConfidence.Source.SELF) &&
                   confidence.numBroadcastPeers() > 1;
        }
    }

    /**
     * This coin selector will select any transaction at all, regardless of where it came from or whether it was
     * confirmed yet.
     */
    public static class AllowUnconfirmedCoinSelector extends DefaultCoinSelector {
        @Override protected boolean shouldSelect(Transaction tx) {
            return true;
        }

        private static AllowUnconfirmedCoinSelector instance;
        public static AllowUnconfirmedCoinSelector get() {
            // This doesn't have to be thread safe as the object has no state, so discarded duplicates are harmless.
            if (instance == null)
                instance = new AllowUnconfirmedCoinSelector();
            return instance;
        }
    }

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

    /**
     * Creates a new, empty wallet with no keys and no transactions. If you want to restore a wallet from disk instead,
     * see loadFromFile.
     */
    public Wallet(NetworkParameters params) {
        this(params, null);
    }

    /**
     * Create a wallet with a keyCrypter to use in encrypting and decrypting keys.
     */
    public Wallet(NetworkParameters params, KeyCrypter keyCrypter) {
        this.keyCrypter = keyCrypter;
        this.params = checkNotNull(params);
        keychain = new ArrayList<ECKey>();
        unspent = new HashMap<Sha256Hash, Transaction>();
        spent = new HashMap<Sha256Hash, Transaction>();
        pending = new HashMap<Sha256Hash, Transaction>();
        dead = new HashMap<Sha256Hash, Transaction>();
        eventListeners = new CopyOnWriteArrayList<WalletEventListener>();
        extensions = new HashMap<String, WalletExtension>();
        createTransientState();
    }

    private void createTransientState() {
        ignoreNextNewBlock = new HashSet<Sha256Hash>();
        txConfidenceListener = new TransactionConfidence.Listener() {
            @Override
            public void onConfidenceChanged(Transaction tx) {
                lock.lock();
                // The invokers unlock us immediately so if an exception is thrown, the lock will be already open.
                invokeOnTransactionConfidenceChanged(tx);
                // Many onWalletChanged events will not occur because they are suppressed, eg, because:
                //   - we are inside a re-org
                //   - we are in the middle of processing a block
                //   - the confidence is changing because a new best block was accepted
                // It will run in cases like:
                //   - the tx is pending and another peer announced it
                //   - the tx is pending and was killed by a detected double spend that was not in a block
                // The latter case cannot happen today because we won't hear about it, but in future this may
                // become more common if conflict notices are implemented.
                invokeOnWalletChanged();
                lock.unlock();
            }
        };
        acceptTimeLockedTransactions = false;
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

    private void saveToFile(File temp, File destFile) throws IOException {
        FileOutputStream stream = null;
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
                canonical.delete();
                if (temp.renameTo(canonical))
                    return;  // else fall through.
                throw new IOException("Failed to rename " + temp + " to " + canonical);
            } else if (!temp.renameTo(destFile)) {
                throw new IOException("Failed to rename " + temp + " to " + destFile);
            }
            lock.lock();
            try {
                if (destFile.equals(autosaveToFile)) {
                    dirty = false;
                }
            } finally {
                lock.unlock();
            }
        } finally {
            if (stream != null) {
                stream.close();
            }
            if (temp.delete()) {
                log.warn("Deleted temp file after failed save.");
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
     * <p>Whether or not the wallet will ignore transactions that have a lockTime parameter > 0. By default, all such
     * transactions are ignored, because they are useful only in special protocols and such a transaction may not
     * confirm as fast as an app typically expects. By setting this property to true, you are acknowledging that
     * you understand what time-locked transactions are, and that your code is capable of handling them without risk.
     * For instance you are not providing anything valuable in return for an unconfirmed transaction that has a lock
     * time far in the future (which opens you up to Finney attacks).</p>
     *
     * <p>Note that this property is not serialized. So you have to set it to true each time you load or create a
     * wallet.</p>
     */
    public void setAcceptTimeLockedTransactions(boolean acceptTimeLockedTransactions) {
        lock.lock();
        try {
            this.acceptTimeLockedTransactions = acceptTimeLockedTransactions;
        } finally {
            lock.unlock();
        }
    }

    /**
     * See {@link Wallet#setAcceptTimeLockedTransactions(boolean)} for an explanation of this property.
     */
    public boolean doesAcceptTimeLockedTransactions() {
        lock.lock();
        try {
            return acceptTimeLockedTransactions;
        } finally {
            lock.unlock();
        }
    }

    // Auto-saving can be done on a background thread if the user wishes it, this is to avoid stalling threads calling
    // into the wallet on serialization/disk access all the time which is important in GUI apps where you don't want
    // the main thread to ever wait on disk (otherwise you lose a lot of responsiveness). The primary case where it
    // can be a problem is during block chain syncup - the wallet has to be saved after every block to record where
    // it got up to and for updating the transaction confidence data, which can slow down block chain download a lot.
    // So this thread not only puts the work of saving onto a background thread but also coalesces requests together.
    private static class AutosaveThread extends Thread {
        private static DelayQueue<AutosaveThread.WalletSaveRequest> walletRefs = new DelayQueue<WalletSaveRequest>();
        private static AutosaveThread globalThread;

        private AutosaveThread() {
            // Allow the JVM to shut down without waiting for this thread. Note this means users could lose auto-saves
            // if they don't explicitly save the wallet before terminating!
            setDaemon(true);
            setName("Wallet auto save thread");
            setPriority(Thread.MIN_PRIORITY);   // Avoid competing with the UI.
        }

        /** Returns the global instance that services all wallets. It never shuts down. */
        public static void maybeStart() {
            if (walletRefs.size() == 0) return;

            synchronized (AutosaveThread.class) {
                if (globalThread == null) {
                    globalThread = new AutosaveThread();
                    globalThread.start();
                }
            }
        }

        /** Called by a wallet when it's become dirty (changed). Will start the background thread if needed. */
        public static void registerForSave(Wallet wallet, long delayMsec) {
            walletRefs.add(new WalletSaveRequest(wallet, delayMsec));
            maybeStart();
        }

        public void run() {
            log.info("Auto-save thread starting up");
            while (true) {
                try {
                    WalletSaveRequest req = walletRefs.poll(5, TimeUnit.SECONDS);
                    if (req == null) {
                        if (walletRefs.size() == 0) {
                            // No work to do for the given delay period, so let's shut down and free up memory.
                            // We'll get started up again if a wallet changes once more.
                            break;
                        } else {
                            // There's work but nothing to do just yet. Go back to sleep and try again.
                            continue;
                        }
                    }

                    req.wallet.lock.lock();
                    try {
                        if (req.wallet.dirty) {
                            if (req.wallet.autoSave()) {
                                // Something went wrong, abort!
                                break;
                            }
                        }
                    } finally {
                        req.wallet.lock.unlock();
                    }
                } catch (InterruptedException e) {
                    log.error("Auto-save thread interrupted during wait", e);
                    break;
                }
            }
            log.info("Auto-save thread shutting down");
            synchronized (AutosaveThread.class) {
                Preconditions.checkState(globalThread == this);   // There should only be one global thread.
                globalThread = null;
            }
            // There's a possible shutdown race where work is added after we decided to shutdown but before
            // we cleared globalThread.
            maybeStart();
        }

        private static class WalletSaveRequest implements Delayed {
            public final Wallet wallet;
            public final long startTimeMs, requestedDelayMs;

            public WalletSaveRequest(Wallet wallet, long requestedDelayMs) {
                this.startTimeMs = System.currentTimeMillis();
                this.requestedDelayMs = requestedDelayMs;
                this.wallet = wallet;
            }

            public long getDelay(TimeUnit timeUnit) {
                long delayRemainingMs = requestedDelayMs - (System.currentTimeMillis() - startTimeMs);
                return timeUnit.convert(delayRemainingMs, TimeUnit.MILLISECONDS);
            }

            public int compareTo(Delayed delayed) {
                if (delayed == this) return 0;
                long delta = getDelay(TimeUnit.MILLISECONDS) - delayed.getDelay(TimeUnit.MILLISECONDS);
                return (delta > 0 ? 1 : (delta < 0 ? -1 : 0));
            }

            @Override
            public boolean equals(Object obj) {
                if (!(obj instanceof WalletSaveRequest)) return false;
                WalletSaveRequest w = (WalletSaveRequest) obj;
                return w.startTimeMs == startTimeMs &&
                       w.requestedDelayMs == requestedDelayMs &&
                       w.wallet == wallet;
            }

            @Override
            public int hashCode() {
                return Objects.hashCode(wallet, startTimeMs, requestedDelayMs);
            }
        }
    }

    /** Returns true if the auto-save thread should abort */
    private boolean autoSave() {
        lock.lock();
        final Sha256Hash lastBlockSeenHash = this.lastBlockSeenHash;
        final AutosaveEventListener autosaveEventListener = this.autosaveEventListener;
        final File autosaveToFile = this.autosaveToFile;
        lock.unlock();
        try {
            log.info("Auto-saving wallet, last seen block is {}", lastBlockSeenHash);
            File directory = autosaveToFile.getAbsoluteFile().getParentFile();
            File temp = File.createTempFile("wallet", null, directory);
            if (autosaveEventListener != null)
                autosaveEventListener.onBeforeAutoSave(temp);
            // This will clear the dirty flag.
            saveToFile(temp, autosaveToFile);
            if (autosaveEventListener != null)
                autosaveEventListener.onAfterAutoSave(autosaveToFile);
        } catch (Exception e) {
            if (autosaveEventListener != null && autosaveEventListener.caughtException(e))
                return true;
            else
                throw new RuntimeException(e);
        }
        return false;
    }

    /**
     * Implementors can handle exceptions thrown during wallet auto-save, and to do pre/post treatment of the wallet.
     */
    public interface AutosaveEventListener {
        /**
         * Called on the auto-save thread if an exception is caught whilst saving the wallet.
         * @return if true, terminates the auto-save thread. Otherwise sleeps and then tries again.
         */
        public boolean caughtException(Throwable t);

        /**
         * Called on the auto-save thread when a new temporary file is created but before the wallet data is saved
         * to it. If you want to do something here like adjust permissions, go ahead and do so. The wallet is locked
         * whilst this method is run.
         */
        public void onBeforeAutoSave(File tempFile);

        /**
         * Called on the auto-save thread after the newly created temporary file has been filled with data and renamed.
         * The wallet is locked whilst this method is run.
         */
        public void onAfterAutoSave(File newlySavedFile);
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
    public void autosaveToFile(File f, long delayTime, TimeUnit timeUnit,
                               AutosaveEventListener eventListener) {
        lock.lock();
        try {
            Preconditions.checkArgument(delayTime >= 0);
            autosaveToFile = Preconditions.checkNotNull(f);
            if (delayTime > 0) {
                autosaveEventListener = eventListener;
                autosaveDelayMs = TimeUnit.MILLISECONDS.convert(delayTime, timeUnit);
            }
        } finally {
            lock.unlock();
        }
    }

    private void queueAutoSave() {
        lock.lock();
        try {
            if (this.autosaveToFile == null) return;
            if (autosaveDelayMs == 0) {
                // No delay time was specified, so save now.
                try {
                    saveToFile(autosaveToFile);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                // If we need to, tell the auto save thread to wake us up. This will start the background thread if one
                // doesn't already exist. It will wake up once the delay expires and call autoSave().
                // The background thread is shared between all wallets.
                if (!dirty) {
                    dirty = true;
                    AutosaveThread.registerForSave(this, autosaveDelayMs);
                }
            }
        } finally {
            lock.unlock();
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
    public static Wallet loadFromFile(File f) throws IOException {
        FileInputStream stream = new FileInputStream(f);
        try {
            return loadFromFileStream(stream);
        } finally {
            stream.close();
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

            if (!success) log.error(toString());
            return success;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a wallet deserialized from the given input stream.
     */
    public static Wallet loadFromFileStream(InputStream stream) throws IOException {
        // Determine what kind of wallet stream this is: Java Serialization or protobuf format.
        stream = new BufferedInputStream(stream);
        stream.mark(100);
        boolean serialization = stream.read() == 0xac && stream.read() == 0xed;
        stream.reset();

        Wallet wallet;
        
        if (serialization) {
            ObjectInputStream ois = null;
            try {
                ois = new ObjectInputStream(stream);
                wallet = (Wallet) ois.readObject();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            } finally {
                if (ois != null) ois.close();
            }
        } else {
            wallet = new WalletProtobufSerializer().readWallet(stream);
        }
        
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
    public void notifyTransactionIsInBlock(Sha256Hash txHash, StoredBlock block,
                                           BlockChain.NewBlockType blockType) throws VerificationException {
        lock.lock();
        try {
            Transaction tx = pending.get(txHash);
            if (tx == null)
                return;
            receive(tx, block, blockType, false);
        } finally {
            lock.unlock();
        }
    }

    /** The results of examining the dependency graph of a pending transaction for protocol abuse. */
    protected static class AnalysisResult {
        // Which tx, if any, had a non-zero lock time.
        Transaction timeLocked;
        // In future, depth, fees, if any are non-standard, anything else that's interesting ...
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
    public void receivePending(Transaction tx, List<Transaction> dependencies) throws VerificationException {
        // Can run in a peer thread. This method will only be called if a prior call to isPendingTransactionRelevant
        // returned true, so we already know by this point that it sends coins to or from our wallet, or is a double
        // spend against one of our other pending transactions.
        //
        // Do a brief risk analysis of the transaction and its dependencies to check for any possible attacks.
        lock.lock();
        try {
            tx.verify();
            // Repeat the check of relevancy here, even though the caller may have already done so - this is to avoid
            // race conditions where receivePending may be being called in parallel.
            if (!isPendingTransactionRelevant(tx))
                return;
            AnalysisResult analysis = analyzeTransactionAndDependencies(tx, dependencies);
            if (analysis.timeLocked != null && !doesAcceptTimeLockedTransactions()) {
                log.warn("Transaction {}, dependency of {} has a time lock value of {}", new Object[]{
                        analysis.timeLocked.getHashAsString(), tx.getHashAsString(), analysis.timeLocked.getLockTime()});
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
                log.warn("Wallet received transaction with an unknown source. Consider tagging tx!");
            }
            // Mark the tx as having been seen but is not yet in the chain. This will normally have been done already by
            // the Peer before we got to this point, but in some cases (unit tests, other sources of transactions) it may
            // have been missed out.
            ConfidenceType currentConfidence = tx.getConfidence().getConfidenceType();
            if (currentConfidence == ConfidenceType.UNKNOWN) {
                tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
                // Manually invoke the wallet tx confidence listener here as we didn't yet commit therefore the
                // txConfidenceListener wasn't added.
                invokeOnTransactionConfidenceChanged(tx);
            }
            // If this tx spends any of our unspent outputs, mark them as spent now, then add to the pending pool. This
            // ensures that if some other client that has our keys broadcasts a spend we stay in sync. Also updates the
            // timestamp on the transaction and registers/runs event listeners.
            //
            // Note that after we return from this function, the wallet may have been modified.
            commitTx(tx);
        } finally {
            lock.unlock();
        }
    }

    private static AnalysisResult analyzeTransactionAndDependencies(Transaction tx, List<Transaction> dependencies) {
        AnalysisResult result = new AnalysisResult();
        if (tx.isTimeLocked())
            result.timeLocked = tx;
        if (dependencies != null) {
            for (Transaction dep : dependencies) {
                if (dep.isTimeLocked()) {
                    result.timeLocked = dep;
                }
            }
        }
        return result;
    }

    /**
     * This method is used by a {@link Peer} to find out if a transaction that has been announced is interesting,
     * that is, whether we should bother downloading its dependencies and exploring the transaction to decide how
     * risky it is. If this method returns true then {@link Wallet#receivePending(Transaction, java.util.List)}
     * will soon be called with the transactions dependencies as well.
     */
    boolean isPendingTransactionRelevant(Transaction tx) throws ScriptException {
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

            if (tx.isTimeLocked() && !acceptTimeLockedTransactions) {
                log.warn("Received transaction {} with a lock time of {}, but not configured to accept these, discarding",
                        tx.getHashAsString(), tx.getLockTime());
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
        checkState(lock.isLocked());
        // Compile a set of outpoints that are spent by tx.
        HashSet<TransactionOutPoint> outpoints = new HashSet<TransactionOutPoint>();
        for (TransactionInput input : tx.getInputs()) {
            outpoints.add(input.getOutpoint());
        }
        // Now for each pending transaction, see if it shares any outpoints with this tx.
        for (Transaction p : pending.values()) {
            for (TransactionInput input : p.getInputs()) {
                // This relies on the fact that TransactionOutPoint equality is defined at the protocol not object
                // level - outpoints from two different inputs that point to the same output compare the same.
                TransactionOutPoint outpoint = input.getOutpoint();
                if (outpoints.contains(outpoint)) {
                    // It does, it's a double spend against the pending pool, which makes it relevant.
                    if (takeAction) {
                        // Look for the actual input object in tx that is double spending.
                        TransactionInput overridingInput = null;
                        for (TransactionInput txInput : tx.getInputs()) {
                            if (txInput.getOutpoint().equals(outpoint)) overridingInput = txInput;
                        }
                        killTx(tx, checkNotNull(overridingInput), p);
                    }
                    return true;
                }
            }
        }
        return false;
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
    public void receiveFromBlock(Transaction tx, StoredBlock block,
                                 BlockChain.NewBlockType blockType) throws VerificationException {
        lock.lock();
        try {
            receive(tx, block, blockType, false);
        } finally {
            lock.unlock();
        }
    }

    private void receive(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType, boolean reorg) throws VerificationException {
        // Runs in a peer thread.
        checkState(lock.isLocked());
        BigInteger prevBalance = getBalance();
        Sha256Hash txHash = tx.getHash();
        boolean bestChain = blockType == BlockChain.NewBlockType.BEST_CHAIN;
        boolean sideChain = blockType == BlockChain.NewBlockType.SIDE_CHAIN;

        BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
        BigInteger valueSentToMe = tx.getValueSentToMe(this);
        BigInteger valueDifference = valueSentToMe.subtract(valueSentFromMe);

        log.info("Received tx {} for {} BTC: {} in block {}", new Object[]{sideChain ? "on a side chain" : "",
                bitcoinValueToFriendlyString(valueDifference), tx.getHashAsString(),
                block != null ? block.getHeader().getHash() : "(unit test)"});

        onWalletChangedSuppressions++;

        // If this transaction is already in the wallet we may need to move it into a different pool. At the very
        // least we need to ensure we're manipulating the canonical object rather than a duplicate.
        Transaction wtx;
        if ((wtx = pending.remove(txHash)) != null) {
            log.info("  <-pending");
            // Make sure "tx" is always the canonical object we want to manipulate, send to event handlers, etc.
            tx = wtx;
        }
        boolean wasPending = wtx != null;

        if (bestChain) {
            if (wasPending) {
                // Was pending and is now confirmed. Disconnect the outputs in case we spent any already: they will be
                // re-connected by processTxFromBestChain below.
                for (TransactionOutput output : tx.getOutputs()) {
                    final TransactionInput spentBy = output.getSpentBy();
                    if (spentBy != null) spentBy.disconnect();
                }
            }
            // TODO: This can trigger tx confidence listeners to be run in the case of double spends.
            // We should delay the execution of the listeners until the bottom to avoid the wallet mutating.
            processTxFromBestChain(tx);
        } else {
            checkState(sideChain);
            // Transactions that appear in a side chain will have that appearance recorded below - we assume that
            // some miners are also trying to include the transaction into the current best chain too, so let's treat
            // it as pending, except we don't need to do any risk analysis on it.
            if (wasPending) {
                // Just put it back in without touching the connections.
                addWalletTransaction(Pool.PENDING, tx);
            } else {
                // Ignore the case where a tx appears on a side chain at the same time as the best chain (this is
                // quite normal and expected).
                Sha256Hash hash = tx.getHash();
                if (!unspent.containsKey(hash) && !spent.containsKey(hash)) {
                    // Otherwise put it (possibly back) into pending.
                    // Committing it updates the spent flags and inserts into the pool as well.
                    tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
                    commitTx(tx);
                }
            }
        }

        if (block != null) {
            // Mark the tx as appearing in this block so we can find it later after a re-org. This also tells the tx
            // confidence object about the block and sets its work done/depth appropriately.
            // TODO: This can trigger re-entrancy: delay running confidence listeners.
            tx.setBlockAppearance(block, bestChain);
            if (bestChain) {
                // Don't notify this tx of work done in notifyNewBestBlock which will be called immediately after
                // this method has been called by BlockChain for all relevant transactions. Otherwise we'd double
                // count.
                ignoreNextNewBlock.add(txHash);
            }
        }

        // Inform anyone interested that we have received or sent coins but only if:
        //  - This is not due to a re-org.
        //  - The coins appeared on the best chain.
        //  - We did in fact receive some new money.
        //  - We have not already informed the user about the coins when we received the tx broadcast, or for our
        //    own spends. If users want to know when a broadcast tx becomes confirmed, they need to use tx confidence
        //    listeners.
        if (!reorg && bestChain && !wasPending) {
            BigInteger newBalance = getBalance();  // This is slow.
            log.info("Balance is now: " + bitcoinValueToFriendlyString(newBalance));
            int diff = valueDifference.compareTo(BigInteger.ZERO);
            // We pick one callback based on the value difference, though a tx can of course both send and receive
            // coins from the wallet.
            if (diff > 0) {
                invokeOnCoinsReceived(tx, prevBalance, newBalance);
            } else if (diff < 0) {
                invokeOnCoinsSent(tx, prevBalance, newBalance);
            } else {
                // We have a transaction that didn't change our balance. Probably we sent coins between our own keys.
                invokeOnWalletChanged();
            }
        }

        // Wallet change notification will be sent shortly after the block is finished processing, in notifyNewBestBlock
        onWalletChangedSuppressions--;

        checkState(isConsistent());
        queueAutoSave();
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
            // TODO: Clarify the code below.
            // Notify all the BUILDING transactions of the new block.
            // This is so that they can update their work done and depth.
            onWalletChangedSuppressions++;
            Set<Transaction> transactions = getTransactions(true);
            for (Transaction tx : transactions) {
                if (ignoreNextNewBlock.contains(tx.getHash())) {
                    // tx was already processed in receive() due to it appearing in this block, so we don't want to
                    // notify the tx confidence of work done twice, it'd result in miscounting.
                    ignoreNextNewBlock.remove(tx.getHash());
                } else {
                    tx.getConfidence().notifyWorkDone(block.getHeader());
                }
            }
            queueAutoSave();
            onWalletChangedSuppressions--;
            invokeOnWalletChanged();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Handle when a transaction becomes newly active on the best chain, either due to receiving a new block or a
     * re-org. Places the tx into the right pool, handles coinbase transactions, handles double-spends and so on.
     */
    private void processTxFromBestChain(Transaction tx) throws VerificationException {
        checkState(lock.isLocked());
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
        checkState(lock.isLocked());
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
                } else {
                    // We saw two pending transactions that double spend each other. We don't know which will win.
                    // This should not happen.
                    log.warn("Saw two pending transactions double spend each other: {} vs {}",
                            tx.getHash(), input.getConnectedOutput().getSpentBy().getParentTransaction().getHash());
                    log.warn("  offending input is input {}", tx.getInputs().indexOf(input));
                }
            } else if (result == TransactionInput.ConnectionResult.SUCCESS) {
                // Otherwise we saw a transaction spend our coins, but we didn't try and spend them ourselves yet.
                // The outputs are already marked as spent by the connect call above, so check if there are any more for
                // us to use. Move if not.
                Transaction connected = checkNotNull(input.getOutpoint().fromTx);
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

    // Updates the wallet when a double spend occurs.
    private void killTx(Transaction overridingTx, TransactionInput overridingInput, Transaction killedTx) {
        final Sha256Hash killedTxHash = killedTx.getHash();
        if (overridingTx == null) {
            // killedTx depended on a transaction that died because it was double spent or a coinbase that got re-orgd.
            killedTx.getConfidence().setOverridingTransaction(null);
            pending.remove(killedTxHash);
            unspent.remove(killedTxHash);
            spent.remove(killedTxHash);
            addWalletTransaction(Pool.DEAD, killedTx);
            // TODO: Properly handle the recursive nature of killing transactions here.
            return;
        }
        TransactionOutPoint overriddenOutPoint = overridingInput.getOutpoint();
        // It is expected that we may not have the overridden/double-spent tx in our wallet ... in the (common?!) case
        // where somebody is stealing money from us, the overriden tx belongs to someone else.
        log.warn("Saw double spend of {} from chain override pending tx {}",
                overriddenOutPoint, killedTx.getHashAsString());
        log.warn("  <-pending ->dead   killed by {}", overridingTx.getHashAsString());
        pending.remove(killedTxHash);
        addWalletTransaction(Pool.DEAD, killedTx);
        log.info("Disconnecting inputs of the newly dead tx");
        for (TransactionInput deadInput : killedTx.getInputs()) {
            Transaction connected = deadInput.getOutpoint().fromTx;
            if (connected == null) continue;
            deadInput.disconnect();
            maybeMovePool(connected, "kill");
        }
        // Try and connect the overriding input to something in our wallet. It's expected that this will mostly fail
        // because when somebody else is double-spending away a payment they made to us, we won't have the overridden
        // tx as it's not ours to begin with. It'll only be found if we're double spending our own payments.
        log.info("Trying to connect overriding tx back");
        TransactionInput.ConnectionResult result = overridingInput.connect(unspent, TransactionInput.ConnectMode.DISCONNECT_ON_CONFLICT);
        if (result == TransactionInput.ConnectionResult.SUCCESS) {
            maybeMovePool(overridingInput.getOutpoint().fromTx, "kill");
        } else {
            result = overridingInput.connect(spent, TransactionInput.ConnectMode.DISCONNECT_ON_CONFLICT);
            if (result == TransactionInput.ConnectionResult.SUCCESS) {
                maybeMovePool(overridingInput.getOutpoint().fromTx, "kill");
            }
        }
        log.info("Informing tx listeners of double spend event");
        killedTx.getConfidence().setOverridingTransaction(overridingTx);  // RE-ENTRY POINT
        // TODO: Recursively kill other transactions that were double spent.
    }

    /**
     * If the transactions outputs are all marked as spent, and it's in the unspent map, move it.
     * If the owned transactions outputs are not all marked as spent, and it's in the spent map, move it.
     */
    private void maybeMovePool(Transaction tx, String context) {
        checkState(lock.isLocked());
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
     * like receiving money.
     */
    public void addEventListener(WalletEventListener listener) {
        eventListeners.add(listener);
    }

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
    public boolean removeEventListener(WalletEventListener listener) {
        return eventListeners.remove(listener);
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
            addWalletTransaction(Pool.PENDING, tx);

            // Event listeners may re-enter so we cannot make assumptions about wallet state after this loop completes.
            try {
                BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
                BigInteger valueSentToMe = tx.getValueSentToMe(this);
                BigInteger newBalance = balance.add(valueSentToMe).subtract(valueSentFromMe);
                if (valueSentToMe.compareTo(BigInteger.ZERO) > 0)
                    invokeOnCoinsReceived(tx, balance, newBalance);
                if (valueSentFromMe.compareTo(BigInteger.ZERO) > 0)
                    invokeOnCoinsSent(tx, balance, newBalance);

                invokeOnWalletChanged();
            } catch (ScriptException e) {
                // Cannot happen as we just created this transaction ourselves.
                throw new RuntimeException(e);
            }

            checkState(isConsistent());
            queueAutoSave();
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
        checkState(lock.isLocked());
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
        case PENDING_INACTIVE:
            checkState(pending.put(tx.getHash(), tx) == null);
            break;
        default:
            throw new RuntimeException("Unknown wallet transaction type " + pool);
        }
        // This is safe even if the listener has been added before, as TransactionConfidence ignores duplicate
        // registration requests. That makes the code in the wallet simpler.
        tx.getConfidence().addEventListener(txConfidenceListener);
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
    public Transaction getTransaction(Sha256Hash hash) {
        lock.lock();
        try {
            Transaction tx;
            if ((tx = pending.get(hash)) != null)
                return tx;
            else if ((tx = unspent.get(hash)) != null)
                return tx;
            else if ((tx = spent.get(hash)) != null)
                return tx;
            else if ((tx = dead.get(hash)) != null)
                return tx;
            return null;
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
                queueAutoSave();
            } else {
                throw new UnsupportedOperationException();
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
                case ALL:
                    return unspent.size() + spent.size() + pending.size() + dead.size();
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
         * <p>This is a dynamic fee (in satoshis) which will be added to the transaction for each kilobyte in size after
         * the first. This is useful as as miners usually sort pending transactions by their fee per unit size when
         * choosing which transactions to add to a block. Note that, to keep this equivalent to the reference client
         * definition, a kilobyte is defined as 1000 bytes, not 1024.</p>
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
         * You can get this from a password by doing wallet.getKeyCrypter().derivePassword(password).
         */
        public KeyParameter aesKey = null;

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
            SendRequest req = new Wallet.SendRequest();
            req.tx = new Transaction(destination.getParameters());
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
    }

    /**
     * <p>Statelessly creates a transaction that sends the given value to address. The change is sent to
     * {@link Wallet#getChangeAddress()}, so you must have added at least one key.</p>
     *
     * <p>If you just want to send money quickly, you probably want
     * {@link Wallet#sendCoins(PeerGroup, Address, java.math.BigInteger)} instead. That will create the sending
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
     * <p>You MUST ensure that nanocoins is smaller than {@link Transaction#MIN_NONDUST_OUTPUT} or the transaction will
     * almost certainly be rejected by the network as dust.</p>
     *
     * @param address       The Bitcoin address to send the money to.
     * @param nanocoins     How much currency to send, in nanocoins.
     * @return either the created Transaction or null if there are insufficient coins.
     * coins as spent until commitTx is called on the result.
     */
    public Transaction createSend(Address address, BigInteger nanocoins) {
        SendRequest req = SendRequest.to(address, nanocoins);
        if (completeTx(req)) {
            return req.tx;
        } else {
            return null;  // No money.
        }
    }

    /**
     * Sends coins to the given address but does not broadcast the resulting pending transaction. It is still stored
     * in the wallet, so when the wallet is added to a {@link PeerGroup} or {@link Peer} the transaction will be
     * announced to the network. The given {@link SendRequest} is completed first using
     * {@link Wallet#completeTx(Wallet.SendRequest)} to make it valid.
     *
     * @return the Transaction that was created, or null if there are insufficient coins in the wallet.
     */
    public Transaction sendCoinsOffline(SendRequest request) {
        lock.lock();
        try {
            if (!completeTx(request))
                return null;  // Not enough money! :-(
            commitTx(request.tx);
            return request.tx;
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen unless there's a bug, as we just created this ourselves.
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
     * <p>You MUST ensure that value is smaller than {@link Transaction#MIN_NONDUST_OUTPUT} or the transaction will
     * almost certainly be rejected by the network as dust.</p>
     *
     * @param peerGroup a PeerGroup to use for broadcast or null.
     * @param to        Which address to send coins to.
     * @param value     How much value to send. You can use Utils.toNanoCoins() to calculate this.
     * @return An object containing the transaction that was created, and a future for the broadcast of it.
     */
    public SendResult sendCoins(PeerGroup peerGroup, Address to, BigInteger value) {
        SendRequest request = SendRequest.to(to, value);
        return sendCoins(peerGroup, request);
    }

    /**
     * <p>Sends coins according to the given request, via the given {@link PeerGroup}.</p>
     *
     * <p>The returned object provides both the transaction, and a future that can be used to learn when the broadcast
     * is complete. Complete means, if the PeerGroup is limited to only one connection, when it was written out to
     * the socket. Otherwise when the transaction is written out and we heard it back from a different peer.</p>
     *
     * <p>Note that the sending transaction is committed to the wallet immediately, not when the transaction is
     * successfully broadcast. This means that even if the network hasn't heard about your transaction you won't be
     * able to spend those same coins again.</p>
     *
     * @param peerGroup a PeerGroup to use for broadcast or null.
     * @param request the SendRequest that describes what to do, get one using static methods on SendRequest itself.
     * @return An object containing the transaction that was created, and a future for the broadcast of it.
     */
    public SendResult sendCoins(PeerGroup peerGroup, SendRequest request) {
        // Does not need to be synchronized as sendCoinsOffline is and the rest is all thread-local.

        // Commit the TX to the wallet immediately so the spent coins won't be reused.
        // TODO: We should probably allow the request to specify tx commit only after the network has accepted it.
        Transaction tx = sendCoinsOffline(request);
        if (tx == null)
            return null;  // Not enough money.
        SendResult result = new SendResult();
        result.tx = tx;
        // The tx has been committed to the pending pool by this point (via sendCoinsOffline -> commitTx), so it has
        // a txConfidenceListener registered. Once the tx is broadcast the peers will update the memory pool with the
        // count of seen peers, the memory pool will update the transaction confidence object, that will invoke the
        // txConfidenceListener which will in turn invoke the wallets event listener onTransactionConfidenceChanged
        // method.
        result.broadcastComplete = peerGroup.broadcastTransaction(tx);
        return result;
    }

    /**
     * Sends coins to the given address, via the given {@link Peer}. Change is returned to {@link Wallet#getChangeAddress()}.
     * If an exception is thrown by {@link Peer#sendMessage(Message)} the transaction is still committed, so the
     * pending transaction must be broadcast <b>by you</b> at some other time. Note that a fee may be automatically added
     * if one may be required for the transaction to be confirmed.
     *
     * @return The {@link Transaction} that was created or null if there was insufficient balance to send the coins.
     * @throws IOException if there was a problem broadcasting the transaction
     */
    public Transaction sendCoins(Peer peer, SendRequest request) throws IOException {
        Transaction tx = sendCoinsOffline(request);
        if (tx == null)
            return null;  // Not enough money.
        peer.sendMessage(tx);
        return tx;
    }

    /**
     * Given a spend request containing an incomplete transaction, makes it valid by adding inputs and outputs according
     * to the instructions in the request. The transaction in the request is modified by this method, as is the fee
     * parameter.
     *
     * @param req a SendRequest that contains the incomplete transaction and details for how to make it valid.
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice.
     * @return whether or not the requested send is affordable.
     */
    public boolean completeTx(SendRequest req) {
        lock.lock();
        try {
            Preconditions.checkArgument(!req.completed, "Given SendRequest has already been completed.");
            // Calculate the amount of value we need to import.
            BigInteger value = BigInteger.ZERO;
            for (TransactionOutput output : req.tx.getOutputs()) {
                value = value.add(output.getValue());
            }
            BigInteger totalOutput = value;

            log.info("Completing send tx with {} outputs totalling {} (not including fees)",
                    req.tx.getOutputs().size(), bitcoinValueToFriendlyString(value));

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
            if (req.ensureMinRequiredFee) {
                for (TransactionOutput output : req.tx.getOutputs())
                    if (output.getValue().compareTo(Utils.CENT) < 0) {
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
            LinkedList<TransactionOutput> candidates = calculateSpendCandidates(true);
            // This can throw InsufficientMoneyException.
            FeeCalculation feeCalculation;
            try {
                feeCalculation = new FeeCalculation(req, value, originalInputs, needAtLeastReferenceFee, candidates);
            } catch (InsufficientMoneyException e) {
                // TODO: Propagate this after 0.9 is released and stop returning a boolean.
                return false;
            }
            CoinSelection bestCoinSelection = feeCalculation.bestCoinSelection;
            TransactionOutput bestChangeOutput = feeCalculation.bestChangeOutput;

            for (TransactionOutput output : bestCoinSelection.gathered)
                req.tx.addInput(output);

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
            try {
                req.tx.signInputs(Transaction.SigHash.ALL, this, req.aesKey);
            } catch (ScriptException e) {
                // If this happens it means an output script in a wallet tx could not be understood. That should never
                // happen, if it does it means the wallet has got into an inconsistent state.
                throw new RuntimeException(e);
            }

            // Check size.
            int size = req.tx.bitcoinSerialize().length;
            if (size > Transaction.MAX_STANDARD_TX_SIZE) {
                // TODO: Throw an unchecked protocol exception here.
                log.warn(String.format(
                        "Transaction could not be created without exceeding max size: %d vs %d",
                        size, Transaction.MAX_STANDARD_TX_SIZE));
                return false;
            }

            // Label the transaction as being self created. We can use this later to spend its change output even before
            // the transaction is confirmed.
            req.tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
            req.tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
            req.completed = true;
            req.fee = calculatedFee;
            log.info("  completed {} with {} inputs", req.tx.getHashAsString(), req.tx.getInputs().size());
            return true;
        } finally {
            lock.unlock();
        }
    }

    private LinkedList<TransactionOutput> calculateSpendCandidates(boolean excludeImmatureCoinbases) {
        checkState(lock.isLocked());
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
     * If {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, com.google.bitcoin.core.Wallet.AutosaveEventListener)}
     * has been called, triggers an auto save bypassing the normal coalescing delay and event handlers.
     * If the key already exists in the wallet, does nothing and returns false.
     */
    public boolean addKey(final ECKey key) {
        return addKeys(Lists.newArrayList(key)) == 1;
    }

    /**
     * Adds the given keys to the wallet. There is currently no way to delete keys (that would result in coin loss).
     * If {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, com.google.bitcoin.core.Wallet.AutosaveEventListener)}
     * has been called, triggers an auto save bypassing the normal coalescing delay and event handlers.
     * Returns the number of keys added, after duplicates are ignored. The onKeyAdded event will be called for each key
     * in the list that was not already present.
     */
    public int addKeys(final List<ECKey> keys) {
        int added = 0;
        lock.lock();
        try {
            // TODO: Consider making keys a sorted list or hashset so membership testing is faster.
            for (final ECKey key : keys) {
                if (keychain.contains(key)) continue;

                // If the key has a keyCrypter that does not match the Wallet's then a KeyCrypterException is thrown.
                // This is done because only one keyCrypter is persisted per Wallet and hence all the keys must be homogenous.
                if (keyCrypter != null && keyCrypter.getUnderstoodEncryptionType() != EncryptionType.UNENCRYPTED) {
                    if (key.isEncrypted() && !keyCrypter.equals(key.getKeyCrypter())) {
                        throw new KeyCrypterException("Cannot add key " + key.toString() + " because the keyCrypter does not match the wallets. Keys must be homogenous.");
                    }
                }
                keychain.add(key);
                added++;
            }
            if (autosaveToFile != null) {
                autoSave();
            }
        } finally {
            lock.unlock();
        }

        for (ECKey key : keys) {
            // TODO: Change this interface to be batch-oriented.
            for (WalletEventListener listener : eventListeners) {
                listener.onKeyAdded(key);
            }
        }
        return added;
    }

    /**
     * Locates a keypair from the keychain given the hash of the public key. This is needed when finding out which
     * key we need to use to redeem a transaction output.
     *
     * @return ECKey object or null if no such key was found.
     */
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

    /**
     * Locates a keypair from the keychain given the raw public key bytes.
     * @return ECKey or null if no such key was found.
     */
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
                LinkedList<TransactionOutput> all = calculateSpendCandidates(false);
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
            LinkedList<TransactionOutput> candidates = calculateSpendCandidates(true);
            CoinSelection selection = selector.select(NetworkParameters.MAX_MONEY, candidates);
            return selection.valueGathered;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public String toString() {
        return toString(false, null);
    }

    /**
     * Formats the wallet as a human readable piece of text. Intended for debugging, the format is not meant to be
     * stable or human readable.
     * @param includePrivateKeys Whether raw private key data should be included.
     * @param chain If set, will be used to estimate lock times for block timelocked transactions.
     */
    public String toString(boolean includePrivateKeys, AbstractBlockChain chain) {
        lock.lock();
        try {
            StringBuilder builder = new StringBuilder();
            builder.append(String.format("Wallet containing %s BTC in:%n", bitcoinValueToFriendlyString(getBalance())));
            builder.append(String.format("  %d unspent transactions%n", unspent.size()));
            builder.append(String.format("  %d spent transactions%n", spent.size()));
            builder.append(String.format("  %d pending transactions%n", pending.size()));
            builder.append(String.format("  %d dead transactions%n", dead.size()));
            builder.append(String.format("Last seen best block: (%d) %s%n",
                    getLastBlockSeenHeight(), getLastBlockSeenHash()));
            if (this.keyCrypter != null) {
                builder.append(String.format("Encryption: %s%n", keyCrypter.toString()));
            }
            // Do the keys.
            builder.append("\nKeys:\n");
            for (ECKey key : keychain) {
                builder.append("  addr:");
                builder.append(key.toAddress(params));
                builder.append(" ");
                builder.append(includePrivateKeys ? key.toStringWithPrivate() : key.toString());
                builder.append("\n");
            }
            // Print the transactions themselves
            if (unspent.size() > 0) {
                builder.append("\nUNSPENT:\n");
                toStringHelper(builder, unspent, chain);
            }
            if (spent.size() > 0) {
                builder.append("\nSPENT:\n");
                toStringHelper(builder, spent, chain);
            }
            if (pending.size() > 0) {
                builder.append("\nPENDING:\n");
                toStringHelper(builder, pending, chain);
            }
            if (dead.size() > 0) {
                builder.append("\nDEAD:\n");
                toStringHelper(builder, dead, chain);
            }
            return builder.toString();
        } finally {
            lock.unlock();
        }
    }

    private void toStringHelper(StringBuilder builder, Map<Sha256Hash, Transaction> transactionMap,
                                AbstractBlockChain chain) {
        checkState(lock.isLocked());
        for (Transaction tx : transactionMap.values()) {
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

            // Map block hash to transactions that appear in it.
            Multimap<Sha256Hash, Transaction> mapBlockTx = ArrayListMultimap.create();
            for (Transaction tx : getTransactions(true)) {
                Collection<Sha256Hash> appearsIn = tx.getAppearsInHashes();
                if (appearsIn == null) continue;  // Pending.
                for (Sha256Hash block : appearsIn)
                    mapBlockTx.put(block, tx);
            }

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

            // Avoid spuriously informing the user of wallet changes whilst we're re-organizing. This also prevents the
            // user from modifying wallet contents (eg, trying to spend) whilst we're in the middle of the process.
            onWalletChangedSuppressions++;

            Collections.reverse(newBlocks);  // Need bottom-to-top but we get top-to-bottom.

            // For each block in the old chain, disconnect the transactions. It doesn't matter if
            // we don't do it in the exact ordering they appeared in the chain, all we're doing is ensuring all
            // the outputs are freed up so we can connect them back again in the next step.
            LinkedList<Transaction> oldChainTxns = Lists.newLinkedList();
            for (Sha256Hash blockHash : oldBlockHashes) {
                for (Transaction tx : mapBlockTx.get(blockHash)) {
                    final Sha256Hash txHash = tx.getHash();
                    if (tx.isCoinBase()) {
                        log.warn("Coinbase tx {} -> dead", tx.getHash());
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
                        killTx(null, null, tx);
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
                for (Transaction tx : mapBlockTx.get(block.getHeader().getHash())) {
                    log.info("  tx {}", tx.getHash());
                    try {
                        receive(tx, block, BlockChain.NewBlockType.BEST_CHAIN, true);
                    } catch (ScriptException e) {
                        throw new RuntimeException(e);  // Cannot happen as these blocks were already verified.
                    }
                }
                notifyNewBestBlock(block);
            }
            log.info("post-reorg balance is {}", Utils.bitcoinValueToFriendlyString(getBalance()));
            // Inform event listeners that a re-org took place. They should save the wallet at this point.
            invokeOnReorganize();
            onWalletChangedSuppressions--;
            invokeOnWalletChanged();
            checkState(isConsistent());
        } finally {
            lock.unlock();
        }
    }

    /**
     * Subtract the supplied depth and work done from the given transactions.
     */
    private static void subtractDepthAndWorkDone(int depthToSubtract, BigInteger workDoneToSubtract,
                                                 Collection<Transaction> transactions) {
        for (Transaction tx : transactions) {
            if (tx.getConfidence().getConfidenceType() == ConfidenceType.BUILDING) {
                tx.getConfidence().setDepthInBlocks(tx.getConfidence().getDepthInBlocks() - depthToSubtract);
                tx.getConfidence().setWorkDone(tx.getConfidence().getWorkDone().subtract(workDoneToSubtract));
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
     * Returns the earliest creation time of the keys in this wallet, in seconds since the epoch, ie the min of 
     * {@link com.google.bitcoin.core.ECKey#getCreationTimeSeconds()}. This can return zero if at least one key does
     * not have that data (was created before key timestamping was implemented). <p>
     *     
     * This method is most often used in conjunction with {@link PeerGroup#setFastCatchupTimeSecs(long)} in order to
     * optimize chain download for new users of wallet apps. Backwards compatibility notice: if you get zero from this
     * method, you can instead use the time of the first release of your software, as it's guaranteed no users will
     * have wallets pre-dating this time. <p>
     * 
     * If there are no keys in the wallet, the current time is returned.
     */
    public long getEarliestKeyCreationTime() {
        lock.lock();
        try {
            if (keychain.size() == 0) {
                return Utils.now().getTime() / 1000;
            }
            long earliestTime = Long.MAX_VALUE;
            for (ECKey key : keychain) {
                earliestTime = Math.min(key.getCreationTimeSeconds(), earliestTime);
            }
            return earliestTime;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the hash of the last seen best-chain block. */
    public Sha256Hash getLastBlockSeenHash() {
        lock.lock();
        try {
            return lastBlockSeenHash;
        } finally {
            lock.unlock();
        }
    }

    public void setLastBlockSeenHash(Sha256Hash lastBlockSeenHash) {
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

    /** Returns the height of the last seen best-chain block. Can be -1 if a wallet is old and doesn't have that data. */
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

            if (autosaveToFile != null) {
                autoSave();
            }
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

            if (autosaveToFile != null) {
                autoSave();
            }
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
            if (keyCrypter == null) {
                // The password cannot decrypt anything as the keyCrypter is null.
                return false;
            }
            return checkAESKey(keyCrypter.deriveKey(checkNotNull(password)));
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

    /**
     * Gets the number of elements that will be added to a bloom filter returned by getBloomFilter
     */
    public int getBloomFilterElementCount() {
        int size = getKeychainSize() * 2;
        for (Transaction tx : getTransactions(false)) {
            for (TransactionOutput out : tx.getOutputs()) {
                try {
                    if (out.isMine(this) && out.getScriptPubKey().isSentToRawPubKey())
                        size++;
                } catch (ScriptException e) {
                    throw new RuntimeException(e); // If it is ours, we parsed the script corectly, so this shouldn't happen
                }
            }
        }
        return size;
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
    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
        BloomFilter filter = new BloomFilter(size, falsePositiveRate, nTweak);
        lock.lock();
        try {
            for (ECKey key : keychain) {
                filter.insert(key.getPubKey());
                filter.insert(key.getPubKeyHash());
            }
        } finally {
            lock.unlock();
        }
        for (Transaction tx : getTransactions(false)) {
            for (int i = 0; i < tx.getOutputs().size(); i++) {
                TransactionOutput out = tx.getOutputs().get(i);
                try {
                    if (out.isMine(this) && out.getScriptPubKey().isSentToRawPubKey()) {
                        TransactionOutPoint outPoint = new TransactionOutPoint(params, i, tx);
                        filter.insert(outPoint.bitcoinSerialize());
                    }
                } catch (ScriptException e) {
                    throw new RuntimeException(e); // If it is ours, we parsed the script corectly, so this shouldn't happen
                }
            }
        }
        return filter;
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
     * that were created by this wallet, but not others.
     */
    public void setCoinSelector(CoinSelector coinSelector) {
        lock.lock();
        try {
            this.coinSelector = coinSelector;
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
        setCoinSelector(Wallet.AllowUnconfirmedCoinSelector.get());
    }

    /**
     * Returns a future that will complete when the balance of the given type is equal or larger to the given value.
     * If the wallet already has a large enough balance the future is returned in a pre-completed state. Note that this
     * method is not blocking, if you want to <i>actually</i> wait immediately, you have to call .get() on the result.
     */
    public ListenableFuture<BigInteger> getBalanceFuture(final BigInteger value, final BalanceType type) {
        final SettableFuture<BigInteger> future = SettableFuture.create();
        final BigInteger current = getBalance(type);
        if (current.compareTo(value) >= 0) {
            // Already have enough.
            future.set(current);
            return future;
        }
        addEventListener(new AbstractWalletEventListener() {
            private boolean done = false;

            @Override
            public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
                check();
            }

            private void check() {
                final BigInteger newBalance = getBalance(type);
                if (!done && newBalance.compareTo(value) >= 0) {
                    // Have enough now.
                    done = true;
                    removeEventListener(this);
                    future.set(newBalance);
                }
            }

            @Override
            public void onCoinsReceived(Wallet w, Transaction t, BigInteger b1, BigInteger b2) {
                check();
            }
        });
        return future;
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
            queueAutoSave();
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
            queueAutoSave();
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
            queueAutoSave();
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
    // Boilerplate for running event listeners - unlocks the wallet, runs, re-locks.

    private void invokeOnTransactionConfidenceChanged(Transaction tx) {
        checkState(lock.isLocked());
        lock.unlock();
        try {
            for (WalletEventListener listener : eventListeners) {
                listener.onTransactionConfidenceChanged(this, tx);
            }
        } finally {
            lock.lock();
        }
    }

    private int onWalletChangedSuppressions = 0;
    private void invokeOnWalletChanged() {
        // Don't invoke the callback in some circumstances, eg, whilst we are re-organizing or fiddling with
        // transactions due to a new block arriving. It will be called later instead.
        checkState(lock.isLocked());
        Preconditions.checkState(onWalletChangedSuppressions >= 0);
        if (onWalletChangedSuppressions > 0) return;
        lock.unlock();
        try {
            for (WalletEventListener listener : eventListeners) {
                listener.onWalletChanged(this);
            }
        } finally {
            lock.lock();
        }
    }

    private void invokeOnCoinsReceived(Transaction tx, BigInteger balance, BigInteger newBalance) {
        checkState(lock.isLocked());
        lock.unlock();
        try {
            for (WalletEventListener listener : eventListeners) {
                listener.onCoinsReceived(Wallet.this, tx, balance, newBalance);
            }
        } finally {
            lock.lock();
        }
    }

    private void invokeOnCoinsSent(Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
        checkState(lock.isLocked());
        lock.unlock();
        try {
            for (WalletEventListener listener : eventListeners) {
                listener.onCoinsSent(Wallet.this, tx, prevBalance, newBalance);
            }
        } finally {
            lock.lock();
        }
    }

    private void invokeOnReorganize() {
        checkState(lock.isLocked());
        lock.unlock();
        try {
            for (WalletEventListener listener : eventListeners) {
                listener.onReorganize(Wallet.this);
            }
        } finally {
            lock.lock();
        }
    }

    private class FeeCalculation {
        private CoinSelection bestCoinSelection;
        private TransactionOutput bestChangeOutput;

        public FeeCalculation(SendRequest req, BigInteger value, List<TransactionInput> originalInputs,
                              boolean needAtLeastReferenceFee, LinkedList<TransactionOutput> candidates) throws InsufficientMoneyException {
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
            BigInteger valueNeeded;
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
                CoinSelection selection = coinSelector.select(valueNeeded, candidates);
                // Can we afford this?
                if (selection.valueGathered.compareTo(valueNeeded) < 0)
                    break;
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
                log.warn("Insufficient value in wallet for send: needed {}", bitcoinValueToFriendlyString(valueNeeded));
                throw new InsufficientMoneyException();
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

        private int estimateBytesForSigning(CoinSelection selection) {
            int size = 0;
            for (TransactionOutput output : selection.gathered) {
                try {
                    if (output.getScriptPubKey().isSentToAddress()) {
                        // Send-to-address spends usually take maximum pubkey.length (as it may be compressed or not) + 75 bytes
                        size += findKeyFromPubHash(output.getScriptPubKey().getPubKeyHash()).getPubKey().length + 75;
                    } else if (output.getScriptPubKey().isSentToRawPubKey())
                        size += 74; // Send-to-pubkey spends usually take maximum 74 bytes to spend
                    else
                        throw new RuntimeException("Unknown output type returned in coin selection");
                } catch (ScriptException e) {
                    // If this happens it means an output script in a wallet tx could not be understood. That should never
                    // happen, if it does it means the wallet has got into an inconsistent state.
                    throw new RuntimeException(e);
                }
            }
            return size;
        }

        private void resetTxInputs(SendRequest req, List<TransactionInput> originalInputs) {
            req.tx.clearInputs();
            for (TransactionInput input : originalInputs)
                req.tx.addInput(input);
        }
    }
}
