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

package org.bitcoinj.core;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import com.google.common.base.Objects.ToStringHelper;
import com.google.common.collect.*;
import com.google.common.primitives.Ints;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.google.protobuf.ByteString;
import net.jcip.annotations.GuardedBy;
import org.bitcoin.protocols.payments.Protos.PaymentDetails;
import org.bitcoinj.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.signers.MissingSigResolutionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.store.UnreadableWalletException;
import org.bitcoinj.store.WalletProtobufSerializer;
import org.bitcoinj.utils.BaseTaggableObject;
import org.bitcoinj.utils.ExchangeRate;
import org.bitcoinj.utils.ListenerRegistration;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.*;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;
import org.bitcoinj.wallet.WalletTransaction.Pool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

import java.io.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static com.google.common.base.Preconditions.*;

// To do list:
//
// - Take all wallet-relevant data out of Transaction and put it into WalletTransaction. Make Transaction immutable.
// - Only store relevant transaction outputs, don't bother storing the rest of the data. Big RAM saving.
// - Split block chain and tx output tracking into a superclass that doesn't have any key or spending related code.
// - Simplify how transactions are tracked and stored: in particular, have the wallet maintain positioning information
//   for transactions independent of the transactions themselves, so the timeline can be walked without having to
//   process and sort every single transaction.
// - Split data persistence out into a backend class and make the wallet transactional, so we can store a wallet
//   in a database not just in RAM.
// - Make clearing of transactions able to only rewind the wallet a certain distance instead of all blocks.
// - Make it scale:
//     - eliminate all the algorithms with quadratic complexity (or worse)
//     - don't require everything to be held in RAM at once
//     - consider allowing eviction of no longer re-orgable transactions or keys that were used up
//
// Finally, find more ways to break the class up and decompose it. Currently every time we move code out, other code
// fills up the lines saved!

/**
 * <p>A Wallet stores keys and a record of transactions that send and receive value from those keys. Using these,
 * it is able to create new transactions that spend the recorded transactions, and this is the fundamental operation
 * of the Bitcoin protocol.</p>
 *
 * <p>To learn more about this class, read <b><a href="https://bitcoinj.github.io/working-with-the-wallet">
 *     working with the wallet.</a></b></p>
 *
 * <p>To fill up a Wallet with transactions, you need to use it in combination with a {@link BlockChain} and various
 * other objects, see the <a href="https://bitcoinj.github.io/getting-started">Getting started</a> tutorial
 * on the website to learn more about how to set everything up.</p>
 *
 * <p>Wallets can be serialized using either Java serialization - this is not compatible across versions of bitcoinj,
 * or protocol buffer serialization. You need to save the wallet whenever it changes, there is an auto-save feature
 * that simplifies this for you although you're still responsible for manually triggering a save when your app is about
 * to quit because the auto-save feature waits a moment before actually committing to disk to avoid IO thrashing when
 * the wallet is changing very fast (eg due to a block chain sync). See
 * {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, org.bitcoinj.wallet.WalletFiles.Listener)}
 * for more information about this.</p>
 */
public class Wallet extends BaseTaggableObject implements Serializable, BlockChainListener, PeerFilterProvider, KeyBag, TransactionBag {
    private static final Logger log = LoggerFactory.getLogger(Wallet.class);
    private static final long serialVersionUID = 2L;
    private static final int MINIMUM_BLOOM_DATA_LENGTH = 8;

    // Ordering: lock > keychainLock. Keychain is protected separately to allow fast querying of current receive address
    // even if the wallet itself is busy e.g. saving or processing a big reorg. Useful for reducing UI latency.
    protected final ReentrantLock lock = Threading.lock("wallet");
    protected final ReentrantLock keychainLock = Threading.lock("wallet-keychain");

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

    @VisibleForTesting final Map<Sha256Hash, Transaction> pending;
    @VisibleForTesting final Map<Sha256Hash, Transaction> unspent;
    @VisibleForTesting final Map<Sha256Hash, Transaction> spent;
    @VisibleForTesting final Map<Sha256Hash, Transaction> dead;

    // All transactions together.
    protected final Map<Sha256Hash, Transaction> transactions;

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

    // The key chain group is not thread safe, and generally the whole hierarchy of objects should not be mutated
    // outside the wallet lock. So don't expose this object directly via any accessors!
    @GuardedBy("keychainLock") protected KeyChainGroup keychain;

    // A list of scripts watched by this wallet.
    private Set<Script> watchedScripts;

    protected final NetworkParameters params;

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
    protected volatile WalletFiles vFileManager;
    // Object that is used to send transactions asynchronously when the wallet requires it.
    protected volatile TransactionBroadcaster vTransactionBroadcaster;
    // UNIX time in seconds. Money controlled by keys created before this time will be automatically respent to a key
    // that was created after it. Useful when you believe some keys have been compromised.
    private volatile long vKeyRotationTimestamp;

    protected transient CoinSelector coinSelector = new DefaultCoinSelector();

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

    // Objects that perform transaction signing. Applied subsequently one after another
    @GuardedBy("lock") private List<TransactionSigner> signers;

    /**
     * Creates a new, empty wallet with no keys and no transactions. If you want to restore a wallet from disk instead,
     * see loadFromFile.
     */
    public Wallet(NetworkParameters params) {
        this(params, new KeyChainGroup(params));
    }

    public static Wallet fromSeed(NetworkParameters params, DeterministicSeed seed) {
        return new Wallet(params, new KeyChainGroup(params, seed));
    }

    /**
     * Creates a wallet that tracks payments to and from the HD key hierarchy rooted by the given watching key. A
     * watching key corresponds to account zero in the recommended BIP32 key hierarchy.
     */
    public static Wallet fromWatchingKey(NetworkParameters params, DeterministicKey watchKey, long creationTimeSeconds) {
        return new Wallet(params, new KeyChainGroup(params, watchKey, creationTimeSeconds));
    }

    /**
     * Creates a wallet that tracks payments to and from the HD key hierarchy rooted by the given watching key. A
     * watching key corresponds to account zero in the recommended BIP32 key hierarchy.
     */
    public static Wallet fromWatchingKey(NetworkParameters params, DeterministicKey watchKey) {
        return new Wallet(params, new KeyChainGroup(params, watchKey));
    }

    // TODO: When this class moves to the Wallet package, along with the protobuf serializer, then hide this.
    /** For internal use only. */
    public Wallet(NetworkParameters params, KeyChainGroup keyChainGroup) {
        this.params = checkNotNull(params);
        this.keychain = checkNotNull(keyChainGroup);
        if (params == UnitTestParams.get())
            this.keychain.setLookaheadSize(5);  // Cut down excess computation for unit tests.
        // If this keychain was created fresh just now (new wallet), make HD so a backup can be made immediately
        // without having to call current/freshReceiveKey. If there are already keys in the chain of any kind then
        // we're probably being deserialized so leave things alone: the API user can upgrade later.
        if (this.keychain.numKeys() == 0)
            this.keychain.createAndActivateNewHDChain();
        watchedScripts = Sets.newHashSet();
        unspent = new HashMap<Sha256Hash, Transaction>();
        spent = new HashMap<Sha256Hash, Transaction>();
        pending = new HashMap<Sha256Hash, Transaction>();
        dead = new HashMap<Sha256Hash, Transaction>();
        transactions = new HashMap<Sha256Hash, Transaction>();
        eventListeners = new CopyOnWriteArrayList<ListenerRegistration<WalletEventListener>>();
        extensions = new HashMap<String, WalletExtension>();
        // Use a linked hash map to ensure ordering of event listeners is correct.
        confidenceChanged = new LinkedHashMap<Transaction, TransactionConfidence.Listener.ChangeReason>();
        signers = new ArrayList<TransactionSigner>();
        addTransactionSigner(new LocalTransactionSigner());
        createTransientState();
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
     * Returns the number of signatures required to spend from this wallet. For a normal non-married wallet this will
     * always be 1. For a married wallet this will be the N from N-of-M CHECKMULTISIG scripts used in this wallet.
     * This value is either directly specified during the marriage (see {@link #addFollowingAccountKeys(java.util.List, int)})
     * or, if not specified, calculated implicitly as a simple majority of keys.
     */
    public int getSigsRequiredToSpend() {
        lock.lock();
        try {
            return keychain.getSigsRequiredToSpend();
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Adds given transaction signer to the list of signers. It will be added to the end of the signers list, so if
     * this wallet already has some signers added, given signer will be executed after all of them.</p>
     * <p>Transaction signer should be fully initialized before adding to the wallet, otherwise {@link IllegalStateException}
     * will be thrown</p>
     */
    public void addTransactionSigner(TransactionSigner signer) {
        lock.lock();
        try {
            if (signer.isReady())
                signers.add(signer);
            else
                throw new IllegalStateException("Signer instance is not ready to be added into Wallet: " + signer.getClass());
        } finally {
            lock.unlock();
        }
    }

    public List<TransactionSigner> getTransactionSigners() {
        lock.lock();
        try {
            return ImmutableList.copyOf(signers);
        } finally {
            lock.unlock();
        }
    }

    /******************************************************************************************************************/

    //region Key Management

    /**
     * Returns a key that hasn't been seen in a transaction yet, and which is suitable for displaying in a wallet
     * user interface as "a convenient key to receive funds on" when the purpose parameter is
     * {@link org.bitcoinj.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS}. The returned key is stable until
     * it's actually seen in a pending or confirmed transaction, at which point this method will start returning
     * a different key (for each purpose independently).
     */
    public DeterministicKey currentKey(KeyChain.KeyPurpose purpose) {
        keychainLock.lock();
        try {
            maybeUpgradeToHD();
            return keychain.currentKey(purpose);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * An alias for calling {@link #currentKey(org.bitcoinj.wallet.KeyChain.KeyPurpose)} with
     * {@link org.bitcoinj.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
    public DeterministicKey currentReceiveKey() {
        return currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
    }

    /**
     * Returns address for a {@link #currentKey(org.bitcoinj.wallet.KeyChain.KeyPurpose)}
     */
    public Address currentAddress(KeyChain.KeyPurpose purpose) {
        keychainLock.lock();
        try {
            maybeUpgradeToHD();
            return keychain.currentAddress(purpose);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * An alias for calling {@link #currentAddress(org.bitcoinj.wallet.KeyChain.KeyPurpose)} with
     * {@link org.bitcoinj.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
    public Address currentReceiveAddress() {
        return currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
    }

    /**
     * Returns a key that has not been returned by this method before (fresh). You can think of this as being
     * a newly created key, although the notion of "create" is not really valid for a
     * {@link org.bitcoinj.wallet.DeterministicKeyChain}. When the parameter is
     * {@link org.bitcoinj.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key out
     * to someone who wishes to send money.
     */
    public DeterministicKey freshKey(KeyChain.KeyPurpose purpose) {
        return freshKeys(purpose, 1).get(0);
    }

    /**
     * Returns a key/s that has not been returned by this method before (fresh). You can think of this as being
     * a newly created key/s, although the notion of "create" is not really valid for a
     * {@link org.bitcoinj.wallet.DeterministicKeyChain}. When the parameter is
     * {@link org.bitcoinj.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key/s out
     * to someone who wishes to send money.
     */
    public List<DeterministicKey> freshKeys(KeyChain.KeyPurpose purpose, int numberOfKeys) {
        List<DeterministicKey> keys;
        keychainLock.lock();
        try {
            maybeUpgradeToHD();
            keys = keychain.freshKeys(purpose, numberOfKeys);
        } finally {
            keychainLock.unlock();
        }
        // Do we really need an immediate hard save? Arguably all this is doing is saving the 'current' key
        // and that's not quite so important, so we could coalesce for more performance.
        saveNow();
        return keys;
    }

    /**
     * An alias for calling {@link #freshKey(org.bitcoinj.wallet.KeyChain.KeyPurpose)} with
     * {@link org.bitcoinj.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
    public DeterministicKey freshReceiveKey() {
        return freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
    }

    /**
     * Returns address for a {@link #freshKey(org.bitcoinj.wallet.KeyChain.KeyPurpose)}
     */
    public Address freshAddress(KeyChain.KeyPurpose purpose) {
        Address key;
        keychainLock.lock();
        try {
            key = keychain.freshAddress(purpose);
        } finally {
            keychainLock.unlock();
        }
        saveNow();
        return key;
    }

    /**
     * An alias for calling {@link #freshAddress(org.bitcoinj.wallet.KeyChain.KeyPurpose)} with
     * {@link org.bitcoinj.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
    public Address freshReceiveAddress() {
        return freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
    }

    /**
     * Returns only the keys that have been issued by {@link #freshReceiveKey()}, {@link #freshReceiveAddress()},
     * {@link #currentReceiveKey()} or {@link #currentReceiveAddress()}.
     */
    public List<ECKey> getIssuedReceiveKeys() {
        keychainLock.lock();
        try {
            return keychain.getActiveKeyChain().getIssuedReceiveKeys();
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Returns only the addresses that have been issued by {@link #freshReceiveKey()}, {@link #freshReceiveAddress()},
     * {@link #currentReceiveKey()} or {@link #currentReceiveAddress()}.
     */
    public List<Address> getIssuedReceiveAddresses() {
        final List<ECKey> keys = getIssuedReceiveKeys();
        List<Address> addresses = new ArrayList<Address>(keys.size());
        for (ECKey key : keys)
            addresses.add(key.toAddress(getParams()));
        return addresses;
    }

    /**
     * Upgrades the wallet to be deterministic (BIP32). You should call this, possibly providing the users encryption
     * key, after loading a wallet produced by previous versions of bitcoinj. If the wallet is encrypted the key
     * <b>must</b> be provided, due to the way the seed is derived deterministically from private key bytes: failing
     * to do this will result in an exception being thrown. For non-encrypted wallets, the upgrade will be done for
     * you automatically the first time a new key is requested (this happens when spending due to the change address).
     */
    public void upgradeToDeterministic(@Nullable KeyParameter aesKey) throws DeterministicUpgradeRequiresPassword {
        keychainLock.lock();
        try {
            keychain.upgradeToDeterministic(vKeyRotationTimestamp, aesKey);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Returns true if the wallet contains random keys and no HD chains, in which case you should call
     * {@link #upgradeToDeterministic(org.spongycastle.crypto.params.KeyParameter)} before attempting to do anything
     * that would require a new address or key.
     */
    public boolean isDeterministicUpgradeRequired() {
        keychainLock.lock();
        try {
            return keychain.isDeterministicUpgradeRequired();
        } finally {
            keychainLock.unlock();
        }
    }

    private void maybeUpgradeToHD() throws DeterministicUpgradeRequiresPassword {
        maybeUpgradeToHD(null);
    }

    @GuardedBy("keychainLock")
    private void maybeUpgradeToHD(@Nullable KeyParameter aesKey) throws DeterministicUpgradeRequiresPassword {
        checkState(keychainLock.isHeldByCurrentThread());
        if (keychain.isDeterministicUpgradeRequired()) {
            log.info("Upgrade to HD wallets is required, attempting to do so.");
            try {
                upgradeToDeterministic(aesKey);
            } catch (DeterministicUpgradeRequiresPassword e) {
                log.error("Failed to auto upgrade due to encryption. You should call wallet.upgradeToDeterministic " +
                        "with the users AES key to avoid this error.");
                throw e;
            }
        }
    }

    /**
     * Returns a snapshot of the watched scripts. This view is not live.
     */
    public List<Script> getWatchedScripts() {
        keychainLock.lock();
        try {
            return new ArrayList<Script>(watchedScripts);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Removes the given key from the basicKeyChain. Be very careful with this - losing a private key <b>destroys the
     * money associated with it</b>.
     * @return Whether the key was removed or not.
     */
    public boolean removeKey(ECKey key) {
        keychainLock.lock();
        try {
            return keychain.removeImportedKey(key);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Returns the number of keys in the key chain, including lookahead keys.
     */
    public int getKeychainSize() {
        keychainLock.lock();
        try {
            return keychain.numKeys();
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Returns a list of the non-deterministic keys that have been imported into the wallet, or the empty list if none.
     */
    public List<ECKey> getImportedKeys() {
        keychainLock.lock();
        try {
            return keychain.getImportedKeys();
        } finally {
            keychainLock.unlock();
        }
    }

    /** Returns the address used for change outputs. Note: this will probably go away in future. */
    public Address getChangeAddress() {
        return currentAddress(KeyChain.KeyPurpose.CHANGE);
    }

    /**
     * <p>Deprecated alias for {@link #importKey(ECKey)}.</p>
     *
     * <p><b>Replace with either {@link #freshReceiveKey()} if your call is addKey(new ECKey()), or with {@link #importKey(ECKey)}
     * which does the same thing this method used to, but with a better name.</b></p>
     */
    @Deprecated
    public boolean addKey(ECKey key) {
        return importKey(key);
    }

    /**
     * <p>Imports the given ECKey to the wallet.</p>
     *
     * <p>If the wallet is configured to auto save to a file, triggers a save immediately. Runs the onKeysAdded event
     * handler. If the key already exists in the wallet, does nothing and returns false.</p>
     */
    public boolean importKey(ECKey key) {
        return importKeys(Lists.newArrayList(key)) == 1;
    }

    /** Replace with {@link #importKeys(java.util.List)}, which does the same thing but with a better name. */
    @Deprecated
    public int addKeys(List<ECKey> keys) {
        return importKeys(keys);
    }

    /**
     * Imports the given keys to the wallet.
     * If {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, org.bitcoinj.wallet.WalletFiles.Listener)}
     * has been called, triggers an auto save bypassing the normal coalescing delay and event handlers.
     * Returns the number of keys added, after duplicates are ignored. The onKeyAdded event will be called for each key
     * in the list that was not already present.
     */
    public int importKeys(final List<ECKey> keys) {
        // API usage check.
        checkNoDeterministicKeys(keys);
        int result;
        keychainLock.lock();
        try {
            result = keychain.importKeys(keys);
        } finally {
            keychainLock.unlock();
        }
        saveNow();
        return result;
    }

    private void checkNoDeterministicKeys(List<ECKey> keys) {
        // Watch out for someone doing wallet.importKey(wallet.freshReceiveKey()); or equivalent: we never tested this.
        for (ECKey key : keys)
            if (key instanceof DeterministicKey)
                throw new IllegalArgumentException("Cannot import HD keys back into the wallet");
    }

    /** Takes a list of keys and a password, then encrypts and imports them in one step using the current keycrypter. */
    public int importKeysAndEncrypt(final List<ECKey> keys, CharSequence password) {
        keychainLock.lock();
        try {
            checkNotNull(getKeyCrypter(), "Wallet is not encrypted");
            return importKeysAndEncrypt(keys, getKeyCrypter().deriveKey(password));
        } finally {
            keychainLock.unlock();
        }
    }

    /** Takes a list of keys and an AES key, then encrypts and imports them in one step using the current keycrypter. */
    public int importKeysAndEncrypt(final List<ECKey> keys, KeyParameter aesKey) {
        keychainLock.lock();
        try {
            checkNoDeterministicKeys(keys);
            return keychain.importKeysAndEncrypt(keys, aesKey);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * <p>Alias for <code>addFollowingAccountKeys(followingAccountKeys, (followingAccountKeys.size() + 1) / 2 + 1)</code></p>
     * <p>Creates married wallet requiring majority of keys to spend (2-of-3, 3-of-5 and so on)</p>
     * <p>IMPORTANT: As of Bitcoin Core 0.9 all multisig transactions which require more than 3 public keys are
     * non-standard and such spends won't be processed by peers with default settings, essentially making such
     * transactions almost nonspendable</p>
     */
    public void addFollowingAccountKeys(List<DeterministicKey> followingAccountKeys) {
        keychainLock.lock();
        try {
            keychain.addFollowingAccountKeys(followingAccountKeys);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Makes given account keys follow the account key of the active keychain. After that you will be able
     * to get P2SH addresses to receive coins to. Given threshold value specifies how many signatures required to
     * spend transactions for this married wallet. This value should not exceed total number of keys involved
     * (one followed key plus number of following keys).</p>
     * <p>IMPORTANT: As of Bitcoin Core 0.9 all multisig transactions which require more than 3 public keys are
     * non-standard and such spends won't be processed by peers with default settings, essentially making such
     * transactions almost nonspendable</p>
     * This method should be called only once before key rotation, otherwise it will throw an IllegalStateException.
     */
    public void addFollowingAccountKeys(List<DeterministicKey> followingAccountKeys, int threshold) {
        keychainLock.lock();
        try {
            keychain.addFollowingAccountKeys(followingAccountKeys, threshold);
        } finally {
            keychainLock.unlock();
        }
    }

    /** See {@link org.bitcoinj.wallet.DeterministicKeyChain#setLookaheadSize(int)} for more info on this. */
    public void setKeychainLookaheadSize(int lookaheadSize) {
        keychainLock.lock();
        try {
            keychain.setLookaheadSize(lookaheadSize);
        } finally {
            keychainLock.unlock();
        }
    }

    /** See {@link org.bitcoinj.wallet.DeterministicKeyChain#setLookaheadSize(int)} for more info on this. */
    public int getKeychainLookaheadSize() {
        keychainLock.lock();
        try {
            return keychain.getLookaheadSize();
        } finally {
            keychainLock.unlock();
        }
    }

    /** See {@link org.bitcoinj.wallet.DeterministicKeyChain#setLookaheadThreshold(int)} for more info on this. */
    public void setKeychainLookaheadThreshold(int num) {
        keychainLock.lock();
        try {
            maybeUpgradeToHD();
            keychain.setLookaheadThreshold(num);
        } finally {
            keychainLock.unlock();
        }
    }

    /** See {@link org.bitcoinj.wallet.DeterministicKeyChain#setLookaheadThreshold(int)} for more info on this. */
    public int getKeychainLookaheadThreshold() {
        keychainLock.lock();
        try {
            maybeUpgradeToHD();
            return keychain.getLookaheadThreshold();
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Returns a public-only DeterministicKey that can be used to set up a watching wallet: that is, a wallet that
     * can import transactions from the block chain just as the normal wallet can, but which cannot spend. Watching
     * wallets are very useful for things like web servers that accept payments. This key corresponds to the account
     * zero key in the recommended BIP32 hierarchy.
     */
    public DeterministicKey getWatchingKey() {
        keychainLock.lock();
        try {
            maybeUpgradeToHD();
            return keychain.getActiveKeyChain().getWatchingKey();
        } finally {
            keychainLock.unlock();
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
        int added = 0;
        keychainLock.lock();
        try {
            for (final Script script : scripts) {
                if (watchedScripts.contains(script)) continue;
                watchedScripts.add(script);
                added++;
            }
        } finally {
            keychainLock.unlock();
        }
        queueOnScriptsAdded(scripts);
        saveNow();
        return added;
    }

    /**
     * Returns all addresses watched by this wallet.
     */
    public List<Address> getWatchedAddresses() {
        keychainLock.lock();
        try {
            List<Address> addresses = new LinkedList<Address>();
            for (Script script : watchedScripts)
                if (script.isSentToAddress())
                    addresses.add(script.getToAddress(params));
            return addresses;
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Locates a keypair from the basicKeyChain given the hash of the public key. This is needed when finding out which
     * key we need to use to redeem a transaction output.
     *
     * @return ECKey object or null if no such key was found.
     */
    @Override
    @Nullable
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        keychainLock.lock();
        try {
            return keychain.findKeyFromPubHash(pubkeyHash);
        } finally {
            keychainLock.unlock();
        }
    }

    /** Returns true if the given key is in the wallet, false otherwise. Currently an O(N) operation. */
    public boolean hasKey(ECKey key) {
        keychainLock.lock();
        try {
            return keychain.hasKey(key);
        } finally {
            keychainLock.unlock();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean isPubKeyHashMine(byte[] pubkeyHash) {
        return findKeyFromPubHash(pubkeyHash) != null;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isWatchedScript(Script script) {
        keychainLock.lock();
        try {
            return watchedScripts.contains(script);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Locates a keypair from the basicKeyChain given the raw public key bytes.
     * @return ECKey or null if no such key was found.
     */
    @Override
    @Nullable
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        keychainLock.lock();
        try {
            return keychain.findKeyFromPubKey(pubkey);
        } finally {
            keychainLock.unlock();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean isPubKeyMine(byte[] pubkey) {
        return findKeyFromPubKey(pubkey) != null;
    }

    /**
     * Locates a redeem data (redeem script and keys) from the keychain given the hash of the script.
     * Returns RedeemData object or null if no such data was found.
     */
    @Nullable
    @Override
    public RedeemData findRedeemDataFromScriptHash(byte[] payToScriptHash) {
        keychainLock.lock();
        try {
            return keychain.findRedeemDataFromScriptHash(payToScriptHash);
        } finally {
            keychainLock.unlock();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean isPayToScriptHashMine(byte[] payToScriptHash) {
        return findRedeemDataFromScriptHash(payToScriptHash) != null;
    }

    /**
     * Marks all keys used in the transaction output as used in the wallet.
     * See {@link org.bitcoinj.wallet.DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    private void markKeysAsUsed(Transaction tx) {
        keychainLock.lock();
        try {
            for (TransactionOutput o : tx.getOutputs()) {
                try {
                    Script script = o.getScriptPubKey();
                    if (script.isSentToRawPubKey()) {
                        byte[] pubkey = script.getPubKey();
                        keychain.markPubKeyAsUsed(pubkey);
                    } else if (script.isSentToAddress()) {
                        byte[] pubkeyHash = script.getPubKeyHash();
                        keychain.markPubKeyHashAsUsed(pubkeyHash);
                    } else if (script.isPayToScriptHash() && keychain.isMarried()) {
                        Address a = Address.fromP2SHScript(tx.getParams(), script);
                        keychain.markP2SHAddressAsUsed(a);
                    }
                } catch (ScriptException e) {
                    // Just means we didn't understand the output of this transaction: ignore it.
                    log.warn("Could not parse tx output script: {}", e.toString());
                }
            }
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Returns the immutable seed for the current active HD chain.
     * @throws org.bitcoinj.core.ECKey.MissingPrivateKeyException if the seed is unavailable (watching wallet)
     */
    public DeterministicSeed getKeyChainSeed() {
        keychainLock.lock();
        try {
            DeterministicSeed seed = keychain.getActiveKeyChain().getSeed();
            if (seed == null)
                throw new ECKey.MissingPrivateKeyException();
            return seed;
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Returns a key for the given HD path, assuming it's already been derived. You normally shouldn't use this:
     * use currentReceiveKey/freshReceiveKey instead.
     */
    public DeterministicKey getKeyByPath(List<ChildNumber> path) {
        keychainLock.lock();
        try {
            maybeUpgradeToHD();
            return keychain.getActiveKeyChain().getKeyByPath(path, false);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Convenience wrapper around {@link Wallet#encrypt(org.bitcoinj.crypto.KeyCrypter,
     * org.spongycastle.crypto.params.KeyParameter)} which uses the default Scrypt key derivation algorithm and
     * parameters to derive a key from the given password.
     */
    public void encrypt(CharSequence password) {
        keychainLock.lock();
        try {
            final KeyCrypterScrypt scrypt = new KeyCrypterScrypt();
            keychain.encrypt(scrypt, scrypt.deriveKey(password));
        } finally {
            keychainLock.unlock();
        }
        saveNow();
    }

    /**
     * Encrypt the wallet using the KeyCrypter and the AES key. A good default KeyCrypter to use is
     * {@link org.bitcoinj.crypto.KeyCrypterScrypt}.
     *
     * @param keyCrypter The KeyCrypter that specifies how to encrypt/ decrypt a key
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming to create from a password)
     * @throws KeyCrypterException Thrown if the wallet encryption fails. If so, the wallet state is unchanged.
     */
    public void encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        keychainLock.lock();
        try {
            keychain.encrypt(keyCrypter, aesKey);
        } finally {
            keychainLock.unlock();
        }
        saveNow();
    }

    /**
     * Decrypt the wallet with the wallets keyCrypter and password.
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
    public void decrypt(CharSequence password) {
        keychainLock.lock();
        try {
            final KeyCrypter crypter = keychain.getKeyCrypter();
            checkState(crypter != null, "Not encrypted");
            keychain.decrypt(crypter.deriveKey(password));
        } finally {
            keychainLock.unlock();
        }
        saveNow();
    }

    /**
     * Decrypt the wallet with the wallets keyCrypter and AES key.
     *
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming to create from a password)
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
    public void decrypt(KeyParameter aesKey) {
        keychainLock.lock();
        try {
            keychain.decrypt(aesKey);
        } finally {
            keychainLock.unlock();
        }
        saveNow();
    }

    /**
     *  Check whether the password can decrypt the first key in the wallet.
     *  This can be used to check the validity of an entered password.
     *
     *  @return boolean true if password supplied can decrypt the first private key in the wallet, false otherwise.
     *  @throws IllegalStateException if the wallet is not encrypted.
     */
    public boolean checkPassword(CharSequence password) {
        keychainLock.lock();
        try {
            return keychain.checkPassword(password);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     *  Check whether the AES key can decrypt the first encrypted key in the wallet.
     *
     *  @return boolean true if AES key supplied can decrypt the first encrypted private key in the wallet, false otherwise.
     */
    public boolean checkAESKey(KeyParameter aesKey) {
        keychainLock.lock();
        try {
            return keychain.checkAESKey(aesKey);
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Get the wallet's KeyCrypter, or null if the wallet is not encrypted.
     * (Used in encrypting/ decrypting an ECKey).
     */
    @Nullable
    public KeyCrypter getKeyCrypter() {
        keychainLock.lock();
        try {
            return keychain.getKeyCrypter();
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Get the type of encryption used for this wallet.
     *
     * (This is a convenience method - the encryption type is actually stored in the keyCrypter).
     */
    public EncryptionType getEncryptionType() {
        keychainLock.lock();
        try {
            KeyCrypter crypter = keychain.getKeyCrypter();
            if (crypter != null)
                return crypter.getUnderstoodEncryptionType();
            else
                return EncryptionType.UNENCRYPTED;
        } finally {
            keychainLock.unlock();
        }
    }

    /** Returns true if the wallet is encrypted using any scheme, false if not. */
    public boolean isEncrypted() {
        return getEncryptionType() != EncryptionType.UNENCRYPTED;
    }

    //endregion

    /******************************************************************************************************************/

    //region Serialization support

    // TODO: Make this package private once the classes finish moving around.
    /** Internal use only. */
    public List<Protos.Key> serializeKeychainToProtobuf() {
        keychainLock.lock();
        try {
            return keychain.serializeToProtobuf();
        } finally {
            keychainLock.unlock();
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
     * {@link Wallet#autosaveToFile(java.io.File, long, java.util.concurrent.TimeUnit, org.bitcoinj.wallet.WalletFiles.Listener)}
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

    /** Requests an asynchronous save on a background thread */
    protected void saveLater() {
        WalletFiles files = vFileManager;
        if (files != null)
            files.saveLater();
    }

    /** If auto saving is enabled, do an immediate sync write to disk ignoring any delays. */
    protected void saveNow() {
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

    //endregion

    /******************************************************************************************************************/

    //region Inbound transaction reception and processing

    /**
     * Called by the {@link BlockChain} when we receive a new filtered block that contains a transactions previously
     * received by a call to {@link #receivePending}.<p>
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
            return true;
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
            Coin valueSentToMe = tx.getValueSentToMe(this);
            Coin valueSentFromMe = tx.getValueSentFromMe(this);
            if (log.isInfoEnabled()) {
                log.info(String.format("Received a pending transaction %s that spends %s from our own wallet," +
                        " and sends us %s", tx.getHashAsString(), valueSentFromMe.toFriendlyString(),
                        valueSentToMe.toFriendlyString()));
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
                log.warn("Pending transaction was considered risky: {}\n{}", analysis, tx);
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
     * and also returns true if tx has inputs that are spending outputs which are
     * not ours but which are spent by pending transactions.</p>
     *
     * <p>Note that if the tx has inputs containing one of our keys, but the connected transaction is not in the wallet,
     * it will not be considered relevant.</p>
     */
    @Override
    public boolean isTransactionRelevant(Transaction tx) throws ScriptException {
        lock.lock();
        try {
            return tx.getValueSentFromMe(this).signum() > 0 ||
                   tx.getValueSentToMe(this).signum() > 0 ||
                   checkForDoubleSpendAgainstPending(tx, false);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Checks if "tx" is spending any inputs of pending transactions. Not a general check, but it can work even if
     * the double spent inputs are not ours.
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
    }

    private void receive(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType,
                         int relativityOffset) throws VerificationException {
        // Runs in a peer thread.
        checkState(lock.isHeldByCurrentThread());
        Coin prevBalance = getBalance();
        Sha256Hash txHash = tx.getHash();
        boolean bestChain = blockType == BlockChain.NewBlockType.BEST_CHAIN;
        boolean sideChain = blockType == BlockChain.NewBlockType.SIDE_CHAIN;

        Coin valueSentFromMe = tx.getValueSentFromMe(this);
        Coin valueSentToMe = tx.getValueSentToMe(this);
        Coin valueDifference = valueSentToMe.subtract(valueSentFromMe);

        log.info("Received tx{} for {}: {} [{}] in block {}", sideChain ? " on a side chain" : "",
                valueDifference.toFriendlyString(), tx.getHashAsString(), relativityOffset,
                block != null ? block.getHeader().getHash() : "(unit test)");

        // Inform the key chains that the issued keys were observed in a transaction, so they know to
        // calculate more keys for the next Bloom filters.
        markKeysAsUsed(tx);

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
            // confidence object about the block and sets its depth appropriately.
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
            Coin newBalance = getBalance();  // This is slow.
            log.info("Balance is now: " + newBalance.toFriendlyString());
            if (!wasPending) {
                int diff = valueDifference.signum();
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
    @Override
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
            // This is so that they can update their depth.
            Set<Transaction> transactions = getTransactions(true);
            for (Transaction tx : transactions) {
                if (ignoreNextNewBlock.contains(tx.getHash())) {
                    // tx was already processed in receive() due to it appearing in this block, so we don't want to
                    // increment the tx confidence depth twice, it'd result in miscounting.
                    ignoreNextNewBlock.remove(tx.getHash());
                } else if (tx.getConfidence().getConfidenceType() == ConfidenceType.BUILDING) {
                    tx.getConfidence().incrementDepthInBlocks();
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
            // to a side chain but it can be switched back on a reorg and resurrected back to spent or unspent.
            // So take it out of the dead pool. Note that we don't resurrect dependent transactions here, even though
            // we could. Bitcoin Core nodes on the network have deleted the dependent transactions from their mempools
            // entirely by this point. We could and maybe should rebroadcast them so the network remembers and tries
            // to confirm them again. But this is a deeply unusual edge case that due to the maturity rule should never
            // happen in practice, thus for simplicities sake we ignore it here.
            log.info("  coinbase tx <-dead: confidence {}", tx.getHashAsString(),
                    tx.getConfidence().getConfidenceType().name());
            dead.remove(tx.getHash());
        }

        // Update tx and other unspent/pending transactions by connecting inputs/outputs.
        updateForSpends(tx, true);

        // Now make sure it ends up in the right pool. Also, handle the case where this TX is double-spending
        // against our pending transactions. Note that a tx may double spend our pending transactions and also send
        // us money/spend our money.
        boolean hasOutputsToMe = tx.getValueSentToMe(this, true).signum() > 0;
        if (hasOutputsToMe) {
            // Needs to go into either unspent or spent (if the outputs were already spent by a pending tx).
            if (tx.isEveryOwnedOutputSpent(this)) {
                log.info("  tx {} ->spent (by pending)", tx.getHashAsString());
                addWalletTransaction(Pool.SPENT, tx);
            } else {
                log.info("  tx {} ->unspent", tx.getHashAsString());
                addWalletTransaction(Pool.UNSPENT, tx);
            }
        } else if (tx.getValueSentFromMe(this).signum() > 0) {
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
                    // Can be:
                    // (1) We already marked this output as spent when we saw the pending transaction (most likely).
                    //     Now it's being confirmed of course, we cannot mark it as spent again.
                    // (2) A double spend from chain: this will be handled later by checkForDoubleSpendAgainstPending.
                    //
                    // In any case, nothing to do here.
                } else {
                    // We saw two pending transactions that double spend each other. We don't know which will win.
                    // This can happen in the case of bad network nodes that mutate transactions. Do a hex dump
                    // so the exact nature of the mutation can be examined.
                    log.warn("Saw two pending transactions double spend each other");
                    log.warn("  offending input is input {}", tx.getInputs().indexOf(input));
                    log.warn("{}: {}", tx.getHash(), Utils.HEX.encode(tx.unsafeBitcoinSerialize()));
                    Transaction other = input.getConnectedOutput().getSpentBy().getParentTransaction();
                    log.warn("{}: {}", other.getHash(), Utils.HEX.encode(tx.unsafeBitcoinSerialize()));
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
        // used by another wallet somewhere else. Also, unconfirmed transactions can arrive from the mempool in more or
        // less random order.
        for (Transaction pendingTx : pending.values()) {
            for (TransactionInput input : pendingTx.getInputs()) {
                TransactionInput.ConnectionResult result = input.connect(tx, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
                if (fromChain) {
                    // This TX is supposed to have just appeared on the best chain, so its outputs should not be marked
                    // as spent yet. If they are, it means something is happening out of order.
                    checkState(result != TransactionInput.ConnectionResult.ALREADY_SPENT);
                }
                if (result == TransactionInput.ConnectionResult.SUCCESS) {
                    log.info("Connected pending tx input {}:{}",
                            pendingTx.getHashAsString(), pendingTx.getInputs().indexOf(input));
                }
            }
        }
        if (!fromChain) {
            maybeMovePool(tx, "pendingtx");
        } else {
            // If the transactions outputs are now all spent, it will be moved into the spent pool by the
            // processTxFromBestChain method.
        }
    }

    // Updates the wallet when a double spend occurs. overridingTx can be null for the case of coinbases
    private void killTx(@Nullable Transaction overridingTx, List<Transaction> killedTx) {
        LinkedList<Transaction> work = new LinkedList<Transaction>(killedTx);
        while (!work.isEmpty()) {
            final Transaction tx = work.poll();
            log.warn("TX {} killed{}", tx.getHashAsString(),
                    overridingTx != null ? "by " + overridingTx.getHashAsString() : "");
            log.warn("Disconnecting each input and moving connected transactions.");
            // TX could be pending (finney attack), or in unspent/spent (coinbase killed by reorg).
            pending.remove(tx.getHash());
            unspent.remove(tx.getHash());
            spent.remove(tx.getHash());
            addWalletTransaction(Pool.DEAD, tx);
            for (TransactionInput deadInput : tx.getInputs()) {
                Transaction connected = deadInput.getOutpoint().fromTx;
                if (connected == null) continue;
                deadInput.disconnect();
                maybeMovePool(connected, "kill");
            }
            tx.getConfidence().setOverridingTransaction(overridingTx);
            confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.TYPE);
            // Now kill any transactions we have that depended on this one.
            for (TransactionOutput deadOutput : tx.getOutputs()) {
                TransactionInput connected = deadOutput.getSpentBy();
                if (connected == null) continue;
                final Transaction parentTransaction = connected.getParentTransaction();
                log.info("This death invalidated dependent tx {}", parentTransaction.getHash());
                work.push(parentTransaction);
            }
        }
        if (overridingTx == null)
            return;
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
            Coin balance = getBalance();
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
            // Mark any keys used in the outputs as "used", this allows wallet UI's to auto-advance the current key
            // they are showing to the user in qr codes etc.
            markKeysAsUsed(tx);
            try {
                Coin valueSentFromMe = tx.getValueSentFromMe(this);
                Coin valueSentToMe = tx.getValueSentToMe(this);
                Coin newBalance = balance.add(valueSentToMe).subtract(valueSentFromMe);
                if (valueSentToMe.signum() > 0) {
                    checkBalanceFuturesLocked(null);
                    queueOnCoinsReceived(tx, balance, newBalance);
                }
                if (valueSentFromMe.signum() > 0)
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

    //endregion

    /******************************************************************************************************************/

    //region Event listeners

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
        // This is thread safe, so we don't need to take the lock.
        eventListeners.add(new ListenerRegistration<WalletEventListener>(listener, executor));
        keychain.addEventListener(listener, executor);
    }

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
    public boolean removeEventListener(WalletEventListener listener) {
        keychain.removeEventListener(listener);
        return ListenerRegistration.removeFromList(listener, eventListeners);
    }

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

    protected void maybeQueueOnWalletChanged() {
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

    protected void queueOnCoinsReceived(final Transaction tx, final Coin balance, final Coin newBalance) {
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

    protected void queueOnCoinsSent(final Transaction tx, final Coin prevBalance, final Coin newBalance) {
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

    protected void queueOnReorganize() {
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

    protected void queueOnScriptsAdded(final List<Script> scripts) {
        for (final ListenerRegistration<WalletEventListener> registration : eventListeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onScriptsAdded(Wallet.this, scripts);
                }
            });
        }
    }

    //endregion

    /******************************************************************************************************************/

    //region Vending transactions and other internal state

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
            // Order by update time.
            Collections.sort(all, Transaction.SORT_TX_BY_UPDATE_TIME);
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

    /** {@inheritDoc} */
    @Override
    public Map<Sha256Hash, Transaction> getTransactionPool(Pool pool) {
        lock.lock();
        try {
            switch (pool) {
                case UNSPENT:
                    return unspent;
                case SPENT:
                    return spent;
                case PENDING:
                    return pending;
                case DEAD:
                    return dead;
                default:
                    throw new RuntimeException("Unknown wallet transaction type " + pool);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Prepares the wallet for a blockchain replay. Removes all transactions (as they would get in the way of the
     * replay) and makes the wallet think it has never seen a block. {@link WalletEventListener#onWalletChanged()} will
     * be fired.
     */
    public void reset() {
        lock.lock();
        try {
            clearTransactions();
            lastBlockSeenHash = null;
            lastBlockSeenHeight = -1; // Magic value for 'never'.
            lastBlockSeenTimeSecs = 0;
            saveLater();
            maybeQueueOnWalletChanged();
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
                clearTransactions();
                saveLater();
            } else {
                throw new UnsupportedOperationException();
            }
        } finally {
            lock.unlock();
        }
    }

    private void clearTransactions() {
        unspent.clear();
        spent.clear();
        pending.clear();
        dead.clear();
        transactions.clear();
    }

    /**
     * Returns all the outputs that match addresses or scripts added via {@link #addWatchedAddress(Address)} or
     * {@link #addWatchedScripts(java.util.List)}.
     * @param excludeImmatureCoinbases Whether to ignore outputs that are unspendable due to being immature.
     */
    public List<TransactionOutput> getWatchedOutputs(boolean excludeImmatureCoinbases) {
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

    @Override
    public String toString() {
        return toString(false, true, true, null);
    }


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
            Coin estimatedBalance = getBalance(BalanceType.ESTIMATED);
            Coin availableBalance = getBalance(BalanceType.AVAILABLE);
            builder.append(String.format("Wallet containing %s BTC (available: %s BTC) in:%n",
                    estimatedBalance.toPlainString(), availableBalance.toPlainString()));
            builder.append(String.format("  %d pending transactions%n", pending.size()));
            builder.append(String.format("  %d unspent transactions%n", unspent.size()));
            builder.append(String.format("  %d spent transactions%n", spent.size()));
            builder.append(String.format("  %d dead transactions%n", dead.size()));
            final Date lastBlockSeenTime = getLastBlockSeenTime();
            final String lastBlockSeenTimeStr = lastBlockSeenTime == null ? "time unknown" : lastBlockSeenTime.toString();
            builder.append(String.format("Last seen best block: %d (%s): %s%n",
                    getLastBlockSeenHeight(), lastBlockSeenTimeStr, getLastBlockSeenHash()));
            final KeyCrypter crypter = keychain.getKeyCrypter();
            if (crypter != null)
                builder.append(String.format("Encryption: %s%n", crypter));

            // Do the keys.
            builder.append("\nKeys:\n");
            final long keyRotationTime = vKeyRotationTimestamp * 1000;
            if (keyRotationTime > 0)
                builder.append(String.format("Key rotation time: %s\n", Utils.dateTimeFormat(keyRotationTime)));
            builder.append(keychain.toString(includePrivateKeys));

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
                    toStringHelper(builder, pending, chain, Transaction.SORT_TX_BY_UPDATE_TIME);
                }
                if (unspent.size() > 0) {
                    builder.append("\n>>> UNSPENT:\n");
                    toStringHelper(builder, unspent, chain, Transaction.SORT_TX_BY_HEIGHT);
                }
                if (spent.size() > 0) {
                    builder.append("\n>>> SPENT:\n");
                    toStringHelper(builder, spent, chain, Transaction.SORT_TX_BY_HEIGHT);
                }
                if (dead.size() > 0) {
                    builder.append("\n>>> DEAD:\n");
                    toStringHelper(builder, dead, chain, Transaction.SORT_TX_BY_UPDATE_TIME);
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
                builder.append(tx.getValueSentFromMe(this).toFriendlyString());
                builder.append(" and receives ");
                builder.append(tx.getValueSentToMe(this).toFriendlyString());
                builder.append(", total value ");
                builder.append(tx.getValue(this).toFriendlyString());
                builder.append(".\n");
            } catch (ScriptException e) {
                // Ignore and don't print this line.
            }
            builder.append(tx.toString(chain));
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
     * of {@link org.bitcoinj.core.ECKey#getCreationTimeSeconds()}. This can return zero if at least one key does
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
        keychainLock.lock();
        try {
            long earliestTime = keychain.getEarliestKeyCreationTime();
            for (Script script : watchedScripts)
                earliestTime = Math.min(script.getCreationTimeSeconds(), earliestTime);
            if (earliestTime == Long.MAX_VALUE)
                return Utils.currentTimeSeconds();
            return earliestTime;
        } finally {
            keychainLock.unlock();
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

    //endregion

    /******************************************************************************************************************/

    //region Balance and balance futures

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
    public Coin getBalance() {
        return getBalance(BalanceType.AVAILABLE);
    }

    /**
     * Returns the balance of this wallet as calculated by the provided balanceType.
     */
    public Coin getBalance(BalanceType balanceType) {
        lock.lock();
        try {
            if (balanceType == BalanceType.AVAILABLE) {
                return getBalance(coinSelector);
            } else if (balanceType == BalanceType.ESTIMATED) {
                LinkedList<TransactionOutput> all = calculateAllSpendCandidates(false);
                Coin value = Coin.ZERO;
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
    public Coin getBalance(CoinSelector selector) {
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
    public Coin getWatchedBalance() {
        return getWatchedBalance(coinSelector);
    }

    /**
     * Returns the balance that would be considered spendable by the given coin selector, including
     * any unspent balance at watched addresses.
     */
    public Coin getWatchedBalance(CoinSelector selector) {
        lock.lock();
        try {
            checkNotNull(selector);
            List<TransactionOutput> candidates = getWatchedOutputs(true);
            CoinSelection selection = selector.select(NetworkParameters.MAX_MONEY, candidates);
            return selection.valueGathered;
        } finally {
            lock.unlock();
        }
    }

    private static class BalanceFutureRequest {
        public SettableFuture<Coin> future;
        public Coin value;
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
     * you can use {@link org.bitcoinj.utils.Threading#waitForUserCode()} to block until the future had a
     * chance to be updated.</p>
     */
    public ListenableFuture<Coin> getBalanceFuture(final Coin value, final BalanceType type) {
        lock.lock();
        try {
            final SettableFuture<Coin> future = SettableFuture.create();
            final Coin current = getBalance(type);
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
    private void checkBalanceFuturesLocked(@Nullable Coin avail) {
        checkState(lock.isHeldByCurrentThread());
        Coin estimated = null;
        final ListIterator<BalanceFutureRequest> it = balanceFutureRequests.listIterator();
        while (it.hasNext()) {
            final BalanceFutureRequest req = it.next();
            Coin val = null;
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
            final Coin v = checkNotNull(val);
            // Don't run any user-provided future listeners with our lock held.
            Threading.USER_THREAD.execute(new Runnable() {
                @Override public void run() {
                    req.future.set(v);
                }
            });
        }
    }

    //endregion

    /******************************************************************************************************************/

    //region Creating and sending transactions

    /** A SendResult is returned to you as part of sending coins to a recipient. */
    public static class SendResult {
        /** The Bitcoin transaction message that moves the money. */
        public Transaction tx;
        /** A future that will complete once the tx message has been successfully broadcast to the network. */
        public ListenableFuture<Transaction> broadcastComplete;
    }

    /**
     * Enumerates possible resolutions for missing signatures.
     */
    public enum MissingSigsMode {
        /** Input script will have OP_0 instead of missing signatures */
        USE_OP_ZERO,
        /**
         * Missing signatures will be replaced by dummy sigs. This is useful when you'd like to know the fee for
         * a transaction without knowing the user's password, as fee depends on size.
         */
        USE_DUMMY_SIG,
        /**
         * If signature is missing, {@link org.bitcoinj.signers.TransactionSigner.MissingSignatureException}
         * will be thrown for P2SH and {@link ECKey.MissingPrivateKeyException} for other tx types.
         */
        THROW
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
         * ({@link TransactionOutput#getMinNonDustValue(Coin)}) to avoid the whole transaction being rejected
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
         * (its value is ignored and set to {@link org.bitcoinj.core.Wallet#getBalance()} - the fees required
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
         * <p>You might also consider adding a {@link SendRequest#feePerKb} to set the fee per kb of transaction size
         * (rounded down to the nearest kb) as that is how transactions are sorted when added to a block by miners.</p>
         */
        public Coin fee = null;

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
        public Coin feePerKb = DEFAULT_FEE_PER_KB;

        /**
         * If you want to modify the default fee for your entire app without having to change each SendRequest you make,
         * you can do it here. This is primarily useful for unit tests.
         */
        public static Coin DEFAULT_FEE_PER_KB = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;

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
         * If true (the default), the inputs will be signed.
         */
        public boolean signInputs = true;

        /**
         * The AES key to use to decrypt the private keys before signing.
         * If null then no decryption will be performed and if decryption is required an exception will be thrown.
         * You can get this from a password by doing wallet.getKeyCrypter().deriveKey(password).
         */
        public KeyParameter aesKey = null;

        /**
         * If not null, the {@link org.bitcoinj.wallet.CoinSelector} to use instead of the wallets default. Coin selectors are
         * responsible for choosing which transaction outputs (coins) in a wallet to use given the desired send value
         * amount.
         */
        public CoinSelector coinSelector = null;

        /**
         * If true (the default), the outputs will be shuffled during completion to randomize the location of the change
         * output, if any. This is normally what you want for privacy reasons but in unit tests it can be annoying
         * so it can be disabled here.
         */
        public boolean shuffleOutputs = true;

        /**
         * Specifies what to do with missing signatures left after completing this request. Default strategy is to
         * throw an exception on missing signature ({@link MissingSigsMode#THROW}).
         * @see MissingSigsMode
         */
        public MissingSigsMode missingSigsMode = MissingSigsMode.THROW;

        /**
         * If not null, this exchange rate is recorded with the transaction during completion.
         */
        public ExchangeRate exchangeRate = null;

        /**
         * If not null, this memo is recorded with the transaction during completion. It can be used to record the memo
         * of the payment request that initiated the transaction.
         */
        public String memo = null;

        // Tracks if this has been passed to wallet.completeTx already: just a safety check.
        private boolean completed;

        private SendRequest() {}

        /**
         * <p>Creates a new SendRequest to the given address for the given value.</p>
         *
         * <p>Be very careful when value is smaller than {@link Transaction#MIN_NONDUST_OUTPUT} as the transaction will
         * likely be rejected by the network in this case.</p>
         */
        public static SendRequest to(Address destination, Coin value) {
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
         * {@link TransactionOutput#getMinNonDustValue(Coin)} afterwards or you risk having the transaction
         * rejected by the network. Note that using {@link SendRequest#to(Address, Coin)} will result
         * in a smaller output, and thus the ability to use a smaller output value without rejection.</p>
         */
        public static SendRequest to(NetworkParameters params, ECKey destination, Coin value) {
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
            req.tx.addOutput(Coin.ZERO, destination);
            req.emptyWallet = true;
            return req;
        }

        /** Copy data from payment request. */
        public SendRequest fromPaymentDetails(PaymentDetails paymentDetails) {
            if (paymentDetails.hasMemo())
                this.memo = paymentDetails.getMemo();
            return this;
        }

        @Override
        public String toString() {
            // print only the user-settable fields
            ToStringHelper helper = Objects.toStringHelper(this).omitNullValues();
            helper.add("emptyWallet", emptyWallet);
            helper.add("changeAddress", changeAddress);
            helper.add("fee", fee);
            helper.add("feePerKb", feePerKb);
            helper.add("ensureMinRequiredFee", ensureMinRequiredFee);
            helper.add("signInputs", signInputs);
            helper.add("aesKey", aesKey != null ? "set" : null); // careful to not leak the key
            helper.add("coinSelector", coinSelector);
            helper.add("shuffleOutputs", shuffleOutputs);
            return helper.toString();
        }
    }

    /**
     * <p>Statelessly creates a transaction that sends the given value to address. The change is sent to
     * {@link Wallet#getChangeAddress()}, so you must have added at least one key.</p>
     *
     * <p>If you just want to send money quickly, you probably want
     * {@link Wallet#sendCoins(TransactionBroadcaster, Address, Coin)} instead. That will create the sending
     * transaction, commit to the wallet and broadcast it to the network all in one go. This method is lower level
     * and lets you see the proposed transaction before anything is done with it.</p>
     *
     * <p>This is a helper method that is equivalent to using {@link Wallet.SendRequest#to(Address, Coin)}
     * followed by {@link Wallet#completeTx(Wallet.SendRequest)} and returning the requests transaction object.
     * Note that this means a fee may be automatically added if required, if you want more control over the process,
     * just do those two steps yourself.</p>
     *
     * <p>IMPORTANT: This method does NOT update the wallet. If you call createSend again you may get two transactions
     * that spend the same coins. You have to call {@link Wallet#commitTx(Transaction)} on the created transaction to
     * prevent this, but that should only occur once the transaction has been accepted by the network. This implies
     * you cannot have more than one outstanding sending tx at once.</p>
     *
     * <p>You MUST ensure that the value is not smaller than {@link Transaction#MIN_NONDUST_OUTPUT} or the transaction
     * will almost certainly be rejected by the network as dust.</p>
     *
     * @param address The Bitcoin address to send the money to.
     * @param value How much currency to send.
     * @return either the created Transaction or null if there are insufficient coins.
     * coins as spent until commitTx is called on the result.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws DustySendRequested if the resultant transaction would violate the dust rules (an output that's too small to be worthwhile)
     * @throws CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process (try breaking up the amounts of value)
     */
    public Transaction createSend(Address address, Coin value) throws InsufficientMoneyException {
        SendRequest req = SendRequest.to(address, value);
        if (params == UnitTestParams.get())
            req.shuffleOutputs = false;
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
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice
     * @throws DustySendRequested if the resultant transaction would violate the dust rules (an output that's too small to be worthwhile)
     * @throws CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process (try breaking up the amounts of value)
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
     * @param to Which address to send coins to.
     * @param value How much value to send.
     * @return An object containing the transaction that was created, and a future for the broadcast of it.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws DustySendRequested if the resultant transaction would violate the dust rules (an output that's too small to be worthwhile)
     * @throws CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process (try breaking up the amounts of value)
     */
    public SendResult sendCoins(TransactionBroadcaster broadcaster, Address to, Coin value) throws InsufficientMoneyException {
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
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice
     * @throws DustySendRequested if the resultant transaction would violate the dust rules (an output that's too small to be worthwhile)
     * @throws CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process (try breaking up the amounts of value)
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
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice
     * @throws DustySendRequested if the resultant transaction would violate the dust rules (an output that's too small to be worthwhile)
     * @throws CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process (try breaking up the amounts of value)
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
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice
     * @throws DustySendRequested if the resultant transaction would violate the dust rules (an output that's too small to be worthwhile)
     * @throws CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process (try breaking up the amounts of value)
     */
    public Transaction sendCoins(Peer peer, SendRequest request) throws InsufficientMoneyException {
        Transaction tx = sendCoinsOffline(request);
        peer.sendMessage(tx);
        return tx;
    }

    public static class CompletionException extends RuntimeException {}
    public static class DustySendRequested extends CompletionException {}
    public static class MultipleOpReturnRequested extends CompletionException {}

    /**
     * Thrown when we were trying to empty the wallet, and the total amount of money we were trying to empty after
     * being reduced for the fee was smaller than the min payment. Note that the missing field will be null in this
     * case.
     */
    public static class CouldNotAdjustDownwards extends CompletionException {}
    public static class ExceededMaxTransactionSize extends CompletionException {}

    /**
     * Given a spend request containing an incomplete transaction, makes it valid by adding outputs and signed inputs
     * according to the instructions in the request. The transaction in the request is modified by this method.
     *
     * @param req a SendRequest that contains the incomplete transaction and details for how to make it valid.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice
     * @throws DustySendRequested if the resultant transaction would violate the dust rules (an output that's too small to be worthwhile)
     * @throws CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process (try breaking up the amounts of value)
     */
    public void completeTx(SendRequest req) throws InsufficientMoneyException {
        lock.lock();
        try {
            checkArgument(!req.completed, "Given SendRequest has already been completed.");
            // Calculate the amount of value we need to import.
            Coin value = Coin.ZERO;
            for (TransactionOutput output : req.tx.getOutputs()) {
                value = value.add(output.getValue());
            }

            log.info("Completing send tx with {} outputs totalling {} (not including fees)",
                    req.tx.getOutputs().size(), value.toFriendlyString());

            // If any inputs have already been added, we don't need to get their value from wallet
            Coin totalInput = Coin.ZERO;
            for (TransactionInput input : req.tx.getInputs())
                if (input.getConnectedOutput() != null)
                    totalInput = totalInput.add(input.getConnectedOutput().getValue());
                else
                    log.warn("SendRequest transaction already has inputs but we don't know how much they are worth - they will be added to fee.");
            value = value.subtract(totalInput);

            List<TransactionInput> originalInputs = new ArrayList<TransactionInput>(req.tx.getInputs());
            int opReturnCount = 0;

            // We need to know if we need to add an additional fee because one of our values are smaller than 0.01 BTC
            boolean needAtLeastReferenceFee = false;
            if (req.ensureMinRequiredFee && !req.emptyWallet) { // Min fee checking is handled later for emptyWallet.
                for (TransactionOutput output : req.tx.getOutputs()) {
                    if (output.getValue().compareTo(Coin.CENT) < 0) {
                        needAtLeastReferenceFee = true;
                        if (output.getValue().compareTo(output.getMinNonDustValue()) < 0) { // Is transaction a "dust".
                            if (output.getScriptPubKey().isOpReturn()) { // Transactions that are OP_RETURN can't be dust regardless of their value.
                                ++opReturnCount;
                                continue;
                            } else {
                                throw new DustySendRequested();
                            }
                        }
                        break;
                    }
                }
            }

            if (opReturnCount > 1) { // Only 1 OP_RETURN per transaction allowed.
                throw new MultipleOpReturnRequested();
            }

            // Calculate a list of ALL potential candidates for spending and then ask a coin selector to provide us
            // with the actual outputs that'll be used to gather the required amount of value. In this way, users
            // can customize coin selection policies.
            //
            // Note that this code is poorly optimized: the spend candidates only alter when transactions in the wallet
            // change - it could be pre-calculated and held in RAM, and this is probably an optimization worth doing.
            LinkedList<TransactionOutput> candidates = calculateAllSpendCandidates(true);
            CoinSelection bestCoinSelection;
            TransactionOutput bestChangeOutput = null;
            if (!req.emptyWallet) {
                // This can throw InsufficientMoneyException.
                FeeCalculation feeCalculation;
                feeCalculation = calculateFee(req, value, originalInputs, needAtLeastReferenceFee, candidates);
                bestCoinSelection = feeCalculation.bestCoinSelection;
                bestChangeOutput = feeCalculation.bestChangeOutput;
            } else {
                // We're being asked to empty the wallet. What this means is ensuring "tx" has only a single output
                // of the total value we can currently spend as determined by the selector, and then subtracting the fee.
                checkState(req.tx.getOutputs().size() == 1, "Empty wallet TX must have a single output only.");
                CoinSelector selector = req.coinSelector == null ? coinSelector : req.coinSelector;
                bestCoinSelection = selector.select(NetworkParameters.MAX_MONEY, candidates);
                candidates = null;  // Selector took ownership and might have changed candidates. Don't access again.
                req.tx.getOutput(0).setValue(bestCoinSelection.valueGathered);
                log.info("  emptying {}", bestCoinSelection.valueGathered.toFriendlyString());
            }

            for (TransactionOutput output : bestCoinSelection.gathered)
                req.tx.addInput(output);

            if (req.ensureMinRequiredFee && req.emptyWallet) {
                final Coin baseFee = req.fee == null ? Coin.ZERO : req.fee;
                final Coin feePerKb = req.feePerKb == null ? Coin.ZERO : req.feePerKb;
                Transaction tx = req.tx;
                if (!adjustOutputDownwardsForFee(tx, bestCoinSelection, baseFee, feePerKb))
                    throw new CouldNotAdjustDownwards();
            }

            if (bestChangeOutput != null) {
                req.tx.addOutput(bestChangeOutput);
                log.info("  with {} change", bestChangeOutput.getValue().toFriendlyString());
            }

            // Now shuffle the outputs to obfuscate which is the change.
            if (req.shuffleOutputs)
                req.tx.shuffleOutputs();

            // Now sign the inputs, thus proving that we are entitled to redeem the connected outputs.
            if (req.signInputs) {
                signTransaction(req);
            }

            // Check size.
            int size = req.tx.bitcoinSerialize().length;
            if (size > Transaction.MAX_STANDARD_TX_SIZE)
                throw new ExceededMaxTransactionSize();

            final Coin calculatedFee = req.tx.getFee();
            if (calculatedFee != null) {
                log.info("  with a fee of {}", calculatedFee.toFriendlyString());
            }

            // Label the transaction as being self created. We can use this later to spend its change output even before
            // the transaction is confirmed. We deliberately won't bother notifying listeners here as there's not much
            // point - the user isn't interested in a confidence transition they made themselves.
            req.tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
            // Label the transaction as being a user requested payment. This can be used to render GUI wallet
            // transaction lists more appropriately, especially when the wallet starts to generate transactions itself
            // for internal purposes.
            req.tx.setPurpose(Transaction.Purpose.USER_PAYMENT);
            // Record the exchange rate that was valid when the transaction was completed.
            req.tx.setExchangeRate(req.exchangeRate);
            req.tx.setMemo(req.memo);
            req.completed = true;
            req.fee = calculatedFee;
            log.info("  completed: {}", req.tx);
        } finally {
            lock.unlock();
        }
    }

    /**
     * <p>Given a send request containing transaction, attempts to sign it's inputs. This method expects transaction
     * to have all necessary inputs connected or they will be ignored.</p>
     * <p>Actual signing is done by pluggable {@link #signers} and it's not guaranteed that
     * transaction will be complete in the end.</p>
     */
    public void signTransaction(SendRequest req) {
        lock.lock();
        try {
            Transaction tx = req.tx;
            List<TransactionInput> inputs = tx.getInputs();
            List<TransactionOutput> outputs = tx.getOutputs();
            checkState(inputs.size() > 0);
            checkState(outputs.size() > 0);

            KeyBag maybeDecryptingKeyBag = new DecryptingKeyBag(this, req.aesKey);

            int numInputs = tx.getInputs().size();
            for (int i = 0; i < numInputs; i++) {
                TransactionInput txIn = tx.getInput(i);
                if (txIn.getConnectedOutput() == null) {
                    // Missing connected output, assuming already signed.
                    continue;
                }

                try {
                    // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                    // we sign missing pieces (to check this would require either assuming any signatures are signing
                    // standard output types or a way to get processed signatures out of script execution)
                    txIn.getScriptSig().correctlySpends(tx, i, txIn.getConnectedOutput().getScriptPubKey());
                    log.warn("Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                    continue;
                } catch (ScriptException e) {
                    // Expected.
                }

                Script scriptPubKey = txIn.getConnectedOutput().getScriptPubKey();
                RedeemData redeemData = txIn.getConnectedRedeemData(maybeDecryptingKeyBag);
                checkNotNull(redeemData, "Transaction exists in wallet that we cannot redeem: %s", txIn.getOutpoint().getHash());
                txIn.setScriptSig(scriptPubKey.createEmptyInputScript(redeemData.keys.get(0), redeemData.redeemScript));
            }

            TransactionSigner.ProposedTransaction proposal = new TransactionSigner.ProposedTransaction(tx);
            for (TransactionSigner signer : signers) {
                if (!signer.signInputs(proposal, maybeDecryptingKeyBag))
                    log.info("{} returned false for the tx", signer.getClass().getName());
            }

            // resolve missing sigs if any
            new MissingSigResolutionSigner(req.missingSigsMode).signInputs(proposal, maybeDecryptingKeyBag);
        } finally {
            lock.unlock();
        }
    }

    /** Reduce the value of the first output of a transaction to pay the given feePerKb as appropriate for its size. */
    private boolean adjustOutputDownwardsForFee(Transaction tx, CoinSelection coinSelection, Coin baseFee, Coin feePerKb) {
        TransactionOutput output = tx.getOutput(0);
        // Check if we need additional fee due to the transaction's size
        int size = tx.bitcoinSerialize().length;
        size += estimateBytesForSigning(coinSelection);
        Coin fee = baseFee.add(feePerKb.multiply((size / 1000) + 1));
        output.setValue(output.getValue().subtract(fee));
        // Check if we need additional fee due to the output's value
        if (output.getValue().compareTo(Coin.CENT) < 0 && fee.compareTo(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE) < 0)
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
    public void setCoinSelector(CoinSelector coinSelector) {
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

    //endregion

    /******************************************************************************************************************/

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

    //region Reorganisations

    /**
     * <p>Don't call this directly. It's not intended for API users.</p>
     *
     * <p>Called by the {@link BlockChain} when the best chain (representing total work done) has changed. This can
     * cause the number of confirmations of a transaction to go higher, lower, drop to zero and can even result in
     * a transaction going dead (will never confirm) due to a double spend.</p>
     *
     * <p>The oldBlocks/newBlocks lists are ordered height-wise from top first to bottom last.</p>
     */
    @Override
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
                        log.warn("Coinbase killed by re-org: {}", tx.getHashAsString());
                        killTx(null, ImmutableList.of(tx));
                    } else {
                        for (TransactionOutput output : tx.getOutputs()) {
                            TransactionInput input = output.getSpentBy();
                            if (input != null) input.disconnect();
                        }
                        tx.disconnectInputs();
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

            // The old blocks have contributed to the depth for all the transactions in the
            // wallet that are in blocks up to and including the chain split block.
            // The total depth is calculated here and then subtracted from the appropriate transactions.
            int depthToSubtract = oldBlocks.size();
            log.info("depthToSubtract = " + depthToSubtract);
            // Remove depthToSubtract from all transactions in the wallet except for pending.
            subtractDepth(depthToSubtract, spent.values());
            subtractDepth(depthToSubtract, unspent.values());
            subtractDepth(depthToSubtract, dead.values());

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
            final Coin balance = getBalance();
            log.info("post-reorg balance is {}", balance.toFriendlyString());
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
     * Subtract the supplied depth from the given transactions.
     */
    private void subtractDepth(int depthToSubtract, Collection<Transaction> transactions) {
        for (Transaction tx : transactions) {
            if (tx.getConfidence().getConfidenceType() == ConfidenceType.BUILDING) {
                tx.getConfidence().setDepthInBlocks(tx.getConfidence().getDepthInBlocks() - depthToSubtract);
                confidenceChanged.put(tx, TransactionConfidence.Listener.ChangeReason.DEPTH);
            }
        }
    }

    //endregion

    /******************************************************************************************************************/

    //region Bloom filtering

    /**
     * Returns the number of distinct data items (note: NOT keys) that will be inserted into a bloom filter, when it
     * is constructed.
     */
    @Override
    public int getBloomFilterElementCount() {
        int size = 0;
        for (Transaction tx : getTransactions(false)) {
            for (TransactionOutput out : tx.getOutputs()) {
                try {
                    if (isTxOutputBloomFilterable(out))
                        size++;
                } catch (ScriptException e) {
                    // If it is ours, we parsed the script correctly, so this shouldn't happen.
                    throw new RuntimeException(e);
                }
            }
        }
        keychainLock.lock();
        try {
            size += keychain.getBloomFilterElementCount();
            // Some scripts may have more than one bloom element.  That should normally be okay, because under-counting
            // just increases false-positive rate.
            size += watchedScripts.size();
            return size;
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * If we are watching any scripts, the bloom filter must update on peers whenever an output is
     * identified.  This is because we don't necessarily have the associated pubkey, so we can't
     * watch for it on spending transactions.
     */
    @Override
    public boolean isRequiringUpdateAllBloomFilter() {
        // This is typically called by the PeerGroup, in which case it will have already explicitly taken the lock
        // before calling, but because this is public API we must still lock again regardless.
        keychainLock.lock();
        try {
            return !watchedScripts.isEmpty();
        } finally {
            keychainLock.unlock();
        }
    }

    /**
     * Gets a bloom filter that contains all of the public keys from this wallet, and which will provide the given
     * false-positive rate. See the docs for {@link BloomFilter} for a brief explanation of anonymity when using filters.
     */
    public BloomFilter getBloomFilter(double falsePositiveRate) {
        return getBloomFilter(getBloomFilterElementCount(), falsePositiveRate, (long)(Math.random()*Long.MAX_VALUE));
    }

    /**
     * <p>Gets a bloom filter that contains all of the public keys from this wallet, and which will provide the given
     * false-positive rate if it has size elements. Keep in mind that you will get 2 elements in the bloom filter for
     * each key in the wallet, for the public key and the hash of the public key (address form).</p>
     * 
     * <p>This is used to generate a BloomFilter which can be {@link BloomFilter#merge(BloomFilter)}d with another.
     * It could also be used if you have a specific target for the filter's size.</p>
     * 
     * <p>See the docs for {@link BloomFilter(int, double)} for a brief explanation of anonymity when using bloom
     * filters.</p>
     */
    @Override
    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
        // This is typically called by the PeerGroup, in which case it will have already explicitly taken the lock
        // before calling, but because this is public API we must still lock again regardless.
        lock.lock();
        keychainLock.lock();
        try {
            BloomFilter filter = keychain.getBloomFilter(size, falsePositiveRate, nTweak);

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
        } finally {
            keychainLock.unlock();
            lock.unlock();
        }
    }

    private boolean isTxOutputBloomFilterable(TransactionOutput out) {
        boolean isScriptTypeSupported = out.getScriptPubKey().isSentToRawPubKey() || out.getScriptPubKey().isPayToScriptHash();
        return (out.isMine(this) && isScriptTypeSupported) ||
                out.isWatched(this);
    }

    /**
     * Used by {@link Peer} to decide whether or not to discard this block and any blocks building upon it, in case
     * the Bloom filter used to request them may be exhausted, that is, not have sufficient keys in the deterministic
     * sequence within it to reliably find relevant transactions.
     */
    public boolean checkForFilterExhaustion(FilteredBlock block) {
        keychainLock.lock();
        try {
            int epoch = keychain.getCombinedKeyLookaheadEpochs();
            for (Transaction tx : block.getAssociatedTransactions().values()) {
                markKeysAsUsed(tx);
            }
            int newEpoch = keychain.getCombinedKeyLookaheadEpochs();
            checkState(newEpoch >= epoch);
            // If the key lookahead epoch has advanced, there was a call to addKeys and the PeerGroup already has a
            // pending request to recalculate the filter queued up on another thread. The calling Peer should abandon
            // block at this point and await a new filter before restarting the download.
            return newEpoch > epoch;
        } finally {
            keychainLock.unlock();
        }
    }

    //endregion

    /******************************************************************************************************************/

    //region Extensions to the wallet format.

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
     * Atomically adds extension or returns an existing extension if there is one with the same id already present.
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

    @Override
    public void setTag(String tag, ByteString value) {
        super.setTag(tag, value);
        saveNow();
    }

    //endregion

    /******************************************************************************************************************/

    private static class FeeCalculation {
        public CoinSelection bestCoinSelection;
        public TransactionOutput bestChangeOutput;
    }

    //region Fee calculation code

    public FeeCalculation calculateFee(SendRequest req, Coin value, List<TransactionInput> originalInputs,
                                       boolean needAtLeastReferenceFee, LinkedList<TransactionOutput> candidates) throws InsufficientMoneyException {
        checkState(lock.isHeldByCurrentThread());
        FeeCalculation result = new FeeCalculation();
        // There are 3 possibilities for what adding change might do:
        // 1) No effect
        // 2) Causes increase in fee (change < 0.01 COINS)
        // 3) Causes the transaction to have a dust output or change < fee increase (ie change will be thrown away)
        // If we get either of the last 2, we keep note of what the inputs looked like at the time and try to
        // add inputs as we go up the list (keeping track of minimum inputs for each category).  At the end, we pick
        // the best input set as the one which generates the lowest total fee.
        Coin additionalValueForNextCategory = null;
        CoinSelection selection3 = null;
        CoinSelection selection2 = null;
        TransactionOutput selection2Change = null;
        CoinSelection selection1 = null;
        TransactionOutput selection1Change = null;
        // We keep track of the last size of the transaction we calculated but only if the act of adding inputs and
        // change resulted in the size crossing a 1000 byte boundary. Otherwise it stays at zero.
        int lastCalculatedSize = 0;
        Coin valueNeeded, valueMissing = null;
        while (true) {
            resetTxInputs(req, originalInputs);

            Coin fees = req.fee == null ? Coin.ZERO : req.fee;
            if (lastCalculatedSize > 0) {
                // If the size is exactly 1000 bytes then we'll over-pay, but this should be rare.
                fees = fees.add(req.feePerKb.multiply((lastCalculatedSize / 1000) + 1));
            } else {
                fees = fees.add(req.feePerKb);  // First time around the loop.
            }
            if (needAtLeastReferenceFee && fees.compareTo(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE) < 0)
                fees = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;

            valueNeeded = value.add(fees);
            if (additionalValueForNextCategory != null)
                valueNeeded = valueNeeded.add(additionalValueForNextCategory);
            Coin additionalValueSelected = additionalValueForNextCategory;

            // Of the coins we could spend, pick some that we actually will spend.
            CoinSelector selector = req.coinSelector == null ? coinSelector : req.coinSelector;
            // selector is allowed to modify candidates list.
            CoinSelection selection = selector.select(valueNeeded, new LinkedList<TransactionOutput>(candidates));
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

            Coin change = selection.valueGathered.subtract(valueNeeded);
            if (additionalValueSelected != null)
                change = change.add(additionalValueSelected);

            // If change is < 0.01 BTC, we will need to have at least minfee to be accepted by the network
            if (req.ensureMinRequiredFee && !change.equals(Coin.ZERO) &&
                    change.compareTo(Coin.CENT) < 0 && fees.compareTo(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE) < 0) {
                // This solution may fit into category 2, but it may also be category 3, we'll check that later
                eitherCategory2Or3 = true;
                additionalValueForNextCategory = Coin.CENT;
                // If the change is smaller than the fee we want to add, this will be negative
                change = change.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.subtract(fees));
            }

            int size = 0;
            TransactionOutput changeOutput = null;
            if (change.signum() > 0) {
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
                                                     Transaction.MIN_NONDUST_OUTPUT.add(Coin.SATOSHI));
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
                    additionalValueForNextCategory = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.add(Coin.SATOSHI);
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
            if (size/1000 > lastCalculatedSize/1000 && req.feePerKb.signum() > 0) {
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
                checkState(additionalValueForNextCategory.equals(Coin.CENT));
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
            log.warn("Insufficient value in wallet for send: needed {} more", valueMissing.toFriendlyString());
            throw new InsufficientMoneyException(valueMissing);
        }

        Coin lowestFee = null;
        result.bestCoinSelection = null;
        result.bestChangeOutput = null;
        if (selection1 != null) {
            if (selection1Change != null)
                lowestFee = selection1.valueGathered.subtract(selection1Change.getValue());
            else
                lowestFee = selection1.valueGathered;
            result.bestCoinSelection = selection1;
            result.bestChangeOutput = selection1Change;
        }

        if (selection2 != null) {
            Coin fee = selection2.valueGathered.subtract(checkNotNull(selection2Change).getValue());
            if (lowestFee == null || fee.compareTo(lowestFee) < 0) {
                lowestFee = fee;
                result.bestCoinSelection = selection2;
                result.bestChangeOutput = selection2Change;
            }
        }

        if (selection3 != null) {
            if (lowestFee == null || selection3.valueGathered.compareTo(lowestFee) < 0) {
                result.bestCoinSelection = selection3;
                result.bestChangeOutput = null;
            }
        }
        return result;
    }

    private void resetTxInputs(SendRequest req, List<TransactionInput> originalInputs) {
        req.tx.clearInputs();
        for (TransactionInput input : originalInputs)
            req.tx.addInput(input);
    }

    private int estimateBytesForSigning(CoinSelection selection) {
        int size = 0;
        for (TransactionOutput output : selection.gathered) {
            try {
                Script script = output.getScriptPubKey();
                ECKey key = null;
                Script redeemScript = null;
                if (script.isSentToAddress()) {
                    key = findKeyFromPubHash(script.getPubKeyHash());
                    checkNotNull(key, "Coin selection includes unspendable outputs");
                } else if (script.isPayToScriptHash()) {
                    redeemScript = findRedeemDataFromScriptHash(script.getPubKeyHash()).redeemScript;
                    checkNotNull(redeemScript, "Coin selection includes unspendable outputs");
                }
                size += script.getNumberOfBytesRequiredToSpend(key, redeemScript);
            } catch (ScriptException e) {
                // If this happens it means an output script in a wallet tx could not be understood. That should never
                // happen, if it does it means the wallet has got into an inconsistent state.
                throw new IllegalStateException(e);
            }
        }
        return size;
    }

    //endregion

    /******************************************************************************************************************/

    //region Wallet maintenance transactions

    // Wallet maintenance transactions. These transactions may not be directly connected to a payment the user is
    // making. They may be instead key rotation transactions for when old keys are suspected to be compromised,
    // de/re-fragmentation transactions for when our output sizes are inappropriate or suboptimal, privacy transactions
    // and so on. Because these transactions may require user intervention in some way (e.g. entering their password)
    // the wallet application is expected to poll the Wallet class to get SendRequests. Ideally security systems like
    // hardware wallets or risk analysis providers are programmed to auto-approve transactions that send from our own
    // keys back to our own keys.

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
    public void setTransactionBroadcaster(@Nullable org.bitcoinj.core.TransactionBroadcaster broadcaster) {
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
     * <p>When a key rotation time is set, any money controlled by keys created before the given timestamp T will be
     * automatically respent to any key that was created after T. This can be used to recover from a situation where
     * a set of keys is believed to be compromised. You can stop key rotation by calling this method again with zero
     * as the argument. Once set up, calling {@link #doMaintenance(org.spongycastle.crypto.params.KeyParameter, boolean)}
     * will create and possibly send rotation transactions: but it won't be done automatically (because you might have
     * to ask for the users password).</p>
     *
     * <p>The given time cannot be in the future.</p>
     */
    public void setKeyRotationTime(long unixTimeSeconds) {
        checkArgument(unixTimeSeconds <= Utils.currentTimeSeconds());
        vKeyRotationTimestamp = unixTimeSeconds;
        saveNow();
    }

    /** Returns whether the keys creation time is before the key rotation time, if one was set. */
    public boolean isKeyRotating(ECKey key) {
        long time = vKeyRotationTimestamp;
        return time != 0 && key.getCreationTimeSeconds() < time;
    }

    /** @deprecated Renamed to doMaintenance */
    @Deprecated
    public ListenableFuture<List<Transaction>> maybeDoMaintenance(@Nullable KeyParameter aesKey, boolean andSend) throws DeterministicUpgradeRequiresPassword {
        return doMaintenance(aesKey, andSend);
    }

    /**
     * A wallet app should call this from time to time in order to let the wallet craft and send transactions needed
     * to re-organise coins internally. A good time to call this would be after receiving coins for an unencrypted
     * wallet, or after sending money for an encrypted wallet. If you have an encrypted wallet and just want to know
     * if some maintenance needs doing, call this method with andSend set to false and look at the returned list of
     * transactions. Maintenance might also include internal changes that involve some processing or work but
     * which don't require making transactions - these will happen automatically unless the password is required
     * in which case an exception will be thrown.
     *
     * @param aesKey the users password, if any.
     * @param signAndSend if true, send the transactions via the tx broadcaster and return them, if false just return them.
     * @return A list of transactions that the wallet just made/will make for internal maintenance. Might be empty.
     * @throws org.bitcoinj.wallet.DeterministicUpgradeRequiresPassword if key rotation requires the users password.
     */
    public ListenableFuture<List<Transaction>> doMaintenance(@Nullable KeyParameter aesKey, boolean signAndSend) throws DeterministicUpgradeRequiresPassword {
        List<Transaction> txns;
        lock.lock();
        keychainLock.lock();
        try {
            txns = maybeRotateKeys(aesKey, signAndSend);
            if (!signAndSend)
                return Futures.immediateFuture(txns);
        } finally {
            keychainLock.unlock();
            lock.unlock();
        }
        checkState(!lock.isHeldByCurrentThread());
        ArrayList<ListenableFuture<Transaction>> futures = new ArrayList<ListenableFuture<Transaction>>(txns.size());
        TransactionBroadcaster broadcaster = vTransactionBroadcaster;
        for (Transaction tx : txns) {
            try {
                final ListenableFuture<Transaction> future = broadcaster.broadcastTransaction(tx);
                futures.add(future);
                Futures.addCallback(future, new FutureCallback<Transaction>() {
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
                log.error("Failed to broadcast rekey tx", e);
            }
        }
        return Futures.allAsList(futures);
    }

    // Checks to see if any coins are controlled by rotating keys and if so, spends them.
    @GuardedBy("keychainLock")
    private List<Transaction> maybeRotateKeys(@Nullable KeyParameter aesKey, boolean sign) throws DeterministicUpgradeRequiresPassword {
        checkState(lock.isHeldByCurrentThread());
        checkState(keychainLock.isHeldByCurrentThread());
        List<Transaction> results = Lists.newLinkedList();
        // TODO: Handle chain replays here.
        final long keyRotationTimestamp = vKeyRotationTimestamp;
        if (keyRotationTimestamp == 0) return results;  // Nothing to do.

        // We might have to create a new HD hierarchy if the previous ones are now rotating.
        boolean allChainsRotating = true;
        for (DeterministicKeyChain chain : keychain.getDeterministicKeyChains()) {
            if (chain.getEarliestKeyCreationTime() >= keyRotationTimestamp) {
                allChainsRotating = false;
                break;
            }
        }
        if (allChainsRotating) {
            try {
                if (keychain.getImportedKeys().isEmpty()) {
                    log.info("All HD chains are currently rotating and we have no random keys, creating fresh HD chain ...");
                    keychain.createAndActivateNewHDChain();
                } else {
                    log.info("All HD chains are currently rotating, attempting to create a new one from the next oldest non-rotating key material ...");
                    keychain.upgradeToDeterministic(keyRotationTimestamp, aesKey);
                    log.info(" ... upgraded to HD again, based on next best oldest key.");
                }
            } catch (AllRandomKeysRotating rotating) {
                log.info(" ... no non-rotating random keys available, generating entirely new HD tree: backup required after this.");
                keychain.createAndActivateNewHDChain();
            }
            saveNow();
        }

        // Because transactions are size limited, we might not be able to re-key the entire wallet in one go. So
        // loop around here until we no longer produce transactions with the max number of inputs. That means we're
        // fully done, at least for now (we may still get more transactions later and this method will be reinvoked).
        Transaction tx;
        do {
            tx = rekeyOneBatch(keyRotationTimestamp, aesKey, results, sign);
            if (tx != null) results.add(tx);
        } while (tx != null && tx.getInputs().size() == KeyTimeCoinSelector.MAX_SIMULTANEOUS_INPUTS);
        return results;
    }

    @Nullable
    private Transaction rekeyOneBatch(long timeSecs, @Nullable KeyParameter aesKey, List<Transaction> others, boolean sign) {
        lock.lock();
        try {
            // Build the transaction using some custom logic for our special needs. Last parameter to
            // KeyTimeCoinSelector is whether to ignore pending transactions or not.
            //
            // We ignore pending outputs because trying to rotate these is basically racing an attacker, and
            // we're quite likely to lose and create stuck double spends. Also, some users who have 0.9 wallets
            // have already got stuck double spends in their wallet due to the Bloom-filtering block reordering
            // bug that was fixed in 0.10, thus, making a re-key transaction depend on those would cause it to
            // never confirm at all.
            CoinSelector keyTimeSelector = new KeyTimeCoinSelector(this, timeSecs, true);
            FilteringCoinSelector selector = new FilteringCoinSelector(keyTimeSelector);
            for (Transaction other : others)
                selector.excludeOutputsSpentBy(other);
            // TODO: Make this use the standard SendRequest.
            CoinSelection toMove = selector.select(Coin.ZERO, calculateAllSpendCandidates(true));
            if (toMove.valueGathered.equals(Coin.ZERO)) return null;  // Nothing to do.
            maybeUpgradeToHD(aesKey);
            Transaction rekeyTx = new Transaction(params);
            for (TransactionOutput output : toMove.gathered) {
                rekeyTx.addInput(output);
            }
            // When not signing, don't waste addresses.
            rekeyTx.addOutput(toMove.valueGathered, sign ? freshReceiveAddress() : currentReceiveAddress());
            if (!adjustOutputDownwardsForFee(rekeyTx, toMove, Coin.ZERO, Transaction.REFERENCE_DEFAULT_MIN_TX_FEE)) {
                log.error("Failed to adjust rekey tx for fees.");
                return null;
            }
            rekeyTx.getConfidence().setSource(TransactionConfidence.Source.SELF);
            rekeyTx.setPurpose(Transaction.Purpose.KEY_ROTATION);
            SendRequest req = SendRequest.forTx(rekeyTx);
            req.aesKey = aesKey;
            if (sign)
                signTransaction(req);
            // KeyTimeCoinSelector should never select enough inputs to push us oversize.
            checkState(rekeyTx.bitcoinSerialize().length < Transaction.MAX_STANDARD_TX_SIZE);
            return rekeyTx;
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } finally {
            lock.unlock();
        }
    }
    //endregion

    /**
     * Returns the wallet lock under which most operations happen. This is here to satisfy the
     * {@link org.bitcoinj.core.PeerFilterProvider} interface and generally should not be used directly by apps.
     * In particular, do <b>not</b> hold this lock if you're display a send confirm screen to the user or for any other
     * long length of time, as it may cause processing holdups elsewhere. Instead, for the "confirm payment screen"
     * use case you should complete a candidate transaction, present it to the user (e.g. for fee purposes) and then
     * when they confirm - which may be quite some time later - recalculate the transaction and check if it's the same.
     * If not, redisplay the confirm window and try again.
     */
    @Override
    public Lock getLock() {
        return new Lock() {
            @Override
            public void lock() {
                lock.lock();
                keychainLock.lock();
            }

            @Override
            public void lockInterruptibly() throws InterruptedException {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean tryLock() {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean tryLock(long l, TimeUnit unit) throws InterruptedException {
                throw new UnsupportedOperationException();
            }

            @Override
            public void unlock() {
                keychainLock.unlock();
                lock.unlock();
            }

            @Override
            public Condition newCondition() {
                throw new UnsupportedOperationException();
            }
        };
    }
}
