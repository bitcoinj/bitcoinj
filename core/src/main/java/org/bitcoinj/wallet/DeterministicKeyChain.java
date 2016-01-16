/*
 * Copyright 2014 The bitcoinj developers.
 * Copyright 2015 Andreas Schildbach
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.listeners.KeyChainEventListener;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;
import com.google.common.collect.PeekingIterator;
import com.google.protobuf.ByteString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.*;
import static com.google.common.collect.Lists.newArrayList;
import static com.google.common.collect.Lists.newLinkedList;

/**
 * <p>A deterministic key chain is a {@link KeyChain} that uses the
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP 32 standard</a>, as implemented by
 * {@link org.bitcoinj.crypto.DeterministicHierarchy}, to derive all the keys in the keychain from a master seed.
 * This type of wallet is extremely convenient and flexible. Although backing up full wallet files is always a good
 * idea, to recover money only the root seed needs to be preserved and that is a number small enough that it can be
 * written down on paper or, when represented using a BIP 39 {@link org.bitcoinj.crypto.MnemonicCode},
 * dictated over the phone (possibly even memorized).</p>
 *
 * <p>Deterministic key chains have other advantages: parts of the key tree can be selectively revealed to allow
 * for auditing, and new public keys can be generated without access to the private keys, yielding a highly secure
 * configuration for web servers which can accept payments into a wallet but not spend from them. This does not work
 * quite how you would expect due to a quirk of elliptic curve mathematics and the techniques used to deal with it.
 * A watching wallet is not instantiated using the public part of the master key as you may imagine. Instead, you
 * need to take the account key (first child of the master key) and provide the public part of that to the watching
 * wallet instead. You can do this by calling {@link #getWatchingKey()} and then serializing it with
 * {@link org.bitcoinj.crypto.DeterministicKey#serializePubB58(org.bitcoinj.core.NetworkParameters)}. The resulting "xpub..." string encodes
 * sufficient information about the account key to create a watching chain via
 * {@link org.bitcoinj.crypto.DeterministicKey#deserializeB58(org.bitcoinj.crypto.DeterministicKey, String, org.bitcoinj.core.NetworkParameters)}
 * (with null as the first parameter) and then
 * {@link DeterministicKeyChain#DeterministicKeyChain(org.bitcoinj.crypto.DeterministicKey)}.</p>
 *
 * <p>This class builds on {@link org.bitcoinj.crypto.DeterministicHierarchy} and
 * {@link org.bitcoinj.crypto.DeterministicKey} by adding support for serialization to and from protobufs,
 * and encryption of parts of the key tree. Internally it arranges itself as per the BIP 32 spec, with the seed being
 * used to derive a master key, which is then used to derive an account key, the account key is used to derive two
 * child keys called the <i>internal</i> and <i>external</i> parent keys (for change and handing out addresses respectively)
 * and finally the actual leaf keys that users use hanging off the end. The leaf keys are special in that they don't
 * internally store the private part at all, instead choosing to rederive the private key from the parent when
 * needed for signing. This simplifies the design for encrypted key chains.</p>
 *
 * <p>The key chain manages a <i>lookahead zone</i>. This zone is required because when scanning the chain, you don't
 * know exactly which keys might receive payments. The user may have handed out several addresses and received payments
 * on them, but for latency reasons the block chain is requested from remote peers in bulk, meaning you must
 * "look ahead" when calculating keys to put in the Bloom filter. The default lookahead zone is 100 keys, meaning if
 * the user hands out more than 100 addresses and receives payment on them before the chain is next scanned, some
 * transactions might be missed. 100 is a reasonable choice for consumer wallets running on CPU constrained devices.
 * For industrial wallets that are receiving keys all the time, a higher value is more appropriate. Ideally DKC and the
 * wallet would know how to adjust this value automatically, but that's not implemented at the moment.</p>
 *
 * <p>In fact the real size of the lookahead zone is larger than requested, by default, it's one third larger. This
 * is because the act of deriving new keys means recalculating the Bloom filters and this is an expensive operation.
 * Thus, to ensure we don't have to recalculate on every single new key/address requested or seen we add more buffer
 * space and only extend the lookahead zone when that buffer is exhausted. For example with a lookahead zone of 100
 * keys, you can request 33 keys before more keys will be calculated and the Bloom filter rebuilt and rebroadcast.
 * But even when you are requesting the 33rd key, you will still be looking 100 keys ahead.
 * </p>
 */
@SuppressWarnings("PublicStaticCollectionField")
public class DeterministicKeyChain implements EncryptableKeyChain {
    private static final Logger log = LoggerFactory.getLogger(DeterministicKeyChain.class);
    public static final String DEFAULT_PASSPHRASE_FOR_MNEMONIC = "";

    protected final ReentrantLock lock = Threading.lock("DeterministicKeyChain");

    private DeterministicHierarchy hierarchy;
    @Nullable private DeterministicKey rootKey;
    @Nullable private DeterministicSeed seed;

    // Paths through the key tree. External keys are ones that are communicated to other parties. Internal keys are
    // keys created for change addresses, coinbases, mixing, etc - anything that isn't communicated. The distinction
    // is somewhat arbitrary but can be useful for audits. The first number is the "account number" but we don't use
    // that feature yet. In future we might hand out different accounts for cases where we wish to hand payers
    // a payment request that can generate lots of addresses independently.
    // The account path may be overridden by subclasses.
    public static final ImmutableList<ChildNumber> ACCOUNT_ZERO_PATH = ImmutableList.of(ChildNumber.ZERO_HARDENED);
    public static final ImmutableList<ChildNumber> EXTERNAL_SUBPATH = ImmutableList.of(ChildNumber.ZERO);
    public static final ImmutableList<ChildNumber> INTERNAL_SUBPATH = ImmutableList.of(ChildNumber.ONE);
    public static final ImmutableList<ChildNumber> EXTERNAL_PATH = HDUtils.concat(ACCOUNT_ZERO_PATH, EXTERNAL_SUBPATH);
    public static final ImmutableList<ChildNumber> INTERNAL_PATH = HDUtils.concat(ACCOUNT_ZERO_PATH, INTERNAL_SUBPATH);
    // m / 44' / 0' / 0'
    public static final ImmutableList<ChildNumber> BIP44_ACCOUNT_ZERO_PATH =
            ImmutableList.of(new ChildNumber(44, true), ChildNumber.ZERO_HARDENED, ChildNumber.ZERO_HARDENED);

    // We try to ensure we have at least this many keys ready and waiting to be handed out via getKey().
    // See docs for getLookaheadSize() for more info on what this is for. The -1 value means it hasn't been calculated
    // yet. For new chains it's set to whatever the default is, unless overridden by setLookaheadSize. For deserialized
    // chains, it will be calculated on demand from the number of loaded keys.
    private static final int LAZY_CALCULATE_LOOKAHEAD = -1;
    protected int lookaheadSize = 100;
    // The lookahead threshold causes us to batch up creation of new keys to minimize the frequency of Bloom filter
    // regenerations, which are expensive and will (in future) trigger chain download stalls/retries. One third
    // is an efficiency tradeoff.
    protected int lookaheadThreshold = calcDefaultLookaheadThreshold();

    private int calcDefaultLookaheadThreshold() {
        return lookaheadSize / 3;
    }

    // The parent keys for external keys (handed out to other people) and internal keys (used for change addresses).
    private DeterministicKey externalParentKey, internalParentKey;
    // How many keys on each path have actually been used. This may be fewer than the number that have been deserialized
    // or held in memory, because of the lookahead zone.
    private int issuedExternalKeys, issuedInternalKeys;
    // A counter that is incremented each time a key in the lookahead threshold zone is marked as used and lookahead
    // is triggered. The Wallet/KCG reads these counters and combines them so it can tell the Peer whether to throw
    // away the current block (and any future blocks in the same download batch) and restart chain sync once a new
    // filter has been calculated. This field isn't persisted to the wallet as it's only relevant within a network
    // session.
    private int keyLookaheadEpoch;

    // We simplify by wrapping a basic key chain and that way we get some functionality like key lookup and event
    // listeners "for free". All keys in the key tree appear here, even if they aren't meant to be used for receiving
    // money.
    private final BasicKeyChain basicKeyChain;

    // If set this chain is following another chain in a married KeyChainGroup
    private boolean isFollowing;

    // holds a number of signatures required to spend. It's the N from N-of-M CHECKMULTISIG script for P2SH transactions
    // and always 1 for other transaction types
    protected int sigsRequiredToSpend = 1;


    public static class Builder<T extends Builder<T>> {
        protected SecureRandom random;
        protected int bits = 128;
        protected String passphrase;
        protected long seedCreationTimeSecs;
        protected byte[] entropy;
        protected DeterministicSeed seed;
        protected DeterministicKey watchingKey;

        protected Builder() {
        }

        @SuppressWarnings("unchecked")
        protected T self() {
            return (T)this;
        }

        /**
         * Creates a deterministic key chain starting from the given entropy. All keys yielded by this chain will be the same
         * if the starting entropy is the same. You should provide the creation time in seconds since the UNIX epoch for the
         * seed: this lets us know from what part of the chain we can expect to see derived keys appear.
         */
        public T entropy(byte[] entropy) {
            this.entropy = entropy;
            return self();
        }

        /**
         * Creates a deterministic key chain starting from the given seed. All keys yielded by this chain will be the same
         * if the starting seed is the same.
         */
        public T seed(DeterministicSeed seed) {
            this.seed = seed;
            return self();
        }

        /**
         * Generates a new key chain with entropy selected randomly from the given {@link java.security.SecureRandom}
         * object and of the requested size in bits.  The derived seed is further protected with a user selected passphrase
         * (see BIP 39).
         * @param random the random number generator - use new SecureRandom().
         * @param bits The number of bits of entropy to use when generating entropy.  Either 128 (default), 192 or 256.
         */
        public T random(SecureRandom random, int bits) {
            this.random = random;
            this.bits = bits;
            return self();
        }

        /**
         * Generates a new key chain with 128 bits of entropy selected randomly from the given {@link java.security.SecureRandom}
         * object.  The derived seed is further protected with a user selected passphrase
         * (see BIP 39).
         * @param random the random number generator - use new SecureRandom().
         */
        public T random(SecureRandom random) {
            this.random = random;
            return self();
        }

        public T watchingKey(DeterministicKey watchingKey) {
            this.watchingKey = watchingKey;
            return self();
        }

        public T seedCreationTimeSecs(long seedCreationTimeSecs) {
            this.seedCreationTimeSecs = seedCreationTimeSecs;
            return self();
        }

        /** The passphrase to use with the generated mnemonic, or null if you would like to use the default empty string. Currently must be the empty string. */
        public T passphrase(String passphrase) {
            // FIXME support non-empty passphrase
            this.passphrase = passphrase;
            return self();
        }

        public DeterministicKeyChain build() {
            checkState(random != null || entropy != null || seed != null || watchingKey!= null, "Must provide either entropy or random or seed or watchingKey");
            checkState(passphrase == null || seed == null, "Passphrase must not be specified with seed");
            DeterministicKeyChain chain;

            if (random != null) {
                // Default passphrase to "" if not specified
                chain = new DeterministicKeyChain(random, bits, getPassphrase(), seedCreationTimeSecs);
            } else if (entropy != null) {
                chain = new DeterministicKeyChain(entropy, getPassphrase(), seedCreationTimeSecs);
            } else if (seed != null) {
                seed.setCreationTimeSeconds(seedCreationTimeSecs);
                chain = new DeterministicKeyChain(seed);
            } else {
                watchingKey.setCreationTimeSeconds(seedCreationTimeSecs);
                chain = new DeterministicKeyChain(watchingKey);
            }

            return chain;
        }

        protected String getPassphrase() {
            return passphrase != null ? passphrase : DEFAULT_PASSPHRASE_FOR_MNEMONIC;
        }
    }

    public static Builder<?> builder() {
        return new Builder();
    }

    /**
     * Generates a new key chain with entropy selected randomly from the given {@link java.security.SecureRandom}
     * object and the default entropy size.
     */
    public DeterministicKeyChain(SecureRandom random) {
        this(random, DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS, DEFAULT_PASSPHRASE_FOR_MNEMONIC, Utils.currentTimeSeconds());
    }

    /**
     * Generates a new key chain with entropy selected randomly from the given {@link java.security.SecureRandom}
     * object and of the requested size in bits.
     */
    public DeterministicKeyChain(SecureRandom random, int bits) {
        this(random, bits, DEFAULT_PASSPHRASE_FOR_MNEMONIC, Utils.currentTimeSeconds());
    }

    /**
     * Generates a new key chain with entropy selected randomly from the given {@link java.security.SecureRandom}
     * object and of the requested size in bits.  The derived seed is further protected with a user selected passphrase
     * (see BIP 39).
     */
    public DeterministicKeyChain(SecureRandom random, int bits, String passphrase, long seedCreationTimeSecs) {
        this(new DeterministicSeed(random, bits, passphrase, seedCreationTimeSecs));
    }

    /**
     * Creates a deterministic key chain starting from the given entropy. All keys yielded by this chain will be the same
     * if the starting seed is the same. You should provide the creation time in seconds since the UNIX epoch for the
     * seed: this lets us know from what part of the chain we can expect to see derived keys appear.
     */
    public DeterministicKeyChain(byte[] entropy, String passphrase, long seedCreationTimeSecs) {
        this(new DeterministicSeed(entropy, passphrase, seedCreationTimeSecs));
    }

    /**
     * Creates a deterministic key chain starting from the given seed. All keys yielded by this chain will be the same
     * if the starting seed is the same.
     */
    protected DeterministicKeyChain(DeterministicSeed seed) {
        this(seed, null);
    }

    /**
     * Creates a deterministic key chain that watches the given (public only) root key. You can use this to calculate
     * balances and generally follow along, but spending is not possible with such a chain. Currently you can't use
     * this method to watch an arbitrary fragment of some other tree, this limitation may be removed in future.
     */
    public DeterministicKeyChain(DeterministicKey watchingKey) {
        checkArgument(watchingKey.isPubKeyOnly(), "Private subtrees not currently supported: if you got this key from DKC.getWatchingKey() then use .dropPrivate().dropParent() on it first.");
        checkArgument(watchingKey.getPath().size() == getAccountPath().size(), "You can only watch an account key currently");
        basicKeyChain = new BasicKeyChain();
        this.seed = null;
        rootKey = null;
        addToBasicChain(watchingKey);
        hierarchy = new DeterministicHierarchy(watchingKey);
        initializeHierarchyUnencrypted(watchingKey);
    }

    /**
     * <p>Creates a deterministic key chain with the given watch key. If <code>isFollowing</code> flag is set then this keychain follows
     * some other keychain. In a married wallet following keychain represents "spouse's" keychain.</p>
     * <p>Watch key has to be an account key.</p>
     */
    protected DeterministicKeyChain(DeterministicKey watchKey, boolean isFollowing) {
        this(watchKey);
        this.isFollowing = isFollowing;
    }

    /**
     * Creates a deterministic key chain with the given watch key and that follows some other keychain. In a married
     * wallet following keychain represents "spouse"
     * Watch key has to be an account key.
     */
    public static DeterministicKeyChain watchAndFollow(DeterministicKey watchKey) {
        return new DeterministicKeyChain(watchKey, true);
    }

    /**
     * Creates a key chain that watches the given account key.
     */
    public static DeterministicKeyChain watch(DeterministicKey accountKey) {
        return new DeterministicKeyChain(accountKey);
    }

    /**
     * For use in {@link KeyChainFactory} during deserialization.
     */
    protected DeterministicKeyChain(DeterministicSeed seed, @Nullable KeyCrypter crypter) {
        this.seed = seed;
        basicKeyChain = new BasicKeyChain(crypter);
        if (!seed.isEncrypted()) {
            rootKey = HDKeyDerivation.createMasterPrivateKey(checkNotNull(seed.getSeedBytes()));
            rootKey.setCreationTimeSeconds(seed.getCreationTimeSeconds());
            addToBasicChain(rootKey);
            hierarchy = new DeterministicHierarchy(rootKey);
            for (int i = 1; i <= getAccountPath().size(); i++) {
                addToBasicChain(hierarchy.get(getAccountPath().subList(0, i), false, true));
            }
            initializeHierarchyUnencrypted(rootKey);
        }
        // Else...
        // We can't initialize ourselves with just an encrypted seed, so we expected deserialization code to do the
        // rest of the setup (loading the root key).
    }

    /**
     * For use in encryption when {@link #toEncrypted(KeyCrypter, KeyParameter)} is called, so that
     * subclasses can override that method and create an instance of the right class.
     *
     * See also {@link #makeKeyChainFromSeed(DeterministicSeed)}
     */
    protected DeterministicKeyChain(KeyCrypter crypter, KeyParameter aesKey, DeterministicKeyChain chain) {
        // Can't encrypt a watching chain.
        checkNotNull(chain.rootKey);
        checkNotNull(chain.seed);

        checkArgument(!chain.rootKey.isEncrypted(), "Chain already encrypted");

        this.issuedExternalKeys = chain.issuedExternalKeys;
        this.issuedInternalKeys = chain.issuedInternalKeys;

        this.lookaheadSize = chain.lookaheadSize;
        this.lookaheadThreshold = chain.lookaheadThreshold;

        this.seed = chain.seed.encrypt(crypter, aesKey);
        basicKeyChain = new BasicKeyChain(crypter);
        // The first number is the "account number" but we don't use that feature.
        rootKey = chain.rootKey.encrypt(crypter, aesKey, null);
        hierarchy = new DeterministicHierarchy(rootKey);
        basicKeyChain.importKey(rootKey);

        for (int i = 1; i < getAccountPath().size(); i++) {
            encryptNonLeaf(aesKey, chain, rootKey, getAccountPath().subList(0, i));
        }
        DeterministicKey account = encryptNonLeaf(aesKey, chain, rootKey, getAccountPath());
        externalParentKey = encryptNonLeaf(aesKey, chain, account, HDUtils.concat(getAccountPath(), EXTERNAL_SUBPATH));
        internalParentKey = encryptNonLeaf(aesKey, chain, account, HDUtils.concat(getAccountPath(), INTERNAL_SUBPATH));

        // Now copy the (pubkey only) leaf keys across to avoid rederiving them. The private key bytes are missing
        // anyway so there's nothing to encrypt.
        for (ECKey eckey : chain.basicKeyChain.getKeys()) {
            DeterministicKey key = (DeterministicKey) eckey;
            if (key.getPath().size() != getAccountPath().size() + 2) continue; // Not a leaf key.
            DeterministicKey parent = hierarchy.get(checkNotNull(key.getParent()).getPath(), false, false);
            // Clone the key to the new encrypted hierarchy.
            key = new DeterministicKey(key.dropPrivateBytes(), parent);
            hierarchy.putKey(key);
            basicKeyChain.importKey(key);
        }
    }

    /** Override in subclasses to use a different account derivation path */
    protected ImmutableList<ChildNumber> getAccountPath() {
        return ACCOUNT_ZERO_PATH;
    }

    private DeterministicKey encryptNonLeaf(KeyParameter aesKey, DeterministicKeyChain chain,
                                            DeterministicKey parent, ImmutableList<ChildNumber> path) {
        DeterministicKey key = chain.hierarchy.get(path, false, false);
        key = key.encrypt(checkNotNull(basicKeyChain.getKeyCrypter()), aesKey, parent);
        hierarchy.putKey(key);
        basicKeyChain.importKey(key);
        return key;
    }

    // Derives the account path keys and inserts them into the basic key chain. This is important to preserve their
    // order for serialization, amongst other things.
    private void initializeHierarchyUnencrypted(DeterministicKey baseKey) {
        externalParentKey = hierarchy.deriveChild(getAccountPath(), false, false, ChildNumber.ZERO);
        internalParentKey = hierarchy.deriveChild(getAccountPath(), false, false, ChildNumber.ONE);
        addToBasicChain(externalParentKey);
        addToBasicChain(internalParentKey);
    }

    /** Returns a freshly derived key that has not been returned by this method before. */
    @Override
    public DeterministicKey getKey(KeyPurpose purpose) {
        return getKeys(purpose, 1).get(0);
    }

    /** Returns freshly derived key/s that have not been returned by this method before. */
    @Override
    public List<DeterministicKey> getKeys(KeyPurpose purpose, int numberOfKeys) {
        checkArgument(numberOfKeys > 0);
        lock.lock();
        try {
            DeterministicKey parentKey;
            int index;
            switch (purpose) {
                // Map both REFUND and RECEIVE_KEYS to the same branch for now. Refunds are a feature of the BIP 70
                // payment protocol. Later we may wish to map it to a different branch (in a new wallet version?).
                // This would allow a watching wallet to only be able to see inbound payments, but not change
                // (i.e. spends) or refunds. Might be useful for auditing ...
                case RECEIVE_FUNDS:
                case REFUND:
                    issuedExternalKeys += numberOfKeys;
                    index = issuedExternalKeys;
                    parentKey = externalParentKey;
                    break;
                case AUTHENTICATION:
                case CHANGE:
                    issuedInternalKeys += numberOfKeys;
                    index = issuedInternalKeys;
                    parentKey = internalParentKey;
                    break;
                default:
                    throw new UnsupportedOperationException();
            }
            // Optimization: potentially do a very quick key generation for just the number of keys we need if we
            // didn't already create them, ignoring the configured lookahead size. This ensures we'll be able to
            // retrieve the keys in the following loop, but if we're totally fresh and didn't get a chance to
            // calculate the lookahead keys yet, this will not block waiting to calculate 100+ EC point multiplies.
            // On slow/crappy Android phones looking ahead 100 keys can take ~5 seconds but the OS will kill us
            // if we block for just one second on the UI thread. Because UI threads may need an address in order
            // to render the screen, we need getKeys to be fast even if the wallet is totally brand new and lookahead
            // didn't happen yet.
            //
            // It's safe to do this because when a network thread tries to calculate a Bloom filter, we'll go ahead
            // and calculate the full lookahead zone there, so network requests will always use the right amount.
            List<DeterministicKey> lookahead = maybeLookAhead(parentKey, index, 0, 0);
            basicKeyChain.importKeys(lookahead);
            List<DeterministicKey> keys = new ArrayList<DeterministicKey>(numberOfKeys);
            for (int i = 0; i < numberOfKeys; i++) {
                ImmutableList<ChildNumber> path = HDUtils.append(parentKey.getPath(), new ChildNumber(index - numberOfKeys + i, false));
                DeterministicKey k = hierarchy.get(path, false, false);
                // Just a last minute sanity check before we hand the key out to the app for usage. This isn't inspired
                // by any real problem reports from bitcoinj users, but I've heard of cases via the grapevine of
                // places that lost money due to bitflips causing addresses to not match keys. Of course in an
                // environment with flaky RAM there's no real way to always win: bitflips could be introduced at any
                // other layer. But as we're potentially retrieving from long term storage here, check anyway.
                checkForBitFlip(k);
                keys.add(k);
            }
            return keys;
        } finally {
            lock.unlock();
        }
    }

    private void checkForBitFlip(DeterministicKey k) {
        DeterministicKey parent = checkNotNull(k.getParent());
        byte[] rederived = HDKeyDerivation.deriveChildKeyBytesFromPublic(parent, k.getChildNumber(), HDKeyDerivation.PublicDeriveMode.WITH_INVERSION).keyBytes;
        byte[] actual = k.getPubKey();
        if (!Arrays.equals(rederived, actual))
            throw new IllegalStateException(String.format(Locale.US, "Bit-flip check failed: %s vs %s", Arrays.toString(rederived), Arrays.toString(actual)));
    }

    private void addToBasicChain(DeterministicKey key) {
        basicKeyChain.importKeys(ImmutableList.of(key));
    }

    /**
     * Mark the DeterministicKey as used.
     * Also correct the issued{Internal|External}Keys counter, because all lower children seem to be requested already.
     * If the counter was updated, we also might trigger lookahead.
     */
    public DeterministicKey markKeyAsUsed(DeterministicKey k) {
        int numChildren = k.getChildNumber().i() + 1;

        if (k.getParent() == internalParentKey) {
            if (issuedInternalKeys < numChildren) {
                issuedInternalKeys = numChildren;
                maybeLookAhead();
            }
        } else if (k.getParent() == externalParentKey) {
            if (issuedExternalKeys < numChildren) {
                issuedExternalKeys = numChildren;
                maybeLookAhead();
            }
        }
        return k;
    }

    public DeterministicKey findKeyFromPubHash(byte[] pubkeyHash) {
        lock.lock();
        try {
            return (DeterministicKey) basicKeyChain.findKeyFromPubHash(pubkeyHash);
        } finally {
            lock.unlock();
        }
    }

    public DeterministicKey findKeyFromPubKey(byte[] pubkey) {
        lock.lock();
        try {
            return (DeterministicKey) basicKeyChain.findKeyFromPubKey(pubkey);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Mark the DeterministicKeys as used, if they match the pubkeyHash
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    @Nullable
    public DeterministicKey markPubHashAsUsed(byte[] pubkeyHash) {
        lock.lock();
        try {
            DeterministicKey k = (DeterministicKey) basicKeyChain.findKeyFromPubHash(pubkeyHash);
            if (k != null)
                markKeyAsUsed(k);
            return k;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Mark the DeterministicKeys as used, if they match the pubkey
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    @Nullable
    public DeterministicKey markPubKeyAsUsed(byte[] pubkey) {
        lock.lock();
        try {
            DeterministicKey k = (DeterministicKey) basicKeyChain.findKeyFromPubKey(pubkey);
            if (k != null)
                markKeyAsUsed(k);
            return k;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean hasKey(ECKey key) {
        lock.lock();
        try {
            return basicKeyChain.hasKey(key);
        } finally {
            lock.unlock();
        }
    }

    /** Returns the deterministic key for the given absolute path in the hierarchy. */
    protected DeterministicKey getKeyByPath(ChildNumber... path) {
        return getKeyByPath(ImmutableList.copyOf(path));
    }

    /** Returns the deterministic key for the given absolute path in the hierarchy. */
    protected DeterministicKey getKeyByPath(List<ChildNumber> path) {
        return getKeyByPath(path, false);
    }

    /** Returns the deterministic key for the given absolute path in the hierarchy, optionally creating it */
    public DeterministicKey getKeyByPath(List<ChildNumber> path, boolean create) {
        return hierarchy.get(path, false, create);
    }

    /**
     * <p>An alias for <code>getKeyByPath(getAccountPath())</code>.</p>
     *
     * <p>Use this when you would like to create a watching key chain that follows this one, but can't spend money from it.
     * The returned key can be serialized and then passed into {@link #watch(org.bitcoinj.crypto.DeterministicKey)}
     * on another system to watch the hierarchy.</p>
     *
     * <p>Note that the returned key is not pubkey only unless this key chain already is: the returned key can still
     * be used for signing etc if the private key bytes are available.</p>
     */
    public DeterministicKey getWatchingKey() {
        return getKeyByPath(getAccountPath());
    }

    /** Returns true if this chain is watch only, meaning it has public keys but no private key. */
    public boolean isWatching() {
        return getWatchingKey().isWatching();
    }

    @Override
    public int numKeys() {
        // We need to return here the total number of keys including the lookahead zone, not the number of keys we
        // have issued via getKey/freshReceiveKey.
        lock.lock();
        try {
            maybeLookAhead();
            return basicKeyChain.numKeys();
        } finally {
            lock.unlock();
        }

    }

    /**
     * Returns number of leaf keys used including both internal and external paths. This may be fewer than the number
     * that have been deserialized or held in memory, because of the lookahead zone.
     */
    public int numLeafKeysIssued() {
        lock.lock();
        try {
            return issuedExternalKeys + issuedInternalKeys;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long getEarliestKeyCreationTime() {
        if (seed != null)
            return seed.getCreationTimeSeconds();
        else
            return getWatchingKey().getCreationTimeSeconds();
    }

    @Override
    public void addEventListener(KeyChainEventListener listener) {
        basicKeyChain.addEventListener(listener);
    }

    @Override
    public void addEventListener(KeyChainEventListener listener, Executor executor) {
        basicKeyChain.addEventListener(listener, executor);
    }

    @Override
    public boolean removeEventListener(KeyChainEventListener listener) {
        return basicKeyChain.removeEventListener(listener);
    }

    /** Returns a list of words that represent the seed or null if this chain is a watching chain. */
    @Nullable
    public List<String> getMnemonicCode() {
        if (seed == null) return null;

        lock.lock();
        try {
            return seed.getMnemonicCode();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Return true if this keychain is following another keychain
     */
    public boolean isFollowing() {
        return isFollowing;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Serialization support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public List<Protos.Key> serializeToProtobuf() {
        List<Protos.Key> result = newArrayList();
        lock.lock();
        try {
            result.addAll(serializeMyselfToProtobuf());
        } finally {
            lock.unlock();
        }
        return result;
    }

    protected List<Protos.Key> serializeMyselfToProtobuf() {
        // Most of the serialization work is delegated to the basic key chain, which will serialize the bulk of the
        // data (handling encryption along the way), and letting us patch it up with the extra data we care about.
        LinkedList<Protos.Key> entries = newLinkedList();
        if (seed != null) {
            Protos.Key.Builder mnemonicEntry = BasicKeyChain.serializeEncryptableItem(seed);
            mnemonicEntry.setType(Protos.Key.Type.DETERMINISTIC_MNEMONIC);
            serializeSeedEncryptableItem(seed, mnemonicEntry);
            entries.add(mnemonicEntry.build());
        }
        Map<ECKey, Protos.Key.Builder> keys = basicKeyChain.serializeToEditableProtobufs();
        for (Map.Entry<ECKey, Protos.Key.Builder> entry : keys.entrySet()) {
            DeterministicKey key = (DeterministicKey) entry.getKey();
            Protos.Key.Builder proto = entry.getValue();
            proto.setType(Protos.Key.Type.DETERMINISTIC_KEY);
            final Protos.DeterministicKey.Builder detKey = proto.getDeterministicKeyBuilder();
            detKey.setChainCode(ByteString.copyFrom(key.getChainCode()));
            for (ChildNumber num : key.getPath())
                detKey.addPath(num.i());
            if (key.equals(externalParentKey)) {
                detKey.setIssuedSubkeys(issuedExternalKeys);
                detKey.setLookaheadSize(lookaheadSize);
                detKey.setSigsRequiredToSpend(getSigsRequiredToSpend());
            } else if (key.equals(internalParentKey)) {
                detKey.setIssuedSubkeys(issuedInternalKeys);
                detKey.setLookaheadSize(lookaheadSize);
                detKey.setSigsRequiredToSpend(getSigsRequiredToSpend());
            }
            // Flag the very first key of following keychain.
            if (entries.isEmpty() && isFollowing()) {
                detKey.setIsFollowing(true);
            }
            if (key.getParent() != null) {
                // HD keys inherit the timestamp of their parent if they have one, so no need to serialize it.
                proto.clearCreationTimestamp();
            }
            entries.add(proto.build());
        }
        return entries;
    }

    static List<DeterministicKeyChain> fromProtobuf(List<Protos.Key> keys, @Nullable KeyCrypter crypter) throws UnreadableWalletException {
        return fromProtobuf(keys, crypter, new DefaultKeyChainFactory());
    }

    /**
     * Returns all the key chains found in the given list of keys. Typically there will only be one, but in the case of
     * key rotation it can happen that there are multiple chains found.
     */
    public static List<DeterministicKeyChain> fromProtobuf(List<Protos.Key> keys, @Nullable KeyCrypter crypter, KeyChainFactory factory) throws UnreadableWalletException {
        List<DeterministicKeyChain> chains = newLinkedList();
        DeterministicSeed seed = null;
        DeterministicKeyChain chain = null;

        int lookaheadSize = -1;
        int sigsRequiredToSpend = 1;

        PeekingIterator<Protos.Key> iter = Iterators.peekingIterator(keys.iterator());
        while (iter.hasNext()) {
            Protos.Key key = iter.next();
            final Protos.Key.Type t = key.getType();
            if (t == Protos.Key.Type.DETERMINISTIC_MNEMONIC) {
                if (chain != null) {
                    checkState(lookaheadSize >= 0);
                    chain.setLookaheadSize(lookaheadSize);
                    chain.setSigsRequiredToSpend(sigsRequiredToSpend);
                    chain.maybeLookAhead();
                    chains.add(chain);
                    chain = null;
                }
                long timestamp = key.getCreationTimestamp() / 1000;
                String passphrase = DEFAULT_PASSPHRASE_FOR_MNEMONIC; // FIXME allow non-empty passphrase
                if (key.hasSecretBytes()) {
                    if (key.hasEncryptedDeterministicSeed())
                        throw new UnreadableWalletException("Malformed key proto: " + key.toString());
                    byte[] seedBytes = null;
                    if (key.hasDeterministicSeed()) {
                        seedBytes = key.getDeterministicSeed().toByteArray();
                    }
                    seed = new DeterministicSeed(key.getSecretBytes().toStringUtf8(), seedBytes, passphrase, timestamp);
                } else if (key.hasEncryptedData()) {
                    if (key.hasDeterministicSeed())
                        throw new UnreadableWalletException("Malformed key proto: " + key.toString());
                    EncryptedData data = new EncryptedData(key.getEncryptedData().getInitialisationVector().toByteArray(),
                            key.getEncryptedData().getEncryptedPrivateKey().toByteArray());
                    EncryptedData encryptedSeedBytes = null;
                    if (key.hasEncryptedDeterministicSeed()) {
                        Protos.EncryptedData encryptedSeed = key.getEncryptedDeterministicSeed();
                        encryptedSeedBytes = new EncryptedData(encryptedSeed.getInitialisationVector().toByteArray(),
                                encryptedSeed.getEncryptedPrivateKey().toByteArray());
                    }
                    seed = new DeterministicSeed(data, encryptedSeedBytes, timestamp);
                } else {
                    throw new UnreadableWalletException("Malformed key proto: " + key.toString());
                }
                if (log.isDebugEnabled())
                    log.debug("Deserializing: DETERMINISTIC_MNEMONIC: {}", seed);
            } else if (t == Protos.Key.Type.DETERMINISTIC_KEY) {
                if (!key.hasDeterministicKey())
                    throw new UnreadableWalletException("Deterministic key missing extra data: " + key.toString());
                byte[] chainCode = key.getDeterministicKey().getChainCode().toByteArray();
                // Deserialize the path through the tree.
                LinkedList<ChildNumber> path = newLinkedList();
                for (int i : key.getDeterministicKey().getPathList())
                    path.add(new ChildNumber(i));
                // Deserialize the public key and path.
                LazyECPoint pubkey = new LazyECPoint(ECKey.CURVE.getCurve(), key.getPublicKey().toByteArray());
                final ImmutableList<ChildNumber> immutablePath = ImmutableList.copyOf(path);
                // Possibly create the chain, if we didn't already do so yet.
                boolean isWatchingAccountKey = false;
                boolean isFollowingKey = false;
                // save previous chain if any if the key is marked as following. Current key and the next ones are to be
                // placed in new following key chain
                if (key.getDeterministicKey().getIsFollowing()) {
                    if (chain != null) {
                        checkState(lookaheadSize >= 0);
                        chain.setLookaheadSize(lookaheadSize);
                        chain.setSigsRequiredToSpend(sigsRequiredToSpend);
                        chain.maybeLookAhead();
                        chains.add(chain);
                        chain = null;
                        seed = null;
                    }
                    isFollowingKey = true;
                }
                if (chain == null) {
                    // If this is not a following chain and previous was, this must be married
                    boolean isMarried = !isFollowingKey && !chains.isEmpty() && chains.get(chains.size() - 1).isFollowing();
                    if (seed == null) {
                        DeterministicKey accountKey = new DeterministicKey(immutablePath, chainCode, pubkey, null, null);
                        accountKey.setCreationTimeSeconds(key.getCreationTimestamp() / 1000);
                        chain = factory.makeWatchingKeyChain(key, iter.peek(), accountKey, isFollowingKey, isMarried);
                        isWatchingAccountKey = true;
                    } else {
                        chain = factory.makeKeyChain(key, iter.peek(), seed, crypter, isMarried);
                        chain.lookaheadSize = LAZY_CALCULATE_LOOKAHEAD;
                        // If the seed is encrypted, then the chain is incomplete at this point. However, we will load
                        // it up below as we parse in the keys. We just need to check at the end that we've loaded
                        // everything afterwards.
                    }
                }
                // Find the parent key assuming this is not the root key, and not an account key for a watching chain.
                DeterministicKey parent = null;
                if (!path.isEmpty() && !isWatchingAccountKey) {
                    ChildNumber index = path.removeLast();
                    parent = chain.hierarchy.get(path, false, false);
                    path.add(index);
                }
                DeterministicKey detkey;
                if (key.hasSecretBytes()) {
                    // Not encrypted: private key is available.
                    final BigInteger priv = new BigInteger(1, key.getSecretBytes().toByteArray());
                    detkey = new DeterministicKey(immutablePath, chainCode, pubkey, priv, parent);
                } else {
                    if (key.hasEncryptedData()) {
                        Protos.EncryptedData proto = key.getEncryptedData();
                        EncryptedData data = new EncryptedData(proto.getInitialisationVector().toByteArray(),
                                proto.getEncryptedPrivateKey().toByteArray());
                        checkNotNull(crypter, "Encountered an encrypted key but no key crypter provided");
                        detkey = new DeterministicKey(immutablePath, chainCode, crypter, pubkey, data, parent);
                    } else {
                        // No secret key bytes and key is not encrypted: either a watching key or private key bytes
                        // will be rederived on the fly from the parent.
                        detkey = new DeterministicKey(immutablePath, chainCode, pubkey, null, parent);
                    }
                }
                if (key.hasCreationTimestamp())
                    detkey.setCreationTimeSeconds(key.getCreationTimestamp() / 1000);
                if (log.isDebugEnabled())
                    log.debug("Deserializing: DETERMINISTIC_KEY: {}", detkey);
                if (!isWatchingAccountKey) {
                    // If the non-encrypted case, the non-leaf keys (account, internal, external) have already
                    // been rederived and inserted at this point. In the encrypted case though,
                    // we can't rederive and we must reinsert, potentially building the heirarchy object
                    // if need be.
                    if (path.size() == 0) {
                        // Master key.
                        if (chain.rootKey == null) {
                            chain.rootKey = detkey;
                            chain.hierarchy = new DeterministicHierarchy(detkey);
                        }
                    } else if (path.size() == chain.getAccountPath().size() + 1) {
                        if (detkey.getChildNumber().num() == 0) {
                            chain.externalParentKey = detkey;
                            chain.issuedExternalKeys = key.getDeterministicKey().getIssuedSubkeys();
                            lookaheadSize = Math.max(lookaheadSize, key.getDeterministicKey().getLookaheadSize());
                            sigsRequiredToSpend = key.getDeterministicKey().getSigsRequiredToSpend();
                        } else if (detkey.getChildNumber().num() == 1) {
                            chain.internalParentKey = detkey;
                            chain.issuedInternalKeys = key.getDeterministicKey().getIssuedSubkeys();
                        }
                    }
                }
                chain.hierarchy.putKey(detkey);
                chain.basicKeyChain.importKey(detkey);
            }
        }
        if (chain != null) {
            checkState(lookaheadSize >= 0);
            chain.setLookaheadSize(lookaheadSize);
            chain.setSigsRequiredToSpend(sigsRequiredToSpend);
            chain.maybeLookAhead();
            chains.add(chain);
        }
        return chains;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Encryption support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public DeterministicKeyChain toEncrypted(CharSequence password) {
        checkNotNull(password);
        checkArgument(password.length() > 0);
        checkState(seed != null, "Attempt to encrypt a watching chain.");
        checkState(!seed.isEncrypted());
        KeyCrypter scrypt = new KeyCrypterScrypt();
        KeyParameter derivedKey = scrypt.deriveKey(password);
        return toEncrypted(scrypt, derivedKey);
    }

    @Override
    public DeterministicKeyChain toEncrypted(KeyCrypter keyCrypter, KeyParameter aesKey) {
        return new DeterministicKeyChain(keyCrypter, aesKey, this);
    }

    @Override
    public DeterministicKeyChain toDecrypted(CharSequence password) {
        checkNotNull(password);
        checkArgument(password.length() > 0);
        KeyCrypter crypter = getKeyCrypter();
        checkState(crypter != null, "Chain not encrypted");
        KeyParameter derivedKey = crypter.deriveKey(password);
        return toDecrypted(derivedKey);
    }

    @Override
    public DeterministicKeyChain toDecrypted(KeyParameter aesKey) {
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        checkState(seed != null, "Can't decrypt a watching chain");
        checkState(seed.isEncrypted());
        String passphrase = DEFAULT_PASSPHRASE_FOR_MNEMONIC; // FIXME allow non-empty passphrase
        DeterministicSeed decSeed = seed.decrypt(getKeyCrypter(), passphrase, aesKey);
        DeterministicKeyChain chain = makeKeyChainFromSeed(decSeed);
        // Now double check that the keys match to catch the case where the key is wrong but padding didn't catch it.
        if (!chain.getWatchingKey().getPubKeyPoint().equals(getWatchingKey().getPubKeyPoint()))
            throw new KeyCrypterException("Provided AES key is wrong");
        chain.lookaheadSize = lookaheadSize;
        // Now copy the (pubkey only) leaf keys across to avoid rederiving them. The private key bytes are missing
        // anyway so there's nothing to decrypt.
        for (ECKey eckey : basicKeyChain.getKeys()) {
            DeterministicKey key = (DeterministicKey) eckey;
            if (key.getPath().size() != getAccountPath().size() + 2) continue; // Not a leaf key.
            checkState(key.isEncrypted());
            DeterministicKey parent = chain.hierarchy.get(checkNotNull(key.getParent()).getPath(), false, false);
            // Clone the key to the new decrypted hierarchy.
            key = new DeterministicKey(key.dropPrivateBytes(), parent);
            chain.hierarchy.putKey(key);
            chain.basicKeyChain.importKey(key);
        }
        chain.issuedExternalKeys = issuedExternalKeys;
        chain.issuedInternalKeys = issuedInternalKeys;
        return chain;
    }

    /**
     * Factory method to create a key chain from a seed.
     * Subclasses should override this to create an instance of the subclass instead of a plain DKC.
     * This is used in encryption/decryption.
     */
    protected DeterministicKeyChain makeKeyChainFromSeed(DeterministicSeed seed) {
        return new DeterministicKeyChain(seed);
    }

    @Override
    public boolean checkPassword(CharSequence password) {
        checkNotNull(password);
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        return checkAESKey(getKeyCrypter().deriveKey(password));
    }

    @Override
    public boolean checkAESKey(KeyParameter aesKey) {
        checkState(rootKey != null, "Can't check password for a watching chain");
        checkNotNull(aesKey);
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        try {
            return rootKey.decrypt(aesKey).getPubKeyPoint().equals(rootKey.getPubKeyPoint());
        } catch (KeyCrypterException e) {
            return false;
        }
    }

    @Nullable
    @Override
    public KeyCrypter getKeyCrypter() {
        return basicKeyChain.getKeyCrypter();
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Bloom filtering support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    @Override
    public int numBloomFilterEntries() {
        return numKeys() * 2;
    }

    @Override
    public BloomFilter getFilter(int size, double falsePositiveRate, long tweak) {
        lock.lock();
        try {
            checkArgument(size >= numBloomFilterEntries());
            maybeLookAhead();
            return basicKeyChain.getFilter(size, falsePositiveRate, tweak);
        } finally {
            lock.unlock();
        }

    }

    /**
     * <p>The number of public keys we should pre-generate on each path before they are requested by the app. This is
     * required so that when scanning through the chain given only a seed, we can give enough keys to the remote node
     * via the Bloom filter such that we see transactions that are "from the future", for example transactions created
     * by a different app that's sharing the same seed, or transactions we made before but we're replaying the chain
     * given just the seed. The default is 100.</p>
     */
    public int getLookaheadSize() {
        lock.lock();
        try {
            return lookaheadSize;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets a new lookahead size. See {@link #getLookaheadSize()} for details on what this is. Setting a new size
     * that's larger than the current size will return immediately and the new size will only take effect next time
     * a fresh filter is requested (e.g. due to a new peer being connected). So you should set this before starting
     * to sync the chain, if you want to modify it. If you haven't modified the lookahead threshold manually then
     * it will be automatically set to be a third of the new size.
     */
    public void setLookaheadSize(int lookaheadSize) {
        lock.lock();
        try {
            boolean readjustThreshold = this.lookaheadThreshold == calcDefaultLookaheadThreshold();
            this.lookaheadSize = lookaheadSize;
            if (readjustThreshold)
                this.lookaheadThreshold = calcDefaultLookaheadThreshold();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets the threshold for the key pre-generation. This is used to avoid adding new keys and thus
     * re-calculating Bloom filters every time a new key is calculated. Without a lookahead threshold, every time we
     * received a relevant transaction we'd extend the lookahead zone and generate a new filter, which is inefficient.
     */
    public void setLookaheadThreshold(int num) {
        lock.lock();
        try {
            if (num >= lookaheadSize)
                throw new IllegalArgumentException("Threshold larger or equal to the lookaheadSize");
            this.lookaheadThreshold = num;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Gets the threshold for the key pre-generation. See {@link #setLookaheadThreshold(int)} for details on what this
     * is. The default is a third of the lookahead size (100 / 3 == 33). If you don't modify it explicitly then this
     * value will always be one third of the lookahead size.
     */
    public int getLookaheadThreshold() {
        lock.lock();
        try {
            if (lookaheadThreshold >= lookaheadSize)
                return 0;
            return lookaheadThreshold;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Pre-generate enough keys to reach the lookahead size. You can call this if you need to explicitly invoke
     * the lookahead procedure, but it's normally unnecessary as it will be done automatically when needed.
     */
    public void maybeLookAhead() {
        lock.lock();
        try {
            List<DeterministicKey> keys = maybeLookAhead(externalParentKey, issuedExternalKeys);
            keys.addAll(maybeLookAhead(internalParentKey, issuedInternalKeys));
            if (keys.isEmpty())
                return;
            keyLookaheadEpoch++;
            // Batch add all keys at once so there's only one event listener invocation, as this will be listened to
            // by the wallet and used to rebuild/broadcast the Bloom filter. That's expensive so we don't want to do
            // it more often than necessary.
            basicKeyChain.importKeys(keys);
        } finally {
            lock.unlock();
        }
    }

    private List<DeterministicKey> maybeLookAhead(DeterministicKey parent, int issued) {
        checkState(lock.isHeldByCurrentThread());
        return maybeLookAhead(parent, issued, getLookaheadSize(), getLookaheadThreshold());
    }

    /**
     * Pre-generate enough keys to reach the lookahead size, but only if there are more than the lookaheadThreshold to
     * be generated, so that the Bloom filter does not have to be regenerated that often.
     *
     * The returned mutable list of keys must be inserted into the basic key chain.
     */
    private List<DeterministicKey> maybeLookAhead(DeterministicKey parent, int issued, int lookaheadSize, int lookaheadThreshold) {
        checkState(lock.isHeldByCurrentThread());
        final int numChildren = hierarchy.getNumChildren(parent.getPath());
        final int needed = issued + lookaheadSize + lookaheadThreshold - numChildren;

        if (needed <= lookaheadThreshold)
            return new ArrayList<DeterministicKey>();

        log.info("{} keys needed for {} = {} issued + {} lookahead size + {} lookahead threshold - {} num children",
                needed, parent.getPathAsString(), issued, lookaheadSize, lookaheadThreshold, numChildren);

        List<DeterministicKey> result  = new ArrayList<DeterministicKey>(needed);
        final Stopwatch watch = Stopwatch.createStarted();
        int nextChild = numChildren;
        for (int i = 0; i < needed; i++) {
            DeterministicKey key = HDKeyDerivation.deriveThisOrNextChildKey(parent, nextChild);
            key = key.dropPrivateBytes();
            hierarchy.putKey(key);
            result.add(key);
            nextChild = key.getChildNumber().num() + 1;
        }
        watch.stop();
        log.info("Took {}", watch);
        return result;
    }

    /** Housekeeping call to call when lookahead might be needed.  Normally called automatically by KeychainGroup. */
    public void maybeLookAheadScripts() {
    }

    /**
     * Returns number of keys used on external path. This may be fewer than the number that have been deserialized
     * or held in memory, because of the lookahead zone.
     */
    public int getIssuedExternalKeys() {
        lock.lock();
        try {
            return issuedExternalKeys;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns number of keys used on internal path. This may be fewer than the number that have been deserialized
     * or held in memory, because of the lookahead zone.
     */
    public int getIssuedInternalKeys() {
        lock.lock();
        try {
            return issuedInternalKeys;
        } finally {
            lock.unlock();
        }
    }

    /** Returns the seed or null if this chain is a watching chain. */
    @Nullable
    public DeterministicSeed getSeed() {
        lock.lock();
        try {
            return seed;
        } finally {
            lock.unlock();
        }
    }

    // For internal usage only
    /* package */ List<ECKey> getKeys(boolean includeLookahead) {
        List<ECKey> keys = basicKeyChain.getKeys();
        if (!includeLookahead) {
            int treeSize = internalParentKey.getPath().size();
            List<ECKey> issuedKeys = new LinkedList<ECKey>();
            for (ECKey key : keys) {
                DeterministicKey detkey = (DeterministicKey) key;
                DeterministicKey parent = detkey.getParent();
                if (parent == null) continue;
                if (detkey.getPath().size() <= treeSize) continue;
                if (parent.equals(internalParentKey) && detkey.getChildNumber().i() >= issuedInternalKeys) continue;
                if (parent.equals(externalParentKey) && detkey.getChildNumber().i() >= issuedExternalKeys) continue;
                issuedKeys.add(detkey);
            }
            return issuedKeys;
        }
        return keys;
    }

    /**
     * Returns only the external keys that have been issued by this chain, lookahead not included.
     */
    public List<ECKey> getIssuedReceiveKeys() {
        final List<ECKey> keys = new ArrayList<ECKey>(getKeys(false));
        for (Iterator<ECKey> i = keys.iterator(); i.hasNext();) {
            DeterministicKey parent = ((DeterministicKey) i.next()).getParent();
            if (parent == null || !externalParentKey.equals(parent))
                i.remove();
        }
        return keys;
    }

    /**
     * Returns leaf keys issued by this chain (including lookahead zone)
     */
    public List<DeterministicKey> getLeafKeys() {
        ImmutableList.Builder<DeterministicKey> keys = ImmutableList.builder();
        for (ECKey key : getKeys(true)) {
            DeterministicKey dKey = (DeterministicKey) key;
            if (dKey.getPath().size() == getAccountPath().size() + 2) {
                keys.add(dKey);
            }
        }
        return keys.build();
    }

    /*package*/ static void serializeSeedEncryptableItem(DeterministicSeed seed, Protos.Key.Builder proto) {
        // The seed can be missing if we have not derived it yet from the mnemonic.
        // This will not normally happen once all the wallets are on the latest code that caches
        // the seed.
        if (seed.isEncrypted() && seed.getEncryptedSeedData() != null) {
            EncryptedData data = seed.getEncryptedSeedData();
            proto.getEncryptedDeterministicSeedBuilder()
                    .setEncryptedPrivateKey(ByteString.copyFrom(data.encryptedBytes))
                    .setInitialisationVector(ByteString.copyFrom(data.initialisationVector));
            // We don't allow mixing of encryption types at the moment.
            checkState(seed.getEncryptionType() == Protos.Wallet.EncryptionType.ENCRYPTED_SCRYPT_AES);
        } else {
            final byte[] secret = seed.getSeedBytes();
            if (secret != null)
                proto.setDeterministicSeed(ByteString.copyFrom(secret));
        }
    }

    /**
     * Returns a counter that is incremented each time new keys are generated due to lookahead. Used by the network
     * code to learn whether to discard the current block and await calculation of a new filter.
     */
    public int getKeyLookaheadEpoch() {
        lock.lock();
        try {
            return keyLookaheadEpoch;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Whether the keychain is married.  A keychain is married when it vends P2SH addresses
     * from multiple keychains in a multisig relationship.
     * @see org.bitcoinj.wallet.MarriedKeyChain
     */
    public boolean isMarried() {
        return false;
    }

    /** Get redeem data for a key.  Only applicable to married keychains. */
    public RedeemData getRedeemData(DeterministicKey followedKey) {
        throw new UnsupportedOperationException();
    }

    /** Create a new key and return the matching output script.  Only applicable to married keychains. */
    public Script freshOutputScript(KeyPurpose purpose) {
        throw new UnsupportedOperationException();
    }

    public String toString(boolean includePrivateKeys, NetworkParameters params) {
        final DeterministicKey watchingKey = getWatchingKey();
        final StringBuilder builder = new StringBuilder();
        if (seed != null) {
            if (seed.isEncrypted()) {
                builder.append("Seed is encrypted\n");
            } else if (includePrivateKeys) {
                final List<String> words = seed.getMnemonicCode();
                builder.append("Seed as words: ").append(Utils.join(words)).append('\n');
                builder.append("Seed as hex:   ").append(seed.toHexString()).append('\n');
            }
            builder.append("Seed birthday: ").append(seed.getCreationTimeSeconds()).append("  [")
                    .append(Utils.dateTimeFormat(seed.getCreationTimeSeconds() * 1000)).append("]\n");
        } else {
            builder.append("Key birthday:  ").append(watchingKey.getCreationTimeSeconds()).append("  [")
                    .append(Utils.dateTimeFormat(watchingKey.getCreationTimeSeconds() * 1000)).append("]\n");
        }
        builder.append("Key to watch:  ").append(watchingKey.serializePubB58(params)).append('\n');
        formatAddresses(includePrivateKeys, params, builder);
        return builder.toString();
    }

    protected void formatAddresses(boolean includePrivateKeys, NetworkParameters params, StringBuilder builder2) {
        for (ECKey key : getKeys(false))
            key.formatKeyWithAddress(includePrivateKeys, builder2, params);
    }

    /** The number of signatures required to spend coins received by this keychain. */
    public void setSigsRequiredToSpend(int sigsRequiredToSpend) {
        this.sigsRequiredToSpend = sigsRequiredToSpend;
    }

    /**
     * Returns the number of signatures required to spend transactions for this KeyChain. It's the N from
     * N-of-M CHECKMULTISIG script for P2SH transactions and always 1 for other transaction types.
     */
    public int getSigsRequiredToSpend() {
        return sigsRequiredToSpend;
    }

    /** Returns the redeem script by its hash or null if this keychain did not generate the script. */
    @Nullable
    public RedeemData findRedeemDataByScriptHash(ByteString bytes) {
        return null;
    }
}
