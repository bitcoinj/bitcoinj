/**
 * Copyright 2013 The bitcoinj developers.
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

package com.google.bitcoin.wallet;

import com.google.bitcoin.core.BloomFilter;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.crypto.*;
import com.google.bitcoin.store.UnreadableWalletException;
import com.google.bitcoin.utils.Threading;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import org.bitcoinj.wallet.Protos;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.*;
import static com.google.common.collect.Lists.newLinkedList;

/**
 * <p>A deterministic key chain is a {@link KeyChain} that uses the
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP 32 standard</a>, as implemented by
 * {@link com.google.bitcoin.crypto.DeterministicHierarchy}, to derive all the keys in the keychain from a master seed.
 * This type of wallet is extremely convenient and flexible. Although backing up full wallet files is always a good
 * idea, to recover money only the root seed needs to be preserved and that is a number small enough that it can be
 * written down on paper or, when represented using a BIP 39 {@link com.google.bitcoin.crypto.MnemonicCode},
 * dictated over the phone (possibly even memorized).</p>
 *
 * <p>Deterministic key chains have other advantages: parts of the key tree can be selectively revealed to allow
 * for auditing, and new public keys can be generated without access to the private keys, yielding a highly secure
 * configuration for web servers which can accept payments into a wallet but not spend from them. This does not work
 * quite how you would expect due to a quirk of elliptic curve mathematics and the techniques used to deal with it.
 * A watching wallet is not instantiated using the public part of the master key as you may imagine. Instead, you
 * need to take the account key (first child of the master key) and provide the public part of that to the watching
 * wallet instead. You can do this by calling {@link #getWatchingKey()} and then serializing it with
 * {@link com.google.bitcoin.crypto.DeterministicKey#serializePubB58()}. The resulting "xpub..." string encodes
 * sufficient information about the account key to create a watching chain via
 * {@link com.google.bitcoin.crypto.DeterministicKey#deserializeB58(com.google.bitcoin.crypto.DeterministicKey, String)}
 * (with null as the first parameter) and then {@link #watch(com.google.bitcoin.crypto.DeterministicKey)}.</p>
 *
 * <p>This class builds on {@link com.google.bitcoin.crypto.DeterministicHierarchy} and
 * {@link com.google.bitcoin.crypto.DeterministicKey} by adding support for serialization to and from protobufs,
 * and encryption of parts of the key tree. Internally it arranges itself as per the BIP 32 spec, with the seed being
 * used to derive a master key, which is then used to derive an account key, the account key is used to derive two
 * child keys called the <i>internal</i> and <i>external</i> keys (for change and handing out addresses respectively)
 * and finally the actual leaf keys that users use hanging off the end. The leaf keys are special in that they don't
 * internally store the private part at all, instead choosing to rederive the private key from the parent when
 * needed for signing. This simplifies the design for encrypted key chains.</p>
 */
public class DeterministicKeyChain implements EncryptableKeyChain {
    private static final Logger log = LoggerFactory.getLogger(DeterministicKeyChain.class);
    private final ReentrantLock lock = Threading.lock("DeterministicKeyChain");

    private DeterministicHierarchy hierarchy;
    private DeterministicKey rootKey;
    private DeterministicSeed seed;

    // Paths through the key tree. External keys are ones that are communicated to other parties. Internal keys are
    // keys created for change addresses, coinbases, mixing, etc - anything that isn't communicated. The distinction
    // is somewhat arbitrary but can be useful for audits. The first number is the "account number" but we don't use
    // that feature yet. In future we might hand out different accounts for cases where we wish to hand payers
    // a payment request that can generate lots of addresses independently.
    public static final ImmutableList<ChildNumber> ACCOUNT_ZERO_PATH = ImmutableList.of(ChildNumber.ZERO_HARDENED);
    public static final ImmutableList<ChildNumber> EXTERNAL_PATH = ImmutableList.of(ChildNumber.ZERO_HARDENED, ChildNumber.ZERO);
    public static final ImmutableList<ChildNumber> INTERNAL_PATH = ImmutableList.of(ChildNumber.ZERO_HARDENED, new ChildNumber(1, false));

    // We try to ensure we have at least this many keys ready and waiting to be handed out via getKey().
    // See docs for getLookaheadSize() for more info on what this is for. The -1 value means it hasn't been calculated
    // yet. For new chains it's set to whatever the default is, unless overridden by setLookaheadSize. For deserialized
    // chains, it will be calculated on demand from the number of loaded keys.
    private static final int LAZY_CALCULATE_LOOKAHEAD = -1;
    private int lookaheadSize = 100;

    // The parent keys for external keys (handed out to other people) and internal keys (used for change addresses).
    private DeterministicKey externalKey, internalKey;
    // How many keys on each path have actually been used. This may be fewer than the number that have been deserialized
    // or held in memory, because of the lookahead zone.
    private int issuedExternalKeys, issuedInternalKeys;

    // We simplify by wrapping a basic key chain and that way we get some functionality like key lookup and event
    // listeners "for free". All keys in the key tree appear here, even if they aren't meant to be used for receiving
    // money.
    private final BasicKeyChain basicKeyChain;

    /**
     * Generates a new key chain with a 128 bit seed selected randomly from the given {@link java.security.SecureRandom}
     * object.
     */
    public DeterministicKeyChain(SecureRandom random) {
        this(getRandomSeed(random), Utils.currentTimeMillis() / 1000);
    }

    private static byte[] getRandomSeed(SecureRandom random) {
        byte[] seed = new byte[128 / 8];
        random.nextBytes(seed);
        return seed;
    }

    /**
     * Creates a deterministic key chain starting from the given seed. All keys yielded by this chain will be the same
     * if the starting seed is the same. You should provide the creation time in seconds since the UNIX epoch for the
     * seed: this lets us know from what part of the chain we can expect to see derived keys appear.
     */
    public DeterministicKeyChain(byte[] seed, long seedCreationTimeSecs) {
        this(new DeterministicSeed(seed, seedCreationTimeSecs));
    }

    public DeterministicKeyChain(DeterministicSeed seed) {
        this(seed, null);
    }

    // c'tor for building watching chains, we keep it private and give it a static name to make the purpose clear.
    private DeterministicKeyChain(DeterministicKey accountKey) {
        checkArgument(accountKey.isPubKeyOnly(), "Private subtrees not currently supported");
        checkArgument(accountKey.getPath().size() == 1, "You can only watch an account key currently");
        basicKeyChain = new BasicKeyChain();
        initializeHierarchyUnencrypted(accountKey);
    }

    /**
     * Creates a deterministic key chain that watches the given (public only) root key. You can use this to calculate
     * balances and generally follow along, but spending is not possible with such a chain. Currently you can't use
     * this method to watch an arbitrary fragment of some other tree, this limitation may be removed in future.
     */
    public static DeterministicKeyChain watch(DeterministicKey accountKey) {
        return new DeterministicKeyChain(accountKey);
    }

    DeterministicKeyChain(DeterministicSeed seed, @Nullable KeyCrypter crypter) {
        this.seed = seed;
        basicKeyChain = new BasicKeyChain(crypter);
        if (!seed.isEncrypted()) {
            rootKey = HDKeyDerivation.createMasterPrivateKey(checkNotNull(seed.getSecretBytes()));
            initializeHierarchyUnencrypted(rootKey);
        } else {
            // We can't initialize ourselves with just an encrypted seed, so we expected deserialization code to do the
            // rest of the setup (loading the root key).
        }
    }

    // For use in encryption.
    private DeterministicKeyChain(KeyCrypter crypter, KeyParameter aesKey, DeterministicKeyChain chain) {
        checkArgument(!chain.rootKey.isEncrypted(), "Chain already encrypted");

        this.issuedExternalKeys = chain.issuedExternalKeys;
        this.issuedInternalKeys = chain.issuedInternalKeys;

        this.lookaheadSize = chain.lookaheadSize;

        this.seed = chain.seed.encrypt(crypter, aesKey);
        basicKeyChain = new BasicKeyChain(crypter);
        // The first number is the "account number" but we don't use that feature.
        rootKey = chain.rootKey.encrypt(crypter, aesKey, null);
        hierarchy = new DeterministicHierarchy(rootKey);
        basicKeyChain.importKey(rootKey);

        DeterministicKey account = encryptNonLeaf(aesKey, chain, rootKey, ACCOUNT_ZERO_PATH);
        externalKey = encryptNonLeaf(aesKey, chain, account, EXTERNAL_PATH);
        internalKey = encryptNonLeaf(aesKey, chain, account, INTERNAL_PATH);

        // Now copy the (pubkey only) leaf keys across to avoid rederiving them. The private key bytes are missing
        // anyway so there's nothing to encrypt.
        for (ECKey eckey : chain.basicKeyChain.getKeys()) {
            DeterministicKey key = (DeterministicKey) eckey;
            if (key.getPath().size() != 3) continue; // Not a leaf key.
            DeterministicKey parent = hierarchy.get(checkNotNull(key.getParent()).getPath(), false, false);
            // Clone the key to the new encrypted hierarchy.
            key = new DeterministicKey(key.getPubOnly(), parent);
            hierarchy.putKey(key);
            basicKeyChain.importKey(key);
        }
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
        if (baseKey.getPath().isEmpty()) {
            // baseKey is a master/root key derived directly from a seed.
            addToBasicChain(rootKey);
            hierarchy = new DeterministicHierarchy(rootKey);
            addToBasicChain(hierarchy.get(ACCOUNT_ZERO_PATH, false, true));
        } else if (baseKey.getPath().size() == 1) {
            // baseKey is a "watching key" that we were given so we could follow along with this account.
            rootKey = null;
            addToBasicChain(baseKey);
            hierarchy = new DeterministicHierarchy(baseKey);
        } else {
            throw new IllegalArgumentException();
        }
        externalKey = hierarchy.deriveChild(ACCOUNT_ZERO_PATH, false, false, ChildNumber.ZERO);
        internalKey = hierarchy.deriveChild(ACCOUNT_ZERO_PATH, false, false, ChildNumber.ONE);
        addToBasicChain(externalKey);
        addToBasicChain(internalKey);
    }

    /** Returns a freshly derived key that has not been returned by this method before. */
    @Override
    public DeterministicKey getKey(KeyPurpose purpose) {
        lock.lock();
        try {
            DeterministicKey key, parentKey;
            int index;
            if (purpose == KeyPurpose.RECEIVE_FUNDS) {
                index = ++issuedExternalKeys;
                parentKey = externalKey;
            } else if (purpose == KeyPurpose.CHANGE) {
                index = ++issuedInternalKeys;
                parentKey = internalKey;
            } else {
                throw new IllegalArgumentException("Unknown key purpose " + purpose);
            }
            // TODO: Handle the case where the derived key is >= curve order.
            List<DeterministicKey> lookahead = maybeLookAhead(parentKey, index);
            basicKeyChain.importKeys(lookahead);
            key = hierarchy.get(HDUtils.append(parentKey.getPath(), new ChildNumber(index - 1, false)), false, false);
            return key;
        } finally {
            lock.unlock();
        }
    }

    private void addToBasicChain(DeterministicKey key) {
        basicKeyChain.importKeys(ImmutableList.of(key));
    }

    @Override
    public DeterministicKey findKeyFromPubHash(byte[] pubkeyHash) {
        lock.lock();
        try {
            return (DeterministicKey) basicKeyChain.findKeyFromPubHash(pubkeyHash);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public DeterministicKey findKeyFromPubKey(byte[] pubkey) {
        lock.lock();
        try {
            return (DeterministicKey) basicKeyChain.findKeyFromPubKey(pubkey);
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
        return getKeyByPath(ImmutableList.<ChildNumber>copyOf(path));
    }

    /** Returns the deterministic key for the given absolute path in the hierarchy. */
    protected DeterministicKey getKeyByPath(ImmutableList<ChildNumber> path) {
        return hierarchy.get(path, false, false);
    }

    /**
     * <p>An alias for <code>getKeyByPath(DeterministicKeyChain.ACCOUNT_ZERO_PATH).getPubOnly()</code>.
     * Use this when you would like to create a watching key chain that follows this one, but can't spend money from it.
     * The returned key can be serialized and then passed into {@link #watch(com.google.bitcoin.crypto.DeterministicKey)}
     * on another system to watch the hierarchy.</p>
     */
    public DeterministicKey getWatchingKey() {
        return getKeyByPath(ACCOUNT_ZERO_PATH).getPubOnly();
    }

    @Override
    public int numKeys() {
        // We need to return here the total number of keys including the lookahead zone, not the number of keys we
        // have issued via getKey/freshReceiveKey.
        return basicKeyChain.numKeys();
    }

    @Override
    public long getEarliestKeyCreationTime() {
        return seed.getCreationTimeSeconds();
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

    /** Returns a list of words that represent the seed. */
    public List<String> toMnemonicCode() {
        lock.lock();
        try {
            return seed.toMnemonicCode();
        } finally {
            lock.unlock();
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Serialization support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public List<Protos.Key> serializeToProtobuf() {
        lock.lock();
        try {
            // Most of the serialization work is delegated to the basic key chain, which will serialize the bulk of the
            // data (handling encryption along the way), and letting us patch it up with the extra data we care about.
            LinkedList<Protos.Key> entries = newLinkedList();
            if (seed != null) {
                Protos.Key.Builder seedEntry = BasicKeyChain.serializeEncryptableItem(seed);
                seedEntry.setType(Protos.Key.Type.DETERMINISTIC_ROOT_SEED);
                entries.add(seedEntry.build());
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
                if (key.equals(externalKey)) {
                    detKey.setIssuedSubkeys(issuedExternalKeys);
                    detKey.setLookaheadSize(lookaheadSize);
                } else if (key.equals(internalKey)) {
                    detKey.setIssuedSubkeys(issuedInternalKeys);
                    detKey.setLookaheadSize(lookaheadSize);
                }
                entries.add(proto.build());
            }
            return entries;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns all the key chains found in the given list of keys. Typically there will only be one, but in the case of
     * key rotation it can happen that there are multiple chains found.
     */
    public static List<DeterministicKeyChain> fromProtobuf(List<Protos.Key> keys, @Nullable KeyCrypter crypter) throws UnreadableWalletException {
        List<DeterministicKeyChain> chains = newLinkedList();
        DeterministicSeed seed = null;
        DeterministicKeyChain chain = null;
        int lookaheadSize = -1;
        for (Protos.Key key : keys) {
            final Protos.Key.Type t = key.getType();
            if (t == Protos.Key.Type.DETERMINISTIC_ROOT_SEED) {
                if (chain != null) {
                    checkState(lookaheadSize >= 0);
                    chain.setLookaheadSize(lookaheadSize);
                    chain.maybeLookAhead();
                    chains.add(chain);
                    chain = null;
                }
                long timestamp = key.getCreationTimestamp() / 1000;
                if (key.hasSecretBytes()) {
                    seed = new DeterministicSeed(key.getSecretBytes().toByteArray(), timestamp);
                } else if (key.hasEncryptedData()) {
                    EncryptedData data = new EncryptedData(key.getEncryptedData().getInitialisationVector().toByteArray(),
                            key.getEncryptedData().getEncryptedPrivateKey().toByteArray());
                    seed = new DeterministicSeed(data, timestamp);
                } else {
                    throw new UnreadableWalletException("Malformed key proto: " + key.toString());
                }
                if (log.isDebugEnabled())
                    log.debug("Deserializing: DETERMINISTIC_ROOT_SEED: {}", seed);
            } else if (t == Protos.Key.Type.DETERMINISTIC_KEY) {
                if (!key.hasDeterministicKey())
                    throw new UnreadableWalletException("Deterministic key missing extra data: " + key.toString());
                byte[] chainCode = key.getDeterministicKey().getChainCode().toByteArray();
                // Deserialize the path through the tree.
                LinkedList<ChildNumber> path = newLinkedList();
                for (int i : key.getDeterministicKey().getPathList())
                    path.add(new ChildNumber(i));
                // Deserialize the public key and path.
                ECPoint pubkey = ECKey.CURVE.getCurve().decodePoint(key.getPublicKey().toByteArray());
                final ImmutableList<ChildNumber> immutablePath = ImmutableList.copyOf(path);
                // Possibly create the chain, if we didn't already do so yet.
                boolean isWatchingAccountKey = false;
                if (chain == null) {
                    if (seed == null) {
                        DeterministicKey accountKey = new DeterministicKey(immutablePath, chainCode, pubkey, null, null);
                        if (!accountKey.getPath().equals(ACCOUNT_ZERO_PATH))
                            throw new UnreadableWalletException("Expecting account key but found key with path: " +
                                    HDUtils.formatPath(accountKey.getPath()));
                        chain = DeterministicKeyChain.watch(accountKey);
                        isWatchingAccountKey = true;
                    } else {
                        chain = new DeterministicKeyChain(seed, crypter);
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
                if (log.isDebugEnabled())
                    log.debug("Deserializing: DETERMINISTIC_KEY: {}", detkey);
                if (!isWatchingAccountKey) {
                    // If the non-encrypted case, the non-leaf keys (account, internal, external) have already been
                    // rederived and inserted at this point and the two lines below are just a no-op. In the encrypted
                    // case though, we can't rederive and we must reinsert, potentially building the heirarchy object
                    // if need be.
                    if (path.size() == 0) {
                        // Master key.
                        chain.rootKey = detkey;
                        chain.hierarchy = new DeterministicHierarchy(detkey);
                    } else if (path.size() == 2) {
                        if (detkey.getChildNumber().num() == 0) {
                            chain.externalKey = detkey;
                            chain.issuedExternalKeys = key.getDeterministicKey().getIssuedSubkeys();
                            lookaheadSize = Math.max(lookaheadSize, key.getDeterministicKey().getLookaheadSize());
                        } else if (detkey.getChildNumber().num() == 1) {
                            chain.internalKey = detkey;
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
        checkState(seed.isEncrypted());
        DeterministicSeed decSeed = seed.decrypt(getKeyCrypter(), aesKey);
        DeterministicKeyChain chain = new DeterministicKeyChain(decSeed);
        chain.lookaheadSize = lookaheadSize;
        // Now copy the (pubkey only) leaf keys across to avoid rederiving them. The private key bytes are missing
        // anyway so there's nothing to decrypt.
        for (ECKey eckey : basicKeyChain.getKeys()) {
            DeterministicKey key = (DeterministicKey) eckey;
            if (key.getPath().size() != 3) continue; // Not a leaf key.
            checkState(key.isEncrypted());
            DeterministicKey parent = chain.hierarchy.get(checkNotNull(key.getParent()).getPath(), false, false);
            // Clone the key to the new decrypted hierarchy.
            key = new DeterministicKey(key.getPubOnly(), parent);
            chain.hierarchy.putKey(key);
            chain.basicKeyChain.importKey(key);
        }
        chain.issuedExternalKeys = issuedExternalKeys;
        chain.issuedInternalKeys = issuedInternalKeys;
        return chain;
    }

    @Override
    public boolean checkPassword(CharSequence password) {
        checkNotNull(password);
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        return checkAESKey(getKeyCrypter().deriveKey(password));
    }

    @Override
    public boolean checkAESKey(KeyParameter aesKey) {
        checkNotNull(aesKey);
        checkState(getKeyCrypter() != null, "Key chain not encrypted");
        try {
            return rootKey.decrypt(getKeyCrypter(), aesKey).getPubKeyPoint().equals(rootKey.getPubKeyPoint());
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
        checkArgument(size >= numBloomFilterEntries());
        return basicKeyChain.getFilter(size, falsePositiveRate, tweak);
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
     * to sync the chain, if you want to modify it.
     */
    public void setLookaheadSize(int lookaheadSize) {
        lock.lock();
        try {
            this.lookaheadSize = lookaheadSize;
        } finally {
            lock.unlock();
        }
    }

    // Pre-generate enough keys to reach the lookahead size.
    private void maybeLookAhead() {
        lock.lock();
        try {
            List<DeterministicKey> keys = maybeLookAhead(externalKey, issuedExternalKeys);
            keys.addAll(maybeLookAhead(internalKey, issuedInternalKeys));
            // Batch add all keys at once so there's only one event listener invocation, as this will be listened to
            // by the wallet and used to rebuild/broadcast the Bloom filter. That's expensive so we don't want to do
            // it more often than necessary.
            basicKeyChain.importKeys(keys);
        } finally {
            lock.unlock();
        }
    }

    // Returned keys must be inserted into the basic key chain.
    private List<DeterministicKey> maybeLookAhead(DeterministicKey parent, int issued) {
        checkState(lock.isHeldByCurrentThread());
        final int numChildren = hierarchy.getNumChildren(parent.getPath());
        int needed = issued + getLookaheadSize() - numChildren;
        checkState(needed >= 0, "needed = " + needed);
        List<DeterministicKey> result  = new ArrayList<DeterministicKey>(needed);
        if (needed == 0) return result;
        long now = System.currentTimeMillis();
        log.info("Pre-generating {} keys for {}", needed, parent.getPathAsString());
        for (int i = 0; i < needed; i++) {
            // TODO: Handle the case where the derived key is >= curve order.
            DeterministicKey key = HDKeyDerivation.deriveChildKey(parent, numChildren + i);
            key = key.getPubOnly();
            hierarchy.putKey(key);
            result.add(key);
        }
        log.info("Took {} msec", System.currentTimeMillis() - now);
        return result;
    }

    /** Returns the seed or null if this chain is encrypted or watching. */
    @Nullable
    public DeterministicSeed getSeed() {
        lock.lock();
        try {
            return seed;
        } finally {
            lock.unlock();
        }
    }

    // For internal usage only (for printing keys in KeyChainGroup).
    /* package */ List<ECKey> getKeys() {
        return basicKeyChain.getKeys();
    }
}
