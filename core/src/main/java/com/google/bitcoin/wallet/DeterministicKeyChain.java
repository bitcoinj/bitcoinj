/**
 * Copyright 2013 Google Inc.
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
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.security.SecureRandom;
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
    private WeakReference<MnemonicCode> mnemonicCode;

    // Paths through the key tree. External keys are ones that are communicated to other parties. Internal keys are
    // keys created for change addresses, coinbases, mixing, etc - anything that isn't communicated. The distinction
    // is somewhat arbitrary but can be useful for audits. The first number is the "account number" but we don't use
    // that feature.
    public static final ImmutableList<ChildNumber> ACCOUNT_ZERO_PATH = ImmutableList.of(ChildNumber.ZERO_PRIV);
    public static final ImmutableList<ChildNumber> EXTERNAL_PATH = ImmutableList.of(ChildNumber.ZERO_PRIV, ChildNumber.ZERO);
    public static final ImmutableList<ChildNumber> INTERNAL_PATH = ImmutableList.of(ChildNumber.ZERO_PRIV, new ChildNumber(1, false));

    private DeterministicKey externalKey, internalKey;
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

    /** Returns the time in seconds since the UNIX epoch at which the seed was randomly generated. */
    public long getSeedCreationTimeSecs() {
        return seed.getCreationTimeSeconds();
    }

    @Override
    public DeterministicKey getKey(KeyPurpose purpose) {
        lock.lock();
        try {
            DeterministicKey key;
            if (purpose == KeyPurpose.RECEIVE_FUNDS) {
                key = HDKeyDerivation.deriveChildKey(externalKey, issuedExternalKeys);
                issuedExternalKeys++;
            } else if (purpose == KeyPurpose.CHANGE) {
                key = HDKeyDerivation.deriveChildKey(internalKey, issuedInternalKeys);
                issuedInternalKeys++;
            } else {
                throw new IllegalArgumentException("Unknown key purpose " + purpose);
            }
            hierarchy.putKey(key);
            basicKeyChain.importKey(key);
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
    public DeterministicKey getKeyByPath(ChildNumber... path) {
        return getKeyByPath(ImmutableList.<ChildNumber>copyOf(path));
    }

    /** Returns the deterministic key for the given absolute path in the hierarchy. */
    public DeterministicKey getKeyByPath(ImmutableList<ChildNumber> path) {
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

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Mnemonic code support
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /** Returns a list of words that represent the seed. */
    public List<String> toMnemonicCode() {
        try {
            return toMnemonicCode(getCachedMnemonicCode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns a list of words that represent the seed, or IllegalStateException if the seed is encrypted or missing. */
    public List<String> toMnemonicCode(MnemonicCode code) {
        try {
            if (seed == null)
                throw new IllegalStateException("The seed is not present in this key chain");
            if (seed.isEncrypted())
                throw new IllegalStateException("The seed is encrypted");
            final byte[] seed = checkNotNull(this.seed.getSecretBytes());
            return code.toMnemonic(seed);
        } catch (MnemonicException.MnemonicLengthException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    private MnemonicCode getCachedMnemonicCode() throws IOException {
        lock.lock();
        try {
            // This object can be large and has to load the word list from disk, so we lazy cache it.
            MnemonicCode m = mnemonicCode != null ? mnemonicCode.get() : null;
            if (m == null) {
                m = new MnemonicCode();
                mnemonicCode = new WeakReference<MnemonicCode>(m);
            }
            return m;
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
    public static List<DeterministicKeyChain> parseFrom(List<Protos.Key> keys, @Nullable KeyCrypter crypter) throws UnreadableWalletException {
        List<DeterministicKeyChain> chains = newLinkedList();
        DeterministicSeed seed = null;
        DeterministicKeyChain chain = null;
        for (Protos.Key key : keys) {
            final Protos.Key.Type t = key.getType();
            if (t == Protos.Key.Type.DETERMINISTIC_ROOT_SEED) {
                if (chain != null) {
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
                log.info("Deserializing: DETERMINISTIC_ROOT_SEED: {}", seed);
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
                log.info("Deserializing: DETERMINISTIC_KEY: {}", detkey);
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
                        if (detkey.getChildNumber().num() == 0)
                            chain.externalKey = detkey;
                        else if (detkey.getChildNumber().num() == 1)
                            chain.internalKey = detkey;
                    }
                }
                chain.hierarchy.putKey(detkey);
                chain.basicKeyChain.importKey(detkey);
                if (parent != null) {
                    if (parent.equals(chain.internalKey))
                        chain.issuedInternalKeys++;
                    else if (parent.equals(chain.externalKey))
                        chain.issuedExternalKeys++;
                }
            }
        }
        if (chain != null)
            chains.add(chain);
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
        // Now copy the (pubkey only) leaf keys across to avoid rederiving them. The private key bytes are missing
        // anyway so there's nothing to encrypt.
        for (ECKey eckey : basicKeyChain.getKeys()) {
            DeterministicKey key = (DeterministicKey) eckey;
            if (key.getPath().size() != 3) continue; // Not a leaf key.
            checkState(key.isEncrypted());
            DeterministicKey parent = chain.hierarchy.get(checkNotNull(key.getParent()).getPath(), false, false);
            // Clone the key to the new encrypted hierarchy.
            key = new DeterministicKey(key.getPubOnly(), parent);
            chain.hierarchy.putKey(key);
            chain.basicKeyChain.importKey(key);
        }
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
}
