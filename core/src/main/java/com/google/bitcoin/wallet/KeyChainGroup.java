/**
 * Copyright 2014 Mike Hearn
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

package com.google.bitcoin.wallet;

import com.google.bitcoin.core.*;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.store.UnreadableWalletException;
import com.google.bitcoin.utils.ListenerRegistration;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.bitcoinj.wallet.Protos;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Executor;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A KeyChainGroup is used by the {@link com.google.bitcoin.core.Wallet} and
 * manages: a {@link com.google.bitcoin.wallet.BasicKeyChain} object (which will normally be empty), and zero or more
 * {@link com.google.bitcoin.wallet.DeterministicKeyChain}s. A deterministic key chain will be created lazily/on demand
 * when a fresh or current key is requested, possibly being initialized from the private key bytes of the earliest non
 * rotating key in the basic key chain if one is available, or from a fresh random seed if not.</p>
 *
 * <p>If a key rotation time is set, it may be necessary to add a new DeterministicKeyChain with a fresh seed
 * and also preserve the old one, so funds can be swept from the rotating keys. In this case, there may be
 * more than one deterministic chain. The latest chain is called the active chain and is where new keys are served
 * from.</p>
 *
 * <p>The wallet delegates most key management tasks to this class. It is <b>not</b> thread safe and requires external
 * locking, i.e. by the wallet lock. The group then in turn delegates most operations to the key chain objects,
 * combining their responses together when necessary.</p>
 */
public class KeyChainGroup {
    private BasicKeyChain basic;
    private final List<DeterministicKeyChain> chains;
    private final EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys;
    @Nullable private KeyCrypter keyCrypter;
    private int lookaheadSize = -1;
    private int lookaheadThreshold = -1;

    /** Creates a keychain group with no basic chain, and a single randomly initialized HD chain. */
    public KeyChainGroup() {
        this(null, new ArrayList<DeterministicKeyChain>(1), null);
    }

    /** Creates a keychain group with no basic chain, and an HD chain initialized from the given seed. */
    public KeyChainGroup(DeterministicSeed seed) {
        this(null, ImmutableList.of(new DeterministicKeyChain(seed)), null);
    }

    /**
     * Creates a keychain group with no basic chain, and an HD chain that is watching the given watching key.
     * This HAS to be an account key as returned by {@link DeterministicKeyChain#getWatchingKey()}.
     */
    public KeyChainGroup(DeterministicKey watchKey) {
        this(null, ImmutableList.of(DeterministicKeyChain.watch(watchKey)), null);
    }

    /**
     * Creates a keychain group with no basic chain, and an HD chain that is watching the given watching key which
     * was assumed to be first used at the given UNIX time.
     * This HAS to be an account key as returned by {@link DeterministicKeyChain#getWatchingKey()}.
     */
    public KeyChainGroup(DeterministicKey watchKey, long creationTimeSecondsSecs) {
        this(null, ImmutableList.of(DeterministicKeyChain.watch(watchKey, creationTimeSecondsSecs)), null);
    }

    // Used for deserialization.
    private KeyChainGroup(@Nullable BasicKeyChain basicKeyChain, List<DeterministicKeyChain> chains, @Nullable KeyCrypter crypter) {
        this.basic = basicKeyChain == null ? new BasicKeyChain() : basicKeyChain;
        this.chains = new ArrayList<DeterministicKeyChain>(checkNotNull(chains));
        this.keyCrypter = crypter;
        this.currentKeys = new EnumMap<KeyChain.KeyPurpose, DeterministicKey>(KeyChain.KeyPurpose.class);
    }

    private void createAndActivateNewHDChain() {
        final DeterministicKeyChain chain = new DeterministicKeyChain(new SecureRandom());
        for (ListenerRegistration<KeyChainEventListener> registration : basic.getListeners())
            chain.addEventListener(registration.listener, registration.executor);
        if (lookaheadSize >= 0)
            chain.setLookaheadSize(lookaheadSize);
        if (lookaheadThreshold >= 0)
            chain.setLookaheadThreshold(lookaheadThreshold);
        chains.add(chain);
    }

    /**
     * Returns a key that hasn't been seen in a transaction yet, and which is suitable for displaying in a wallet
     * user interface as "a convenient key to receive funds on" when the purpose parameter is
     * {@link com.google.bitcoin.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS}. The returned key is stable until
     * it's actually seen in a pending or confirmed transaction, at which point this method will start returning
     * a different key (for each purpose independently).
     */
    public DeterministicKey currentKey(KeyChain.KeyPurpose purpose) {
        final DeterministicKey current = currentKeys.get(purpose);
        return current != null ? current  : freshKey(purpose);
    }

    /**
     * Returns address for a {@link #currentKey(com.google.bitcoin.wallet.KeyChain.KeyPurpose)}
     */
    public Address currentAddress(KeyChain.KeyPurpose purpose, NetworkParameters params) {
        return currentKey(purpose).toAddress(params);
    }

    /**
     * Returns a key that has not been returned by this method before (fresh). You can think of this as being
     * a newly created key, although the notion of "create" is not really valid for a
     * {@link com.google.bitcoin.wallet.DeterministicKeyChain}. When the parameter is
     * {@link com.google.bitcoin.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key out
     * to someone who wishes to send money.
     */
    public DeterministicKey freshKey(KeyChain.KeyPurpose purpose) {
        return freshKeys(purpose,1).get(0);
    }

    /**
     * Returns a key/s that have not been returned by this method before (fresh). You can think of this as being
     * newly created key/s, although the notion of "create" is not really valid for a
     * {@link com.google.bitcoin.wallet.DeterministicKeyChain}. When the parameter is
     * {@link com.google.bitcoin.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key out
     * to someone who wishes to send money.
     */
    public List<DeterministicKey> freshKeys(KeyChain.KeyPurpose purpose, int numberOfKeys) {
        DeterministicKeyChain chain = getActiveKeyChain();
        List<DeterministicKey> keys = chain.getKeys(purpose, numberOfKeys);   // Always returns the next key along the key chain.
        currentKeys.put(purpose, keys.get(keys.size() - 1));
        return keys;
    }

    /**
     * Returns address for a {@link #freshKey(com.google.bitcoin.wallet.KeyChain.KeyPurpose)}
     */
    public Address freshAddress(KeyChain.KeyPurpose purpose, NetworkParameters params) {
        return freshKey(purpose).toAddress(params);
    }

    /** Returns the key chain that's used for generation of fresh/current keys. This is always the newest HD chain. */
    public DeterministicKeyChain getActiveKeyChain() {
        if (chains.isEmpty())
            createAndActivateNewHDChain();
        return chains.get(chains.size() - 1);
    }

    /**
     * Sets the lookahead buffer size for ALL deterministic key chains, see
     * {@link com.google.bitcoin.wallet.DeterministicKeyChain#setLookaheadSize(int)}
     * for more information.
     */
    public void setLookaheadSize(int lookaheadSize) {
        this.lookaheadSize = lookaheadSize;
        for (DeterministicKeyChain chain : chains) {
            chain.setLookaheadSize(lookaheadSize);
        }
    }

    /**
     * Gets the current lookahead size being used for ALL deterministic key chains. See
     * {@link com.google.bitcoin.wallet.DeterministicKeyChain#setLookaheadSize(int)}
     * for more information.
     */
    public int getLookaheadSize() {
        return lookaheadSize;
    }

    /**
     * Sets the lookahead buffer threshold for ALL deterministic key chains, see
     * {@link com.google.bitcoin.wallet.DeterministicKeyChain#setLookaheadThreshold(int)}
     * for more information.
     */
    public void setLookaheadThreshold(int num) {
        for (DeterministicKeyChain chain : chains) {
            chain.setLookaheadThreshold(num);
        }
    }

    /**
     * Gets the current lookahead threshold being used for ALL deterministic key chains. See
     * {@link com.google.bitcoin.wallet.DeterministicKeyChain#setLookaheadThreshold(int)}
     * for more information.
     */
    public int getLookaheadThreshold() {
        return lookaheadThreshold;
    }

    /** Imports the given keys into the basic chain, creating it if necessary. */
    public int importKeys(List<ECKey> keys) {
        return basic.importKeys(keys);
    }

    /** Imports the given keys into the basic chain, creating it if necessary. */
    public int importKeys(ECKey... keys) {
        return importKeys(ImmutableList.copyOf(keys));
    }

    public boolean checkPassword(CharSequence password) {
        checkState(keyCrypter != null, "Not encrypted");
        return checkAESKey(keyCrypter.deriveKey(password));
    }

    public boolean checkAESKey(KeyParameter aesKey) {
        checkState(keyCrypter != null, "Not encrypted");
        if (basic.numKeys() > 0)
            return basic.checkAESKey(aesKey) && getActiveKeyChain().checkAESKey(aesKey);
        return getActiveKeyChain().checkAESKey(aesKey);
    }

    /** Imports the given unencrypted keys into the basic chain, encrypting them along the way with the given key. */
    public int importKeysAndEncrypt(final List<ECKey> keys, KeyParameter aesKey) {
        // TODO: Firstly check if the aes key can decrypt any of the existing keys successfully.
        checkState(keyCrypter != null, "Not encrypted");
        LinkedList<ECKey> encryptedKeys = Lists.newLinkedList();
        for (ECKey key : keys) {
            if (key.isEncrypted())
                throw new IllegalArgumentException("Cannot provide already encrypted keys");
            encryptedKeys.add(key.encrypt(keyCrypter, aesKey));
        }
        return importKeys(encryptedKeys);
    }

    @Nullable
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        ECKey result;
        if ((result = basic.findKeyFromPubHash(pubkeyHash)) != null)
            return result;
        for (DeterministicKeyChain chain : chains) {
            if ((result = chain.findKeyFromPubHash(pubkeyHash)) != null)
                return result;
        }
        return null;
    }

    /**
     * Mark the DeterministicKeys as used, if they match the pubkeyHash
     * See {@link com.google.bitcoin.wallet.DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    public void markPubKeyHashAsUsed(byte[] pubkeyHash) {
        for (DeterministicKeyChain chain : chains) {
            if (chain.markPubHashAsUsed(pubkeyHash))
                return;
        }
    }


    public boolean hasKey(ECKey key) {
        if (basic.hasKey(key))
            return true;
        for (DeterministicKeyChain chain : chains)
            if (chain.hasKey(key))
                return true;
        return false;
    }

    @Nullable
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        ECKey result;
        if ((result = basic.findKeyFromPubKey(pubkey)) != null)
            return result;
        for (DeterministicKeyChain chain : chains) {
            if ((result = chain.findKeyFromPubKey(pubkey)) != null)
                return result;
        }
        return null;
    }

    /**
     * Mark the DeterministicKeys as used, if they match the pubkey
     * See {@link com.google.bitcoin.wallet.DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    public void markPubKeyAsUsed(byte[] pubkey) {
        for (DeterministicKeyChain chain : chains) {
            if (chain.markPubKeyAsUsed(pubkey))
                return;
        }
    }

    /** Returns the number of keys managed by this group, including the lookahead buffers. */
    public int numKeys() {
        int result = basic.numKeys();
        for (DeterministicKeyChain chain : chains)
            result += chain.numKeys();
        return result;
    }

    /**
     * Removes a key that was imported into the basic key chain. You cannot remove deterministic keys.
     * @throws java.lang.IllegalArgumentException if the key is deterministic.
     */
    public boolean removeImportedKey(ECKey key) {
        checkNotNull(key);
        checkArgument(!(key instanceof DeterministicKey));
        return basic.removeKey(key);
    }

    /**
     * Encrypt the keys in the group using the KeyCrypter and the AES key. A good default KeyCrypter to use is
     * {@link com.google.bitcoin.crypto.KeyCrypterScrypt}.
     *
     * @throws com.google.bitcoin.crypto.KeyCrypterException Thrown if the wallet encryption fails for some reason, leaving the group unchanged.
     */
    public void encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        checkNotNull(keyCrypter);
        checkNotNull(aesKey);
        // This code must be exception safe.
        BasicKeyChain newBasic = basic.toEncrypted(keyCrypter, aesKey);
        List<DeterministicKeyChain> newChains = new ArrayList<DeterministicKeyChain>(chains.size());
        // If the user is trying to encrypt us before ever asking for a key, we might not have lazy created an HD chain
        // yet. So do it now.
        if (chains.isEmpty())
            createAndActivateNewHDChain();
        for (DeterministicKeyChain chain : chains)
            newChains.add(chain.toEncrypted(keyCrypter, aesKey));

        this.keyCrypter = keyCrypter;
        basic = newBasic;
        chains.clear();
        chains.addAll(newChains);
    }

    /**
     * Decrypt the keys in the group using the previously given key crypter and the AES key. A good default
     * KeyCrypter to use is {@link com.google.bitcoin.crypto.KeyCrypterScrypt}.
     *
     * @throws com.google.bitcoin.crypto.KeyCrypterException Thrown if the wallet decryption fails for some reason, leaving the group unchanged.
     */
    public void decrypt(KeyParameter aesKey) {
        // This code must be exception safe.
        checkNotNull(aesKey);
        BasicKeyChain newBasic = basic.toDecrypted(aesKey);
        List<DeterministicKeyChain> newChains = new ArrayList<DeterministicKeyChain>(chains.size());
        for (DeterministicKeyChain chain : chains)
            newChains.add(chain.toDecrypted(aesKey));

        this.keyCrypter = null;
        basic = newBasic;
        chains.clear();
        chains.addAll(newChains);
    }

    /** Returns true if the group is encrypted. */
    public boolean isEncrypted() {
        return keyCrypter != null;
    }

    /** Returns the key crypter or null if the group is not encrypted. */
    @Nullable public KeyCrypter getKeyCrypter() { return keyCrypter; }

    /**
     * Returns a list of the non-deterministic keys that have been imported into the wallet, or the empty list if none.
     */
    public List<ECKey> getImportedKeys() {
        return basic.getKeys();
    }

    public long getEarliestKeyCreationTime() {
        long time = basic.getEarliestKeyCreationTime();   // Long.MAX_VALUE if empty.
        for (DeterministicKeyChain chain : chains)
            time = Math.min(time, chain.getEarliestKeyCreationTime());
        return time;
    }

    public int getBloomFilterElementCount() {
        int result = basic.numBloomFilterEntries();
        for (DeterministicKeyChain chain : chains)
            result += chain.numBloomFilterEntries();
        return result;
    }

    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
        BloomFilter filter = new BloomFilter(size, falsePositiveRate, nTweak);
        if (basic.numKeys() > 0)
            filter.merge(basic.getFilter(size, falsePositiveRate, nTweak));
        for (DeterministicKeyChain chain : chains)
            filter.merge(chain.getFilter(size, falsePositiveRate, nTweak));
        return filter;
    }

    /** {@inheritDoc} */
    public boolean isRequiringUpdateAllBloomFilter() {
        throw new UnsupportedOperationException();   // Unused.
    }

    /** Adds a listener for events that are run when keys are added, on the user thread. */
    public void addEventListener(KeyChainEventListener listener) {
        addEventListener(listener, Threading.USER_THREAD);
    }

    /** Adds a listener for events that are run when keys are added, on the given executor. */
    public void addEventListener(KeyChainEventListener listener, Executor executor) {
        checkNotNull(listener);
        checkNotNull(executor);
        basic.addEventListener(listener, executor);
        for (DeterministicKeyChain chain : chains)
            chain.addEventListener(listener, executor);
    }

    /** Removes a listener for events that are run when keys are added. */
    public boolean removeEventListener(KeyChainEventListener listener) {
        checkNotNull(listener);
        for (DeterministicKeyChain chain : chains)
            chain.removeEventListener(listener);
        return basic.removeEventListener(listener);
    }

    /** Returns a list of key protobufs obtained by merging the chains. */
    public List<Protos.Key> serializeToProtobuf() {
        List<Protos.Key> result;
        if (basic != null)
            result = basic.serializeToProtobuf();
        else
            result = Lists.newArrayList();
        for (DeterministicKeyChain chain : chains) {
            List<Protos.Key> protos = chain.serializeToProtobuf();
            result.addAll(protos);
        }
        return result;
    }

    public static KeyChainGroup fromProtobufUnencrypted(List<Protos.Key> keys) throws UnreadableWalletException {
        BasicKeyChain basicKeyChain = BasicKeyChain.fromProtobufUnencrypted(keys);
        List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(keys, null);
        if (chains.isEmpty()) {
            // TODO: Old bag-of-keys style wallet only! Auto-upgrade time!
        }
        return new KeyChainGroup(basicKeyChain, chains, null);
    }

    public static KeyChainGroup fromProtobufEncrypted(List<Protos.Key> keys, KeyCrypter crypter) throws UnreadableWalletException {
        checkNotNull(crypter);
        BasicKeyChain basicKeyChain = BasicKeyChain.fromProtobufEncrypted(keys, crypter);
        List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(keys, crypter);
        if (chains.isEmpty()) {
            // TODO: Old bag-of-keys style wallet only! Auto-upgrade time!
        }
        return new KeyChainGroup(basicKeyChain, chains, crypter);
    }

    public String toString(@Nullable NetworkParameters params, boolean includePrivateKeys) {
        final StringBuilder builder = new StringBuilder();
        if (basic != null) {
            for (ECKey key : basic.getKeys())
                formatKeyWithAddress(params, includePrivateKeys, key, builder);
        }
        for (DeterministicKeyChain chain : chains) {
            DeterministicSeed seed = chain.getSeed();
            if (seed != null) {
                if (seed.isEncrypted()) {
                    builder.append(String.format("Seed is encrypted%n"));
                } else if (includePrivateKeys) {
                    final List<String> words = seed.toMnemonicCode();
                    builder.append(
                            String.format("Seed as words: %s%nSeed as hex:   %s%n", Joiner.on(' ').join(words),
                                    seed.toHexString())
                    );
                }
                builder.append(String.format("Seed birthday: %d  [%s]%n", seed.getCreationTimeSeconds(), new Date(seed.getCreationTimeSeconds() * 1000)));
            }
            final DeterministicKey watchingKey = chain.getWatchingKey();
            // Don't show if it's been imported from a watching wallet already, because it'd result in a weird/
            // unintuitive result where the watching key in a watching wallet is not the one it was created with
            // due to the parent fingerprint being missing/not stored. In future we could store the parent fingerprint
            // optionally as well to fix this, but it seems unimportant for now.
            if (watchingKey.getParent() != null) {
                builder.append(String.format("Key to watch:  %s%n%n", watchingKey.serializePubB58()));
            }
            for (ECKey key : chain.getKeys())
                formatKeyWithAddress(params, includePrivateKeys, key, builder);
        }
        return builder.toString();
    }

    private void formatKeyWithAddress(@Nullable NetworkParameters params, boolean includePrivateKeys,
                                      ECKey key, StringBuilder builder) {
        if (params != null) {
            final Address address = key.toAddress(params);
            builder.append("  addr:");
            builder.append(address.toString());
        }
        builder.append("  hash160:");
        builder.append(Utils.HEX.encode(key.getPubKeyHash()));
        builder.append(" ");
        builder.append(includePrivateKeys ? key.toStringWithPrivate() : key.toString());
        builder.append("\n");
    }
}
