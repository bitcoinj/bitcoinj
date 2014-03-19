/**
 * Copyright 2014 Mike Hearn
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
import com.google.bitcoin.core.PeerFilterProvider;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.store.UnreadableWalletException;
import com.google.bitcoin.utils.ListenerRegistration;
import com.google.bitcoin.utils.Threading;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.bitcoinj.wallet.Protos;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executor;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A KeyChainGroup is used by the {@link com.google.bitcoin.core.Wallet} and
 * manages: zero or one {@link com.google.bitcoin.wallet.BasicKeyChain} objects, and one or more
 * {@link com.google.bitcoin.wallet.DeterministicKeyChain}s, depending on the following criteria:</p>
 *
 * <ul>
 *     <li>A pre-HD wallet contains a single bag of arbitrary, unrelated keys. They will be managed by the
 *     BasicKeyChain</li>
 *     <li>A wallet that was upgraded during the transition from basic to HD will have a BasicKeyChain and one
 *     DeterministicKeyChain, with the seed being initialized from the earliest non-rotating key in the basic chain.</li>
 *     <li>A wallet created post-HD support will not have any BasicKeyChain unless a key is imported. It will have
 *     at least one DeterministicKeyChain.</li>
 *     <li>If a key rotation time is set, it may be necessary to add a new DeterministicKeyChain with a fresh seed
 *     and also preserve the old one, so funds can be swept from the rotating keys. In this case, there may be
 *     more than one deterministic chain. The latest chain is called the active chain and is where new keys are served
 *     from.</li>
 * </ul>
 *
 * <p>The wallet delegates most key management tasks to this class. It is <b>not</b> thread safe and requires external
 * locking, i.e. by the wallet lock. The group then in turn delegates most operations to the key chain objects,
 * combining their responses together when necessary.</p>
 */
public class KeyChainGroup implements PeerFilterProvider {
    @Nullable private BasicKeyChain basic;
    private final List<DeterministicKeyChain> chains;
    private final EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys;
    @Nullable private KeyCrypter keyCrypter;
    // We keep track of added listeners so that we can attach them to new chains as they are created.
    private List<ListenerRegistration<KeyChainEventListener>> listeners;

    /** Creates a keychain group with no basic chain, and a single randomly initialized HD chain. */
    public KeyChainGroup() {
        this(null, new ArrayList<DeterministicKeyChain>(1), null);
        createAndActivateNewHDChain();
    }

    // Used for deserialization.
    private KeyChainGroup(@Nullable BasicKeyChain basicKeyChain, List<DeterministicKeyChain> chains, @Nullable KeyCrypter crypter) {
        this.basic = basicKeyChain;
        this.chains = checkNotNull(chains);
        this.keyCrypter = crypter;
        this.currentKeys = new EnumMap<KeyChain.KeyPurpose, DeterministicKey>(KeyChain.KeyPurpose.class);
        this.listeners = new ArrayList<ListenerRegistration<KeyChainEventListener>>(1);
    }

    private void createAndActivateNewHDChain() {
        final DeterministicKeyChain chain = new DeterministicKeyChain(new SecureRandom());
        chains.add(chain);
    }

    /**
     * Returns a key that hasn't been seen in a transaction yet, and which is suitable for displaying in a wallet
     * user interface as "a convenient key to receive funds on" when the purpose parameter is
     * {@link com.google.bitcoin.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS}. The returned key is stable until
     * it's actually seen in a pending or confirmed transaction, at which point this method will start returning
     * a different key (for each purpose independently).
     */
    public ECKey currentKey(KeyChain.KeyPurpose purpose) {
        final DeterministicKey current = currentKeys.get(purpose);
        return current != null ? current  : freshKey(purpose);
    }

    /**
     * Returns a key that has not been returned by this method before (fresh). You can think of this as being
     * a newly created key, although the notion of "create" is not really valid for a
     * {@link com.google.bitcoin.wallet.DeterministicKeyChain}. When the parameter is
     * {@link com.google.bitcoin.wallet.KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key out
     * to someone who wishes to send money.
     */
    public ECKey freshKey(KeyChain.KeyPurpose purpose) {
        DeterministicKeyChain chain = getActiveKeyChain();
        DeterministicKey key = chain.getKey(purpose);   // Always returns the next key along the key chain.
        currentKeys.put(purpose, key);
        return key;
    }

    /** Returns the key chain that's used for generation of fresh/current keys. This is always the newest HD chain. */
    public DeterministicKeyChain getActiveKeyChain() {
        checkState(!chains.isEmpty());   // We should never arrive here without being properly initialized.
        return chains.get(chains.size() - 1);
    }

    /**
     * Sets the lookahead buffer size for ALL deterministic key chains, see {@link com.google.bitcoin.wallet.DeterministicKeyChain#setLookaheadSize(int)}
     * for more information.
     */
    public void setLookaheadSize(int lookaheadSize) {
        checkState(!chains.isEmpty());
        for (DeterministicKeyChain chain : chains) {
            chain.setLookaheadSize(lookaheadSize);
        }
    }

    /** Imports the given keys into the basic chain, creating it if necessary. */
    public int importKeys(List<ECKey> keys) {
        return obtainBasic().importKeys(keys);
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
        if (basic != null && basic.numKeys() > 0)
            return basic.checkAESKey(aesKey);
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

    /** Returns true if this group has a basic key chain. By default it's false for a newly created group. */
    public boolean hasBasicChain() {
        return basic != null;
    }

    private BasicKeyChain obtainBasic() {
        if (basic != null) return basic;
        basic = new BasicKeyChain();
        for (ListenerRegistration<KeyChainEventListener> registration : listeners)
            basic.addEventListener(registration.listener, registration.executor);
        return basic;
    }

    @Nullable
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        ECKey result;
        if (basic != null && (result = basic.findKeyFromPubHash(pubkeyHash)) != null)
            return result;
        for (DeterministicKeyChain chain : chains) {
            if ((result = chain.findKeyFromPubHash(pubkeyHash)) != null)
                return result;
        }
        return null;
    }

    public boolean hasKey(ECKey key) {
        if (basic != null && basic.hasKey(key))
            return true;
        for (DeterministicKeyChain chain : chains)
            if (chain.hasKey(key))
                return true;
        return false;
    }

    @Nullable
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        ECKey result;
        if (basic != null && (result = basic.findKeyFromPubKey(pubkey)) != null)
            return result;
        for (DeterministicKeyChain chain : chains) {
            if ((result = chain.findKeyFromPubKey(pubkey)) != null)
                return result;
        }
        return null;
    }

    /** Returns the number of keys managed by this group, including the lookahead buffers. */
    public int numKeys() {
        int result = 0;
        if (basic != null)
            result += basic.numKeys();
        for (DeterministicKeyChain chain : chains)
            result += chain.numKeys();
        return result;
    }

    /**
     * Removes a key that was imported into the basic key chain. You cannot remove deterministic keys.
     * @throws java.lang.IllegalArgumentException if the key is deterministic.
     * @throws java.lang.IllegalStateException if there is no basic chain.
     */
    public boolean removeImportedKey(ECKey key) {
        checkNotNull(key);
        checkState(basic != null);
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
        BasicKeyChain newBasic = null;
        if (basic != null)
            newBasic = basic.toEncrypted(keyCrypter, aesKey);
        List<DeterministicKeyChain> newChains = new ArrayList<DeterministicKeyChain>(chains.size());
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
        BasicKeyChain newBasic = null;
        if (basic != null)
            newBasic = basic.toDecrypted(aesKey);
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

    /** {@inheritDoc} */
    @Override
    public long getEarliestKeyCreationTime() {
        long time;
        if (basic != null)
            time = basic.getEarliestKeyCreationTime();
        else
            time = Long.MAX_VALUE;
        for (DeterministicKeyChain chain : chains)
            time = Math.min(time, chain.getEarliestKeyCreationTime());
        return time;
    }

    /** {@inheritDoc} */
    public int getBloomFilterElementCount() {
        int result = 0;
        if (basic != null)
            result += basic.numBloomFilterEntries();
        for (DeterministicKeyChain chain : chains)
            result += chain.numBloomFilterEntries();
        return result;
    }

    /** {@inheritDoc} */
    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
        BloomFilter filter = new BloomFilter(size, falsePositiveRate, nTweak);
        if (basic != null)
            filter.merge(basic.getFilter(size, falsePositiveRate, nTweak));
        for (DeterministicKeyChain chain : chains) {
            filter.merge(chain.getFilter(size, falsePositiveRate, nTweak));
        }
        return filter;
    }

    /** {@inheritDoc} */
    @Override
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
        if (basic != null)
            basic.addEventListener(listener, executor);
        for (DeterministicKeyChain chain : chains)
            chain.addEventListener(listener, executor);
        listeners.add(new ListenerRegistration<KeyChainEventListener>(listener, executor));
    }

    /** Removes a listener for events that are run when keys are added. */
    public boolean removeEventListener(KeyChainEventListener listener) {
        checkNotNull(listener);
        if (basic != null)
            basic.removeEventListener(listener);
        for (DeterministicKeyChain chain : chains)
            chain.removeEventListener(listener);
        return ListenerRegistration.removeFromList(listener, listeners);
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
        if (basicKeyChain.numKeys() == 0)
            basicKeyChain = null;
        if (chains.isEmpty()) {
            // Old bag-of-keys style wallet only! Auto-upgrade time!
            throw new UnsupportedOperationException("FIXME");
        }
        return new KeyChainGroup(basicKeyChain, chains, null);
    }

    public static KeyChainGroup fromProtobufEncrypted(List<Protos.Key> keys, KeyCrypter crypter) throws UnreadableWalletException {
        checkNotNull(crypter);
        BasicKeyChain basicKeyChain = BasicKeyChain.fromProtobufEncrypted(keys, crypter);
        List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(keys, crypter);
        if (basicKeyChain.numKeys() == 0)
            basicKeyChain = null;
        if (chains.isEmpty()) {
            // Old bag-of-keys style wallet only! Auto-upgrade time!
            throw new UnsupportedOperationException("FIXME");
        }
        return new KeyChainGroup(basicKeyChain, chains, crypter);
    }
}
