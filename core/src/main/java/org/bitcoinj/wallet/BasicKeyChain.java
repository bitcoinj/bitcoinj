/*
 * Copyright 2013 Google Inc.
 * Copyright 2019 Andreas Schildbach
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
import org.bitcoinj.crypto.*;
import org.bitcoinj.utils.ListenerRegistration;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.listeners.KeyChainEventListener;

import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.*;

/**
 * A {@link KeyChain} that implements the simplest model possible: it can have keys imported into it, and just acts as
 * a dumb bag of keys. It will, left to its own devices, always return the same key for usage by the wallet, although
 * it will automatically add one to itself if it's empty or if encryption is requested.
 */
public class BasicKeyChain implements EncryptableKeyChain {
    private final ReentrantLock lock = Threading.lock(BasicKeyChain.class);

    // Maps used to let us quickly look up a key given data we find in transactions or the block chain.
    private final LinkedHashMap<ByteString, ECKey> hashToKeys;
    private final LinkedHashMap<ByteString, ECKey> pubkeyToKeys;
    @Nullable private final KeyCrypter keyCrypter;
    private boolean isWatching;

    private final CopyOnWriteArrayList<ListenerRegistration<KeyChainEventListener>> listeners;

    public BasicKeyChain() {
        this(null);
    }

    public BasicKeyChain(@Nullable KeyCrypter crypter) {
        this.keyCrypter = crypter;
        hashToKeys = new LinkedHashMap<>();
        pubkeyToKeys = new LinkedHashMap<>();
        listeners = new CopyOnWriteArrayList<>();
    }

    /** Returns the {@link KeyCrypter} in use or null if the key chain is not encrypted. */
    @Override
    @Nullable
    public KeyCrypter getKeyCrypter() {
        lock.lock();
        try {
            return keyCrypter;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public ECKey getKey(@Nullable KeyPurpose ignored) {
        lock.lock();
        try {
            if (hashToKeys.isEmpty()) {
                checkState(keyCrypter == null);   // We will refuse to encrypt an empty key chain.
                final ECKey key = new ECKey();
                importKeyLocked(key);
                queueOnKeysAdded(ImmutableList.of(key));
            }
            return hashToKeys.values().iterator().next();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<ECKey> getKeys(@Nullable KeyPurpose purpose, int numberOfKeys) {
        checkArgument(numberOfKeys > 0);
        lock.lock();
        try {
            if (hashToKeys.size() < numberOfKeys) {
                checkState(keyCrypter == null);

                List<ECKey> keys = new ArrayList<>();
                for (int i = 0; i < numberOfKeys - hashToKeys.size(); i++) {
                    keys.add(new ECKey());
                }

                ImmutableList<ECKey> immutableKeys = ImmutableList.copyOf(keys);
                importKeysLocked(immutableKeys);
                queueOnKeysAdded(immutableKeys);
            }

            List<ECKey> keysToReturn = new ArrayList<>();
            int count = 0;
            while (hashToKeys.values().iterator().hasNext() && numberOfKeys != count) {
                keysToReturn.add(hashToKeys.values().iterator().next());
                count++;
            }
            return keysToReturn;
        } finally {
            lock.unlock();
        }
    }

    /** Returns a copy of the list of keys that this chain is managing. */
    public List<ECKey> getKeys() {
        lock.lock();
        try {
            return new ArrayList<>(hashToKeys.values());
        } finally {
            lock.unlock();
        }
    }

    public int importKeys(ECKey... keys) {
        return importKeys(ImmutableList.copyOf(keys));
    }

    public int importKeys(List<? extends ECKey> keys) {
        lock.lock();
        try {
            // Check that if we're encrypted, the keys are all encrypted, and if we're not, that none are.
            // We are NOT checking that the actual password matches here because we don't have access to the password at
            // this point: if you screw up and import keys with mismatched passwords, you lose! So make sure the
            // password is checked first.
            for (ECKey key : keys) {
                checkKeyEncryptionStateMatches(key);
            }
            List<ECKey> actuallyAdded = new ArrayList<>(keys.size());
            for (final ECKey key : keys) {
                if (hasKey(key)) continue;
                actuallyAdded.add(key);
                importKeyLocked(key);
            }
            if (actuallyAdded.size() > 0)
                queueOnKeysAdded(actuallyAdded);
            return actuallyAdded.size();
        } finally {
            lock.unlock();
        }
    }

    private void checkKeyEncryptionStateMatches(ECKey key) {
        if (keyCrypter == null && key.isEncrypted())
            throw new KeyCrypterException("Key is encrypted but chain is not");
        else if (keyCrypter != null && !key.isEncrypted())
            throw new KeyCrypterException("Key is not encrypted but chain is");
        else if (keyCrypter != null && key.getKeyCrypter() != null && !key.getKeyCrypter().equals(keyCrypter))
            throw new KeyCrypterException("Key encrypted under different parameters to chain");
    }

    private void importKeyLocked(ECKey key) {
        if (hashToKeys.isEmpty()) {
            isWatching = key.isWatching();
        } else {
            if (key.isWatching() && !isWatching)
                throw new IllegalArgumentException("Key is watching but chain is not");
            if (!key.isWatching() && isWatching)
                throw new IllegalArgumentException("Key is not watching but chain is");
        }
        ECKey previousKey = pubkeyToKeys.put(ByteString.copyFrom(key.getPubKey()), key);
        hashToKeys.put(ByteString.copyFrom(key.getPubKeyHash()), key);
        checkState(previousKey == null);
    }

    private void importKeysLocked(List<ECKey> keys) {
        for (ECKey key : keys) {
            importKeyLocked(key);
        }
    }

    /**
     * Imports a key to the key chain. If key is present in the key chain, ignore it.
     */
    public void importKey(ECKey key) {
        lock.lock();
        try {
            checkKeyEncryptionStateMatches(key);
            if (hasKey(key)) return;
            importKeyLocked(key);
            queueOnKeysAdded(ImmutableList.of(key));
        } finally {
            lock.unlock();
        }
    }

    public ECKey findKeyFromPubHash(byte[] pubKeyHash) {
        lock.lock();
        try {
            return hashToKeys.get(ByteString.copyFrom(pubKeyHash));
        } finally {
            lock.unlock();
        }
    }

    public ECKey findKeyFromPubKey(byte[] pubKey) {
        lock.lock();
        try {
            return pubkeyToKeys.get(ByteString.copyFrom(pubKey));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean hasKey(ECKey key) {
        return findKeyFromPubKey(key.getPubKey()) != null;
    }

    @Override
    public int numKeys() {
        return pubkeyToKeys.size();
    }

    /** Whether this basic key chain is empty, full of regular (usable for signing) keys, or full of watching keys. */
    public enum State {
        EMPTY,
        WATCHING,
        REGULAR
    }

    /**
     * Returns whether this chain consists of pubkey only (watching) keys, regular keys (usable for signing), or
     * has no keys in it yet at all (thus we cannot tell).
     */
    public State isWatching() {
        lock.lock();
        try {
            if (hashToKeys.isEmpty())
                return State.EMPTY;
            return isWatching ? State.WATCHING : State.REGULAR;
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
            boolean a = hashToKeys.remove(ByteString.copyFrom(key.getPubKeyHash())) != null;
            boolean b = pubkeyToKeys.remove(ByteString.copyFrom(key.getPubKey())) != null;
            checkState(a == b);   // Should be in both maps or neither.
            return a;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long getEarliestKeyCreationTime() {
        lock.lock();
        try {
            long time = Long.MAX_VALUE;
            for (ECKey key : hashToKeys.values())
                time = Math.min(key.getCreationTimeSeconds(), time);
            return time;
        } finally {
            lock.unlock();
        }
    }

    public List<ListenerRegistration<KeyChainEventListener>> getListeners() {
        return new ArrayList<>(listeners);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Serialization support
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    Map<ECKey, Protos.Key.Builder> serializeToEditableProtobufs() {
        Map<ECKey, Protos.Key.Builder> result = new LinkedHashMap<>();
        for (ECKey ecKey : hashToKeys.values()) {
            Protos.Key.Builder protoKey = serializeEncryptableItem(ecKey);
            protoKey.setPublicKey(ByteString.copyFrom(ecKey.getPubKey()));
            result.put(ecKey, protoKey);
        }
        return result;
    }

    @Override
    public List<Protos.Key> serializeToProtobuf() {
        Collection<Protos.Key.Builder> builders = serializeToEditableProtobufs().values();
        List<Protos.Key> result = new ArrayList<>(builders.size());
        for (Protos.Key.Builder builder : builders) result.add(builder.build());
        return result;
    }

    /*package*/ static Protos.Key.Builder serializeEncryptableItem(EncryptableItem item) {
        Protos.Key.Builder proto = Protos.Key.newBuilder();
        proto.setCreationTimestamp(item.getCreationTimeSeconds() * 1000);
        if (item.isEncrypted() && item.getEncryptedData() != null) {
            // The encrypted data can be missing for an "encrypted" key in the case of a deterministic wallet for
            // which the leaf keys chain to an encrypted parent and rederive their private keys on the fly. In that
            // case the caller in DeterministicKeyChain will take care of setting the type.
            EncryptedData data = item.getEncryptedData();
            proto.setEncryptedData(proto.getEncryptedData().toBuilder()
                    .setEncryptedPrivateKey(ByteString.copyFrom(data.encryptedBytes))
                    .setInitialisationVector(ByteString.copyFrom(data.initialisationVector)));
            // We don't allow mixing of encryption types at the moment.
            checkState(item.getEncryptionType() == Protos.Wallet.EncryptionType.ENCRYPTED_SCRYPT_AES);
            proto.setType(Protos.Key.Type.ENCRYPTED_SCRYPT_AES);
        } else {
            final byte[] secret = item.getSecretBytes();
            // The secret might be missing in the case of a watching wallet, or a key for which the private key
            // is expected to be rederived on the fly from its parent.
            if (secret != null)
                proto.setSecretBytes(ByteString.copyFrom(secret));
            proto.setType(Protos.Key.Type.ORIGINAL);
        }
        return proto;
    }

    /**
     * Returns a new BasicKeyChain that contains all basic, ORIGINAL type keys extracted from the list. Unrecognised
     * key types are ignored.
     */
    public static BasicKeyChain fromProtobufUnencrypted(List<Protos.Key> keys) throws UnreadableWalletException {
        BasicKeyChain chain = new BasicKeyChain();
        chain.deserializeFromProtobuf(keys);
        return chain;
    }

    /**
     * Returns a new BasicKeyChain that contains all basic, ORIGINAL type keys and also any encrypted keys extracted
     * from the list. Unrecognised key types are ignored.
     * @throws org.bitcoinj.wallet.UnreadableWalletException.BadPassword if the password doesn't seem to match
     * @throws org.bitcoinj.wallet.UnreadableWalletException if the data structures are corrupted/inconsistent
     */
    public static BasicKeyChain fromProtobufEncrypted(List<Protos.Key> keys, KeyCrypter crypter) throws UnreadableWalletException {
        BasicKeyChain chain = new BasicKeyChain(checkNotNull(crypter));
        chain.deserializeFromProtobuf(keys);
        return chain;
    }

    private void deserializeFromProtobuf(List<Protos.Key> keys) throws UnreadableWalletException {
        lock.lock();
        try {
            checkState(hashToKeys.isEmpty(), "Tried to deserialize into a non-empty chain");
            for (Protos.Key key : keys) {
                if (key.getType() != Protos.Key.Type.ORIGINAL && key.getType() != Protos.Key.Type.ENCRYPTED_SCRYPT_AES)
                    continue;
                boolean encrypted = key.getType() == Protos.Key.Type.ENCRYPTED_SCRYPT_AES;
                byte[] priv = key.hasSecretBytes() ? key.getSecretBytes().toByteArray() : null;
                if (!key.hasPublicKey())
                    throw new UnreadableWalletException("Public key missing");
                byte[] pub = key.getPublicKey().toByteArray();
                ECKey ecKey;
                if (encrypted) {
                    checkState(keyCrypter != null, "This wallet is encrypted but encrypt() was not called prior to deserialization");
                    if (!key.hasEncryptedData())
                        throw new UnreadableWalletException("Encrypted private key data missing");
                    Protos.EncryptedData proto = key.getEncryptedData();
                    EncryptedData e = new EncryptedData(proto.getInitialisationVector().toByteArray(),
                            proto.getEncryptedPrivateKey().toByteArray());
                    ecKey = ECKey.fromEncrypted(e, keyCrypter, pub);
                } else {
                    if (priv != null)
                        ecKey = ECKey.fromPrivateAndPrecalculatedPublic(priv, pub);
                    else
                        ecKey = ECKey.fromPublicOnly(pub);
                }
                ecKey.setCreationTimeSeconds(key.getCreationTimestamp() / 1000);
                importKeyLocked(ecKey);
            }
        } finally {
            lock.unlock();
        }
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Event listener support
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void addEventListener(KeyChainEventListener listener) {
        addEventListener(listener, Threading.USER_THREAD);
    }

    @Override
    public void addEventListener(KeyChainEventListener listener, Executor executor) {
        addEventListener(new ListenerRegistration<>(listener, executor));
    }

    /* package private */ void addEventListener(ListenerRegistration<KeyChainEventListener> listener) {
        listeners.add(listener);
    }

    @Override
    public boolean removeEventListener(KeyChainEventListener listener) {
        return ListenerRegistration.removeFromList(listener, listeners);
    }

    private void queueOnKeysAdded(final List<ECKey> keys) {
        checkState(lock.isHeldByCurrentThread());
        for (final ListenerRegistration<KeyChainEventListener> registration : listeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onKeysAdded(keys);
                }
            });
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Encryption support
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Convenience wrapper around {@link #toEncrypted(KeyCrypter,
     * org.bouncycastle.crypto.params.KeyParameter)} which uses the default Scrypt key derivation algorithm and
     * parameters, derives a key from the given password and returns the created key.
     */
    @Override
    public BasicKeyChain toEncrypted(CharSequence password) {
        checkNotNull(password);
        checkArgument(password.length() > 0);
        KeyCrypter scrypt = new KeyCrypterScrypt();
        KeyParameter derivedKey = scrypt.deriveKey(password);
        return toEncrypted(scrypt, derivedKey);
    }

    /**
     * Encrypt the wallet using the KeyCrypter and the AES key. A good default KeyCrypter to use is
     * {@link KeyCrypterScrypt}.
     *
     * @param keyCrypter The KeyCrypter that specifies how to encrypt/ decrypt a key
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming
     *               to create from a password)
     * @throws KeyCrypterException Thrown if the wallet encryption fails. If so, the wallet state is unchanged.
     */
    @Override
    public BasicKeyChain toEncrypted(KeyCrypter keyCrypter, KeyParameter aesKey) {
        lock.lock();
        try {
            checkNotNull(keyCrypter);
            checkState(this.keyCrypter == null, "Key chain is already encrypted");
            BasicKeyChain encrypted = new BasicKeyChain(keyCrypter);
            for (ECKey key : hashToKeys.values()) {
                ECKey encryptedKey = key.encrypt(keyCrypter, aesKey);
                // Check that the encrypted key can be successfully decrypted.
                // This is done as it is a critical failure if the private key cannot be decrypted successfully
                // (all bitcoin controlled by that private key is lost forever).
                // For a correctly constructed keyCrypter the encryption should always be reversible so it is just
                // being as cautious as possible.
                if (!ECKey.encryptionIsReversible(key, encryptedKey, keyCrypter, aesKey))
                    throw new KeyCrypterException("The key " + key.toString() + " cannot be successfully decrypted after encryption so aborting wallet encryption.");
                encrypted.importKeyLocked(encryptedKey);
            }
            for (ListenerRegistration<KeyChainEventListener> listener : listeners) {
                encrypted.addEventListener(listener);
            }
            return encrypted;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public BasicKeyChain toDecrypted(CharSequence password) {
        checkNotNull(keyCrypter, "Wallet is already decrypted");
        KeyParameter aesKey = keyCrypter.deriveKey(password);
        return toDecrypted(aesKey);
    }

    @Override
    public BasicKeyChain toDecrypted(KeyParameter aesKey) {
        lock.lock();
        try {
            checkState(keyCrypter != null, "Wallet is already decrypted");
            // Do an up-front check.
            if (numKeys() > 0 && !checkAESKey(aesKey))
                throw new KeyCrypterException("Password/key was incorrect.");
            BasicKeyChain decrypted = new BasicKeyChain();
            for (ECKey key : hashToKeys.values()) {
                decrypted.importKeyLocked(key.decrypt(aesKey));
            }
            for (ListenerRegistration<KeyChainEventListener> listener : listeners) {
                decrypted.addEventListener(listener);
            }
            return decrypted;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns whether the given password is correct for this key chain.
     * @throws IllegalStateException if the chain is not encrypted at all.
     */
    @Override
    public boolean checkPassword(CharSequence password) {
        checkNotNull(password);
        checkState(keyCrypter != null, "Key chain not encrypted");
        return checkAESKey(keyCrypter.deriveKey(password));
    }

    /**
     * Check whether the AES key can decrypt the first encrypted key in the wallet.
     *
     * @return true if AES key supplied can decrypt the first encrypted private key in the wallet, false otherwise.
     */
    @Override
    public boolean checkAESKey(KeyParameter aesKey) {
        lock.lock();
        try {
            // If no keys then cannot decrypt.
            if (hashToKeys.isEmpty()) return false;
            checkState(keyCrypter != null, "Key chain is not encrypted");

            // Find the first encrypted key in the wallet.
            ECKey first = null;
            for (ECKey key : hashToKeys.values()) {
                if (key.isEncrypted()) {
                    first = key;
                    break;
                }
            }
            checkState(first != null, "No encrypted keys in the wallet");

            try {
                ECKey rebornKey = first.decrypt(aesKey);
                return Arrays.equals(first.getPubKey(), rebornKey.getPubKey());
            } catch (KeyCrypterException e) {
                // The AES key supplied is incorrect.
                return false;
            }
        } finally {
            lock.unlock();
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Bloom filtering support
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    @Override
    public BloomFilter getFilter(int size, double falsePositiveRate, long tweak) {
        lock.lock();
        try {
            BloomFilter filter = new BloomFilter(size, falsePositiveRate, tweak);
            for (ECKey key : hashToKeys.values())
                filter.insert(key);
            return filter;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int numBloomFilterEntries() {
        return numKeys() * 2;
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Key rotation support
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /** Returns the first ECKey created after the given UNIX time, or null if there is none. */
    @Nullable
    public ECKey findOldestKeyAfter(long timeSecs) {
        lock.lock();
        try {
            ECKey oldest = null;
            for (ECKey key : hashToKeys.values()) {
                final long keyTime = key.getCreationTimeSeconds();
                if (keyTime > timeSecs) {
                    if (oldest == null || oldest.getCreationTimeSeconds() > keyTime)
                        oldest = key;
                }
            }
            return oldest;
        } finally {
            lock.unlock();
        }
    }

    /** Returns a list of all ECKeys created after the given UNIX time. */
    public List<ECKey> findKeysBefore(long timeSecs) {
        lock.lock();
        try {
            List<ECKey> results = new LinkedList<>();
            for (ECKey key : hashToKeys.values()) {
                final long keyTime = key.getCreationTimeSeconds();
                if (keyTime < timeSecs) {
                    results.add(key);
                }
            }
            return results;
        } finally {
            lock.unlock();
        }
    }

    public String toString(boolean includePrivateKeys, @Nullable KeyParameter aesKey, NetworkParameters params) {
        final StringBuilder builder = new StringBuilder();
        List<ECKey> keys = getKeys();
        Collections.sort(keys, ECKey.AGE_COMPARATOR);
        for (ECKey key : keys)
            key.formatKeyWithAddress(includePrivateKeys, aesKey, builder, params, null, "imported");
        return builder.toString();
    }
}
