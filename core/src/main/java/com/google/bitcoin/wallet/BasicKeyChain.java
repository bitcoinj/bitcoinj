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
import com.google.bitcoin.crypto.EncryptedData;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterException;
import com.google.bitcoin.crypto.KeyCrypterScrypt;
import com.google.bitcoin.store.UnreadableWalletException;
import com.google.bitcoin.utils.ListenerRegistration;
import com.google.bitcoin.utils.Threading;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import org.bitcoinj.wallet.Protos;
import org.spongycastle.crypto.params.KeyParameter;

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
    private final ReentrantLock lock = Threading.lock("BasicKeyChain");

    // Maps used to let us quickly look up a key given data we find in transcations or the block chain.
    private final LinkedHashMap<ByteString, ECKey> hashToKeys;
    private final LinkedHashMap<ByteString, ECKey> pubkeyToKeys;
    @Nullable private KeyCrypter keyCrypter;

    private final CopyOnWriteArrayList<ListenerRegistration<KeyChainEventListener>> listeners;

    public BasicKeyChain() {
        hashToKeys = new LinkedHashMap<ByteString, ECKey>();
        pubkeyToKeys = new LinkedHashMap<ByteString, ECKey>();
        listeners = new CopyOnWriteArrayList<ListenerRegistration<KeyChainEventListener>>();
    }

    /** Returns the {@link KeyCrypter} in use or null if the key chain is not encrypted. */
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
    public ECKey getKey(KeyPurpose purpose) {
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

    /** Returns a copy of the list of keys that this chain is managing. */
    public List<ECKey> getKeys() {
        lock.lock();
        try {
            return new ArrayList<ECKey>(hashToKeys.values());
        } finally {
            lock.unlock();
        }
    }

    public int importKeys(List<? extends ECKey> keys) {
        lock.lock();
        try {
            // Check none of the keys are encrypted: we disallow mixing of encrypted keys between wallets in case the
            // passwords are different.
            for (ECKey key : keys)
                if (key.isEncrypted())
                    throw new IllegalArgumentException("Cannot import an encrypted key, decrypt it first.");
            List<ECKey> actuallyAdded = new ArrayList<ECKey>(keys.size());
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

    private void importKeyLocked(ECKey key) {
        checkState(lock.isHeldByCurrentThread());
        pubkeyToKeys.put(ByteString.copyFrom(key.getPubKey()), key);
        hashToKeys.put(ByteString.copyFrom(key.getPubKeyHash()), key);
    }

    @Override
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        lock.lock();
        try {
            return hashToKeys.get(ByteString.copyFrom(pubkeyHash));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        lock.lock();
        try {
            return pubkeyToKeys.get(ByteString.copyFrom(pubkey));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean hasKey(ECKey key) {
        return findKeyFromPubKey(key.getPubKey()) != null;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Serialization support
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public List<Protos.Key> serializeToProtobuf() {
        List<Protos.Key> result = Lists.newArrayListWithExpectedSize(hashToKeys.size());
        for (ECKey ecKey : hashToKeys.values()) {
            Protos.Key.Builder protoKey = Protos.Key.newBuilder();
            protoKey.setType(Protos.Key.Type.ORIGINAL)
                    .setCreationTimestamp(ecKey.getCreationTimeSeconds() * 1000)
                    .setPublicKey(ByteString.copyFrom(ecKey.getPubKey()));
            byte[] priv = ecKey.getPrivKeyBytes();
            if (priv != null)
                protoKey.setPrivateKey(ByteString.copyFrom(priv));
            if (keyCrypter != null) {
                EncryptedData encryptedPrivateKey = checkNotNull(ecKey.getEncryptedPrivateKey());
                protoKey.getEncryptedPrivateKeyBuilder()
                        .setEncryptedPrivateKey(ByteString.copyFrom(encryptedPrivateKey.encryptedBytes))
                        .setInitialisationVector(ByteString.copyFrom(encryptedPrivateKey.initialisationVector));
                // We don't allow mixing of encryption types at the moment.
                checkState(ecKey.getKeyCrypter().getUnderstoodEncryptionType() == Protos.Wallet.EncryptionType.ENCRYPTED_SCRYPT_AES);
                protoKey.setType(Protos.Key.Type.ENCRYPTED_SCRYPT_AES);
            }
            result.add(protoKey.build());
        }
        return result;
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
     * @throws com.google.bitcoin.store.UnreadableWalletException.BadPassword if the password doesn't seem to match
     * @throws com.google.bitcoin.store.UnreadableWalletException if the data structures are corrupted/inconsistent
     */
    public static BasicKeyChain fromProtobufEncrypted(List<Protos.Key> keys, KeyCrypter crypter, CharSequence password) throws UnreadableWalletException {
        BasicKeyChain chain = new BasicKeyChain();
        chain.keyCrypter = checkNotNull(crypter);
        chain.deserializeFromProtobuf(keys);
        if (!chain.checkPassword(password))
            throw new UnreadableWalletException.BadPassword();
        return chain;
    }

    /**
     * Returns a new BasicKeyChain that contains all basic, ORIGINAL type keys and also any encrypted keys extracted
     * from the list. Unrecognised key types are ignored.
     * @throws com.google.bitcoin.store.UnreadableWalletException.BadPassword if the password doesn't seem to match
     * @throws com.google.bitcoin.store.UnreadableWalletException if the data structures are corrupted/inconsistent
     */
    public static BasicKeyChain fromProtobufEncrypted(List<Protos.Key> keys, KeyCrypter crypter,  KeyParameter aesKey) throws UnreadableWalletException {
        BasicKeyChain chain = new BasicKeyChain();
        chain.keyCrypter = checkNotNull(crypter);
        chain.deserializeFromProtobuf(keys);
        if (!chain.checkAESKey(aesKey))
            throw new UnreadableWalletException.BadPassword();
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
                byte[] priv = key.hasPrivateKey() ? key.getPrivateKey().toByteArray() : null;
                if (!key.hasPublicKey())
                    throw new UnreadableWalletException("Public key missing");
                byte[] pub = key.getPublicKey().toByteArray();
                ECKey ecKey;
                if (encrypted) {
                    checkState(keyCrypter != null, "This wallet is encrypted but encrypt() was not called prior to deserialization");
                    if (!key.hasEncryptedPrivateKey())
                        throw new UnreadableWalletException("Encrypted private key data missing");
                    Protos.EncryptedPrivateKey proto = key.getEncryptedPrivateKey();
                    EncryptedData e = new EncryptedData(proto.getInitialisationVector().toByteArray(),
                            proto.getEncryptedPrivateKey().toByteArray());
                    ecKey = ECKey.fromEncrypted(e, keyCrypter, pub);
                } else {
                    if (priv != null)
                        ecKey = ECKey.fromPrivateAndPrecalculatedPublic(priv, pub);
                    else
                        ecKey = ECKey.fromPublicOnly(pub);
                }
                ecKey.setCreationTimeSeconds((key.getCreationTimestamp() + 500) / 1000);
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
        listeners.add(new ListenerRegistration<KeyChainEventListener>(listener, executor));
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
     * Convenience wrapper around {@link #encrypt(com.google.bitcoin.crypto.KeyCrypter,
     * org.spongycastle.crypto.params.KeyParameter)} which uses the default Scrypt key derivation algorithm and
     * parameters, derives a key from the given password and returns the created key.
     */
    @Override
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
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming
     *               to create from a password)
     * @throws KeyCrypterException Thrown if the wallet encryption fails. If so, the wallet state is unchanged.
     */
    @Override
    public void encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        lock.lock();
        try {
            checkNotNull(keyCrypter);
            checkState(this.keyCrypter == null, "Key chain is already encrypted");
            LinkedList<ECKey> cryptedKeys = Lists.newLinkedList();
            for (ECKey key : hashToKeys.values()) {
                ECKey encryptedKey = key.encrypt(keyCrypter, aesKey);
                // Check that the encrypted key can be successfully decrypted.
                // This is done as it is a critical failure if the private key cannot be decrypted successfully
                // (all bitcoin controlled by that private key is lost forever).
                // For a correctly constructed keyCrypter the encryption should always be reversible so it is just
                // being as cautious as possible.
                if (!ECKey.encryptionIsReversible(key, encryptedKey, keyCrypter, aesKey))
                    throw new KeyCrypterException("The key " + key.toString() + " cannot be successfully decrypted after encryption so aborting wallet encryption.");
                cryptedKeys.add(encryptedKey);
            }
            replaceKeysLocked(keyCrypter, cryptedKeys);
        } finally {
            lock.unlock();
        }
    }

    private void replaceKeysLocked(@Nullable KeyCrypter keyCrypter, List<ECKey> cryptedKeys) {
        checkState(lock.isHeldByCurrentThread());
        // Replace the old keychain with the encrypted one.
        hashToKeys.clear();
        pubkeyToKeys.clear();
        for (ECKey key : cryptedKeys)
            importKeyLocked(key);
        this.keyCrypter = keyCrypter;
        queueOnEncryptionChanged();
    }

    private void queueOnEncryptionChanged() {
        checkState(lock.isHeldByCurrentThread());
        for (final ListenerRegistration<KeyChainEventListener> registration : listeners) {
            registration.executor.execute(new Runnable() {
                @Override
                public void run() {
                    registration.listener.onEncryptionChanged();
                }
            });
        }
    }

    @Override
    public void decrypt(KeyParameter aesKey) {
        lock.lock();
        try {
            checkNotNull(keyCrypter, "Wallet is already decrypted");
            // Do an up-front check.
            if (!checkAESKey(aesKey))
                throw new KeyCrypterException("Password/key was incorrect.");

            // Create a new arraylist that will contain the decrypted keys
            LinkedList<ECKey> decryptedKeys = Lists.newLinkedList();

            for (ECKey key : hashToKeys.values()) {
                decryptedKeys.add(key.decrypt(keyCrypter, aesKey));
            }
            replaceKeysLocked(null, decryptedKeys);
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
        lock.lock();
        try {
            checkState(keyCrypter != null, "Key chain not encrypted");
            return checkAESKey(keyCrypter.deriveKey(password));
        } finally {
            lock.unlock();
        }
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
                ECKey rebornKey = first.decrypt(keyCrypter, aesKey);
                return Arrays.equals(first.getPubKey(), rebornKey.getPubKey());
            } catch (KeyCrypterException e) {
                // The AES key supplied is incorrect.
                return false;
            }
        } finally {
            lock.unlock();
        }
    }
}
