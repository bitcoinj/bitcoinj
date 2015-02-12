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

package org.bitcoinj.wallet;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.store.UnreadableWalletException;
import org.bitcoinj.utils.ListenerRegistration;
import org.bitcoinj.utils.Threading;
import com.google.common.base.Joiner;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.protobuf.ByteString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Executor;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A KeyChainGroup is used by the {@link org.bitcoinj.core.Wallet} and
 * manages: a {@link BasicKeyChain} object (which will normally be empty), and zero or more
 * {@link DeterministicKeyChain}s. A deterministic key chain will be created lazily/on demand
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
 *
 * <p>Deterministic key chains have a concept of a lookahead size and threshold. Please see the discussion in the
 * class docs for {@link DeterministicKeyChain} for more information on this topic.</p>
 */
public class KeyChainGroup implements KeyBag {
    private static final Logger log = LoggerFactory.getLogger(KeyChainGroup.class);

    private BasicKeyChain basic;
    private NetworkParameters params;
    protected final LinkedList<DeterministicKeyChain> chains;
    // currentKeys is used for normal, non-multisig/married wallets. currentAddresses is used when we're handing out
    // P2SH addresses. They're mutually exclusive.
    private final EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys;

    // The map keys are the watching keys of the followed chains and values are the following chains
    private Multimap<DeterministicKey, DeterministicKeyChain> followingKeychains;

    // holds a number of signatures required to spend. It's the N from N-of-M CHECKMULTISIG script for P2SH transactions
    // and always 1 for other transaction types
    private int sigsRequiredToSpend;

    // The map holds P2SH redeem script and corresponding ECKeys issued by this KeyChainGroup (including lookahead)
    // mapped to redeem script hashes.
    private LinkedHashMap<ByteString, RedeemData> marriedKeysRedeemData;

    private final EnumMap<KeyChain.KeyPurpose, Address> currentAddresses;
    @Nullable private KeyCrypter keyCrypter;
    private int lookaheadSize = -1;
    private int lookaheadThreshold = -1;

    /** Creates a keychain group with no basic chain, and a single, lazily created HD chain. */
    public KeyChainGroup(NetworkParameters params) {
        this(params, null, new ArrayList<DeterministicKeyChain>(1), null, null, 1, null);
    }

    /** Creates a keychain group with no basic chain, and an HD chain initialized from the given seed. */
    public KeyChainGroup(NetworkParameters params, DeterministicSeed seed) {
        this(params, null, ImmutableList.of(new DeterministicKeyChain(seed)), null, null, 1, null);
    }

    /**
     * Creates a keychain group with no basic chain, and an HD chain that is watching the given watching key.
     * This HAS to be an account key as returned by {@link DeterministicKeyChain#getWatchingKey()}.
     */
    public KeyChainGroup(NetworkParameters params, DeterministicKey watchKey) {
        this(params, null, ImmutableList.of(DeterministicKeyChain.watch(watchKey)), null, null, 1, null);
    }

    /**
     * Creates a keychain group with no basic chain, and an HD chain that is watching the given watching key which
     * was assumed to be first used at the given UNIX time.
     * This HAS to be an account key as returned by {@link DeterministicKeyChain#getWatchingKey()}.
     */
    public KeyChainGroup(NetworkParameters params, DeterministicKey watchKey, long creationTimeSecondsSecs) {
        this(params, null, ImmutableList.of(DeterministicKeyChain.watch(watchKey, creationTimeSecondsSecs)), null, null, 1, null);
    }

    /**
     * Creates a keychain group with no basic chain, with an HD chain initialized from the given seed and being followed
     * by given list of watch keys. Watch keys have to be account keys.
     */
    public KeyChainGroup(NetworkParameters params, DeterministicSeed seed, List<DeterministicKey> followingAccountKeys, int sigsRequiredToSpend) {
        this(params, seed);

        addFollowingAccountKeys(followingAccountKeys, sigsRequiredToSpend);
    }

    /**
     * <p>Alias for <code>addFollowingAccountKeys(followingAccountKeys, (followingAccountKeys.size() + 1) / 2 + 1)</code></p>
     * <p>Creates married keychain requiring majority of keys to spend (2-of-3, 3-of-5 and so on)</p>
     * <p>IMPORTANT: As of Bitcoin Core 0.9 all multisig transactions which require more than 3 public keys are non-standard
     * and such spends won't be processed by peers with default settings, essentially making such transactions almost
     * nonspendable</p>
     */
    public void addFollowingAccountKeys(List<DeterministicKey> followingAccountKeys) {
        addFollowingAccountKeys(followingAccountKeys, (followingAccountKeys.size() + 1) / 2 + 1);
    }

    /**
     * <p>Makes given account keys follow the account key of the active keychain. After that active keychain will be
     * treated as married and you will be able to get P2SH addresses to receive coins to. Given sigsRequiredToSpend value
     * specifies how many signatures required to spend transactions for this married keychain. This value should not exceed
     * total number of keys involved (one followed key plus number of following keys), otherwise IllegalArgumentException
     * will be thrown.</p>
     * <p>IMPORTANT: As of Bitcoin Core 0.9 all multisig transactions which require more than 3 public keys are non-standard
     * and such spends won't be processed by peers with default settings, essentially making such transactions almost
     * nonspendable</p>
     * <p>This method will throw an IllegalStateException, if active keychain is already married or already has leaf keys
     * issued. In future this behaviour may be replaced with key rotation.</p>
     */
    public void addFollowingAccountKeys(List<DeterministicKey> followingAccountKeys, int sigsRequiredToSpend) {
        checkArgument(sigsRequiredToSpend <= followingAccountKeys.size() + 1, "Multisig threshold can't exceed total number of keys");
        checkState(!isMarried(), "KeyChainGroup is married already");
        checkState(getActiveKeyChain().numLeafKeysIssued() == 0, "Active keychain already has keys in use");

        this.sigsRequiredToSpend = sigsRequiredToSpend;

        DeterministicKey accountKey = getActiveKeyChain().getWatchingKey();
        for (DeterministicKey key : followingAccountKeys) {
            checkArgument(key.getPath().size() == 1, "Following keys have to be account keys");
            DeterministicKeyChain chain = DeterministicKeyChain.watchAndFollow(key);
            if (lookaheadSize >= 0)
                chain.setLookaheadSize(lookaheadSize);
            if (lookaheadThreshold >= 0)
                chain.setLookaheadThreshold(lookaheadThreshold);
            followingKeychains.put(accountKey, chain);
        }
    }

    // Used for deserialization.
    private KeyChainGroup(NetworkParameters params, @Nullable BasicKeyChain basicKeyChain, List<DeterministicKeyChain> chains,
                          @Nullable EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys, Multimap<DeterministicKey,
                          DeterministicKeyChain> followingKeychains, int sigsRequiredToSpend, @Nullable KeyCrypter crypter) {
        this.params = params;
        this.basic = basicKeyChain == null ? new BasicKeyChain() : basicKeyChain;
        this.chains = new LinkedList<DeterministicKeyChain>(checkNotNull(chains));
        this.keyCrypter = crypter;
        this.currentKeys = currentKeys == null
                ? new EnumMap<KeyChain.KeyPurpose, DeterministicKey>(KeyChain.KeyPurpose.class)
                : currentKeys;
        this.currentAddresses = new EnumMap<KeyChain.KeyPurpose, Address>(KeyChain.KeyPurpose.class);
        this.followingKeychains = HashMultimap.create();
        if (followingKeychains != null) {
            this.followingKeychains.putAll(followingKeychains);
        }
        this.sigsRequiredToSpend = sigsRequiredToSpend;
        marriedKeysRedeemData = new LinkedHashMap<ByteString, RedeemData>();
        maybeLookaheadScripts();

        if (!this.followingKeychains.isEmpty()) {
            DeterministicKey followedWatchKey = getActiveKeyChain().getWatchingKey();
            for (Map.Entry<KeyChain.KeyPurpose, DeterministicKey> entry : this.currentKeys.entrySet()) {
                Address address = makeP2SHOutputScript(entry.getValue(), followedWatchKey).getToAddress(params);
                currentAddresses.put(entry.getKey(), address);
            }
        }
    }

    /**
     * This keeps {@link #marriedKeysRedeemData} in sync with the number of keys issued
     */
    private void maybeLookaheadScripts() {
        if (chains.isEmpty())
            return;

        int numLeafKeys = 0;
        for (DeterministicKeyChain chain : chains) {
            numLeafKeys += chain.getLeafKeys().size();
        }

        checkState(marriedKeysRedeemData.size() <= numLeafKeys, "Number of scripts is greater than number of leaf keys");
        if (marriedKeysRedeemData.size() == numLeafKeys)
            return;

        for (DeterministicKeyChain chain : chains) {
            if (isMarried(chain)) {
                chain.maybeLookAhead();
                for (DeterministicKey followedKey : chain.getLeafKeys()) {
                    RedeemData redeemData = getRedeemData(followedKey, chain.getWatchingKey());
                    Script scriptPubKey = ScriptBuilder.createP2SHOutputScript(redeemData.redeemScript);
                    marriedKeysRedeemData.put(ByteString.copyFrom(scriptPubKey.getPubKeyHash()), redeemData);
                }
            }
        }
    }

    /** Adds a new HD chain to the chains list, and make it the default chain (from which keys are issued). */
    public void createAndActivateNewHDChain() {
        // We can't do auto upgrade here because we don't know the rotation time, if any.
        final DeterministicKeyChain chain = new DeterministicKeyChain(new SecureRandom());
        log.info("Creating and activating a new HD chain: {}", chain);
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
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS}. The returned key is stable until
     * it's actually seen in a pending or confirmed transaction, at which point this method will start returning
     * a different key (for each purpose independently).
     * <p>This method is not supposed to be used for married keychains and will throw UnsupportedOperationException if
     * the active chain is married.
     * For married keychains use {@link #currentAddress(KeyChain.KeyPurpose)}
     * to get a proper P2SH address</p>
     */
    public DeterministicKey currentKey(KeyChain.KeyPurpose purpose) {
        DeterministicKeyChain chain = getActiveKeyChain();
        if (isMarried(chain)) {
            throw new UnsupportedOperationException("Key is not suitable to receive coins for married keychains." +
                                                    " Use freshAddress to get P2SH address instead");
        }
        DeterministicKey current = currentKeys.get(purpose);
        if (current == null) {
            current = freshKey(purpose);
            currentKeys.put(purpose, current);
        }
        return current;
    }

    /**
     * Returns address for a {@link #currentKey(KeyChain.KeyPurpose)}
     */
    public Address currentAddress(KeyChain.KeyPurpose purpose) {
        DeterministicKeyChain chain = getActiveKeyChain();
        if (isMarried(chain)) {
            Address current = currentAddresses.get(purpose);
            if (current == null) {
                current = freshAddress(purpose);
                currentAddresses.put(purpose, current);
            }
            return current;
        } else {
            return currentKey(purpose).toAddress(params);
        }
    }

    /**
     * Returns a key that has not been returned by this method before (fresh). You can think of this as being
     * a newly created key, although the notion of "create" is not really valid for a
     * {@link DeterministicKeyChain}. When the parameter is
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key out
     * to someone who wishes to send money.
     * <p>This method is not supposed to be used for married keychains and will throw UnsupportedOperationException if
     * the active chain is married.
     * For married keychains use {@link #freshAddress(KeyChain.KeyPurpose)}
     * to get a proper P2SH address</p>
     */
    public DeterministicKey freshKey(KeyChain.KeyPurpose purpose) {
        return freshKeys(purpose, 1).get(0);
    }

    /**
     * Returns a key/s that have not been returned by this method before (fresh). You can think of this as being
     * newly created key/s, although the notion of "create" is not really valid for a
     * {@link DeterministicKeyChain}. When the parameter is
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key out
     * to someone who wishes to send money.
     * <p>This method is not supposed to be used for married keychains and will throw UnsupportedOperationException if
     * the active chain is married.
     * For married keychains use {@link #freshAddress(KeyChain.KeyPurpose)}
     * to get a proper P2SH address</p>
     */
    public List<DeterministicKey> freshKeys(KeyChain.KeyPurpose purpose, int numberOfKeys) {
        DeterministicKeyChain chain = getActiveKeyChain();
        if (isMarried(chain)) {
            throw new UnsupportedOperationException("Key is not suitable to receive coins for married keychains." +
                    " Use freshAddress to get P2SH address instead");
        }
        return chain.getKeys(purpose, numberOfKeys);   // Always returns the next key along the key chain.
    }

    /**
     * Returns address for a {@link #freshKey(KeyChain.KeyPurpose)}
     */
    public Address freshAddress(KeyChain.KeyPurpose purpose) {
        DeterministicKeyChain chain = getActiveKeyChain();
        if (isMarried(chain)) {
            List<ECKey> marriedKeys = freshMarriedKeys(purpose, chain);
            Script p2shScript = makeP2SHOutputScript(marriedKeys);
            Address freshAddress = Address.fromP2SHScript(params, p2shScript);
            maybeLookaheadScripts();
            currentAddresses.put(purpose, freshAddress);
            return freshAddress;
        } else {
            return freshKey(purpose).toAddress(params);
        }
    }

    private List<ECKey> freshMarriedKeys(KeyChain.KeyPurpose purpose, DeterministicKeyChain followedKeyChain) {
        DeterministicKey followedKey = followedKeyChain.getKey(purpose);
        ImmutableList.Builder<ECKey> keys = ImmutableList.<ECKey>builder().add(followedKey);
        Collection<DeterministicKeyChain> keyChains = followingKeychains.get(followedKeyChain.getWatchingKey());
        for (DeterministicKeyChain keyChain : keyChains) {
            DeterministicKey followingKey = keyChain.getKey(purpose);
            checkState(followedKey.getChildNumber().equals(followingKey.getChildNumber()), "Following keychains should be in sync");
            keys.add(followingKey);
        }
        return keys.build();
    }

    private List<ECKey> getMarriedKeysWithFollowed(DeterministicKey followedKey, Collection<DeterministicKeyChain> followingChains) {
        ImmutableList.Builder<ECKey> keys = ImmutableList.builder();
        for (DeterministicKeyChain keyChain : followingChains) {
            keyChain.maybeLookAhead();
            keys.add(keyChain.getKeyByPath(followedKey.getPath()));
        }
        keys.add(followedKey);
        return keys.build();
    }

    /** Returns the key chain that's used for generation of fresh/current keys. This is always the newest HD chain. */
    public DeterministicKeyChain getActiveKeyChain() {
        if (chains.isEmpty()) {
            if (basic.numKeys() > 0) {
                log.warn("No HD chain present but random keys are: you probably deserialized an old wallet.");
                // If called from the wallet (most likely) it'll try to upgrade us, as it knows the rotation time
                // but not the password.
                throw new DeterministicUpgradeRequiredException();
            }
            // Otherwise we have no HD chains and no random keys: we are a new born! So a random seed is fine.
            createAndActivateNewHDChain();
        }
        return chains.get(chains.size() - 1);
    }

    /**
     * Sets the lookahead buffer size for ALL deterministic key chains as well as for following key chains if any exist,
     * see {@link DeterministicKeyChain#setLookaheadSize(int)}
     * for more information.
     */
    public void setLookaheadSize(int lookaheadSize) {
        this.lookaheadSize = lookaheadSize;
        for (DeterministicKeyChain chain : chains) {
            chain.setLookaheadSize(lookaheadSize);
        }
        for (DeterministicKeyChain chain : followingKeychains.values()) {
            chain.setLookaheadSize(lookaheadSize);
        }
    }

    /**
     * Gets the current lookahead size being used for ALL deterministic key chains. See
     * {@link DeterministicKeyChain#setLookaheadSize(int)}
     * for more information.
     */
    public int getLookaheadSize() {
        if (lookaheadSize == -1)
            return getActiveKeyChain().getLookaheadSize();
        else
            return lookaheadSize;
    }

    /**
     * Sets the lookahead buffer threshold for ALL deterministic key chains, see
     * {@link DeterministicKeyChain#setLookaheadThreshold(int)}
     * for more information.
     */
    public void setLookaheadThreshold(int num) {
        for (DeterministicKeyChain chain : chains) {
            chain.setLookaheadThreshold(num);
        }
    }

    /**
     * Gets the current lookahead threshold being used for ALL deterministic key chains. See
     * {@link DeterministicKeyChain#setLookaheadThreshold(int)}
     * for more information.
     */
    public int getLookaheadThreshold() {
        if (lookaheadThreshold == -1)
            return getActiveKeyChain().getLookaheadThreshold();
        else
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

    @Nullable
    public RedeemData findRedeemDataFromScriptHash(byte[] scriptHash) {
        return marriedKeysRedeemData.get(ByteString.copyFrom(scriptHash));
    }

    public void markP2SHAddressAsUsed(Address address) {
        checkState(isMarried());
        checkArgument(address.isP2SHAddress());
        RedeemData data = findRedeemDataFromScriptHash(address.getHash160());
        if (data == null)
            return;   // Not our P2SH address.
        for (ECKey key : data.keys) {
            for (DeterministicKeyChain chain : chains) {
                DeterministicKey k = chain.findKeyFromPubKey(key.getPubKey());
                if (k == null) continue;
                chain.markKeyAsUsed(k);
                maybeMarkCurrentAddressAsUsed(address);
            }
        }
    }

    @Nullable
    @Override
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
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    public void markPubKeyHashAsUsed(byte[] pubkeyHash) {
        for (DeterministicKeyChain chain : chains) {
            DeterministicKey key;
            if ((key = chain.markPubHashAsUsed(pubkeyHash)) != null) {
                maybeMarkCurrentKeyAsUsed(key);
                return;
            }
        }
    }

    /** If the given P2SH address is "current", advance it to a new one. */
    private void maybeMarkCurrentAddressAsUsed(Address address) {
        checkState(isMarried());
        checkArgument(address.isP2SHAddress());
        for (Map.Entry<KeyChain.KeyPurpose, Address> entry : currentAddresses.entrySet()) {
            if (entry.getValue() != null && entry.getValue().equals(address)) {
                log.info("Marking P2SH address as used: {}", address);
                currentAddresses.put(entry.getKey(), freshAddress(entry.getKey()));
                return;
            }
        }
    }

    /** If the given key is "current", advance the current key to a new one. */
    private void maybeMarkCurrentKeyAsUsed(DeterministicKey key) {
        // It's OK for currentKeys to be empty here: it means we're a married wallet and the key may be a part of a
        // rotating chain.
        for (Map.Entry<KeyChain.KeyPurpose, DeterministicKey> entry : currentKeys.entrySet()) {
            if (entry.getValue() != null && entry.getValue().equals(key)) {
                log.info("Marking key as used: {}", key);
                currentKeys.put(entry.getKey(), freshKey(entry.getKey()));
                return;
            }
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
    @Override
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
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    public void markPubKeyAsUsed(byte[] pubkey) {
        for (DeterministicKeyChain chain : chains) {
            DeterministicKey key;
            if ((key = chain.markPubKeyAsUsed(pubkey)) != null) {
                maybeMarkCurrentKeyAsUsed(key);
                return;
            }
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
     * Returns true if the given keychain is being followed by at least one another keychain
     */
    public boolean isMarried(DeterministicKeyChain keychain) {
        DeterministicKey watchingKey = keychain.getWatchingKey();
        return followingKeychains.containsKey(watchingKey) && followingKeychains.get(watchingKey).size() > 0;
    }

    /**
     * An alias for {@link #isMarried(DeterministicKeyChain)} called for the active keychain
     */
    public boolean isMarried() {
        return isMarried(getActiveKeyChain());
    }

    /**
     * Encrypt the keys in the group using the KeyCrypter and the AES key. A good default KeyCrypter to use is
     * {@link org.bitcoinj.crypto.KeyCrypterScrypt}.
     *
     * @throws org.bitcoinj.crypto.KeyCrypterException Thrown if the wallet encryption fails for some reason,
     *         leaving the group unchanged.
     * @throws DeterministicUpgradeRequiredException Thrown if there are random keys but no HD chain.
     */
    public void encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        checkNotNull(keyCrypter);
        checkNotNull(aesKey);
        // This code must be exception safe.
        BasicKeyChain newBasic = basic.toEncrypted(keyCrypter, aesKey);
        List<DeterministicKeyChain> newChains = new ArrayList<DeterministicKeyChain>(chains.size());
        if (chains.isEmpty() && basic.numKeys() == 0) {
            // No HD chains and no random keys: encrypting an entirely empty keychain group. But we can't do that, we
            // must have something to encrypt: so instantiate a new HD chain here.
            createAndActivateNewHDChain();
        }
        for (DeterministicKeyChain chain : chains)
            newChains.add(chain.toEncrypted(keyCrypter, aesKey));
        this.keyCrypter = keyCrypter;
        basic = newBasic;
        chains.clear();
        chains.addAll(newChains);
    }

    /**
     * Decrypt the keys in the group using the previously given key crypter and the AES key. A good default
     * KeyCrypter to use is {@link org.bitcoinj.crypto.KeyCrypterScrypt}.
     *
     * @throws org.bitcoinj.crypto.KeyCrypterException Thrown if the wallet decryption fails for some reason, leaving the group unchanged.
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
        for (DeterministicKeyChain chain : chains) {
            if (isMarried(chain)) {
                chain.maybeLookAhead();
                result += chain.getLeafKeys().size() * 2;
            } else {
                result += chain.numBloomFilterEntries();
            }
        }
        return result;
    }

    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
        BloomFilter filter = new BloomFilter(size, falsePositiveRate, nTweak);
        if (basic.numKeys() > 0)
            filter.merge(basic.getFilter(size, falsePositiveRate, nTweak));

        for (Map.Entry<ByteString, RedeemData> entry : marriedKeysRedeemData.entrySet()) {
            filter.insert(entry.getKey().toByteArray());
            filter.insert(entry.getValue().redeemScript.getProgram());
        }

        for (DeterministicKeyChain chain : chains) {
            if (!isMarried(chain)) {
                filter.merge(chain.getFilter(size, falsePositiveRate, nTweak));
            }
        }
        return filter;
    }

    /** {@inheritDoc} */
    public boolean isRequiringUpdateAllBloomFilter() {
        throw new UnsupportedOperationException();   // Unused.
    }

    private Script makeP2SHOutputScript(List<ECKey> marriedKeys) {
        return ScriptBuilder.createP2SHOutputScript(makeRedeemScript(marriedKeys));
    }

    private Script makeP2SHOutputScript(DeterministicKey followedKey, DeterministicKey followedAccountKey) {
        return ScriptBuilder.createP2SHOutputScript(getRedeemData(followedKey, followedAccountKey).redeemScript);
    }

    private RedeemData getRedeemData(DeterministicKey followedKey, DeterministicKey followedAccountKey) {
        Collection<DeterministicKeyChain> followingChains = followingKeychains.get(followedAccountKey);
        List<ECKey> marriedKeys = getMarriedKeysWithFollowed(followedKey, followingChains);
        return RedeemData.of(marriedKeys, makeRedeemScript(marriedKeys));
    }

    private Script makeRedeemScript(List<ECKey> marriedKeys) {
        return ScriptBuilder.createRedeemScript(sigsRequiredToSpend, marriedKeys);
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
            // prepend each chain with it's following chains if any
            for (DeterministicKeyChain followingChain : followingKeychains.get(chain.getWatchingKey())) {
                result.addAll(followingChain.serializeToProtobuf());
            }
            List<Protos.Key> protos = chain.serializeToProtobuf();
            result.addAll(protos);
        }
        return result;
    }

    public static KeyChainGroup fromProtobufUnencrypted(NetworkParameters params, List<Protos.Key> keys, int sigsRequiredToSpend) throws UnreadableWalletException {
        checkArgument(sigsRequiredToSpend > 0);
        BasicKeyChain basicKeyChain = BasicKeyChain.fromProtobufUnencrypted(keys);
        List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(keys, null);
        EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys = null;
        if (!chains.isEmpty())
            currentKeys = createCurrentKeysMap(chains);
        Multimap<DeterministicKey, DeterministicKeyChain> followingKeychains = extractFollowingKeychains(chains);
        if (sigsRequiredToSpend < 2 && followingKeychains.size() > 0)
            throw new IllegalArgumentException("Married KeyChainGroup requires multiple signatures to spend");
        return new KeyChainGroup(params, basicKeyChain, chains, currentKeys, followingKeychains, sigsRequiredToSpend, null);
    }

    public static KeyChainGroup fromProtobufEncrypted(NetworkParameters params, List<Protos.Key> keys, int sigsRequiredToSpend, KeyCrypter crypter) throws UnreadableWalletException {
        checkArgument(sigsRequiredToSpend > 0);
        checkNotNull(crypter);
        BasicKeyChain basicKeyChain = BasicKeyChain.fromProtobufEncrypted(keys, crypter);
        List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(keys, crypter);
        EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys = null;
        if (!chains.isEmpty())
            currentKeys = createCurrentKeysMap(chains);
        Multimap<DeterministicKey, DeterministicKeyChain> followingKeychains = extractFollowingKeychains(chains);
        if (sigsRequiredToSpend < 2 && followingKeychains.size() > 0)
            throw new IllegalArgumentException("Married KeyChainGroup requires multiple signatures to spend");
        return new KeyChainGroup(params, basicKeyChain, chains, currentKeys, followingKeychains, sigsRequiredToSpend, crypter);
    }

    /**
     * If the key chain contains only random keys and no deterministic key chains, this method will create a chain
     * based on the oldest non-rotating private key (i.e. the seed is derived from the old wallet).
     *
     * @param keyRotationTimeSecs If non-zero, UNIX time for which keys created before this are assumed to be
     *                            compromised or weak, those keys will not be used for deterministic upgrade.
     * @param aesKey If non-null, the encryption key the keychain is encrypted under. If the keychain is encrypted
     *               and this is not supplied, an exception is thrown letting you know you should ask the user for
     *               their password, turn it into a key, and then try again.
     * @throws java.lang.IllegalStateException if there is already a deterministic key chain present or if there are
     *                                         no random keys (i.e. this is not an upgrade scenario), or if aesKey is
     *                                         provided but the wallet is not encrypted.
     * @throws java.lang.IllegalArgumentException if the rotation time specified excludes all keys.
     * @throws DeterministicUpgradeRequiresPassword if the key chain group is encrypted
     *         and you should provide the users encryption key.
     * @return the DeterministicKeyChain that was created by the upgrade.
     */
    public DeterministicKeyChain upgradeToDeterministic(long keyRotationTimeSecs, @Nullable KeyParameter aesKey) throws DeterministicUpgradeRequiresPassword, AllRandomKeysRotating {
        checkState(basic.numKeys() > 0);
        checkArgument(keyRotationTimeSecs >= 0);
        // Subtract one because the key rotation time might have been set to the creation time of the first known good
        // key, in which case, that's the one we want to find.
        ECKey keyToUse = basic.findOldestKeyAfter(keyRotationTimeSecs - 1);
        if (keyToUse == null)
            throw new AllRandomKeysRotating();

        if (keyToUse.isEncrypted()) {
            if (aesKey == null) {
                // We can't auto upgrade because we don't know the users password at this point. We throw an
                // exception so the calling code knows to abort the load and ask the user for their password, they can
                // then try loading the wallet again passing in the AES key.
                //
                // There are a few different approaches we could have used here, but they all suck. The most obvious
                // is to try and be as lazy as possible, running in the old random-wallet mode until the user enters
                // their password for some other reason and doing the upgrade then. But this could result in strange
                // and unexpected UI flows for the user, as well as complicating the job of wallet developers who then
                // have to support both "old" and "new" UI modes simultaneously, switching them on the fly. Given that
                // this is a one-off transition, it seems more reasonable to just ask the user for their password
                // on startup, and then the wallet app can have all the widgets for accessing seed words etc active
                // all the time.
                throw new DeterministicUpgradeRequiresPassword();
            }
            keyToUse = keyToUse.decrypt(aesKey);
        } else if (aesKey != null) {
            throw new IllegalStateException("AES Key was provided but wallet is not encrypted.");
        }

        if (chains.isEmpty()) {
            log.info("Auto-upgrading pre-HD wallet to HD!");
        } else {
            log.info("Wallet with existing HD chain is being re-upgraded due to change in key rotation time.");
        }
        log.info("Instantiating new HD chain using oldest non-rotating private key (address: {})", keyToUse.toAddress(params));
        byte[] entropy = checkNotNull(keyToUse.getSecretBytes());
        // Private keys should be at least 128 bits long.
        checkState(entropy.length >= DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8);
        // We reduce the entropy here to 128 bits because people like to write their seeds down on paper, and 128
        // bits should be sufficient forever unless the laws of the universe change or ECC is broken; in either case
        // we all have bigger problems.
        entropy = Arrays.copyOfRange(entropy, 0, DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8);    // final argument is exclusive range.
        checkState(entropy.length == DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8);
        String passphrase = ""; // FIXME allow non-empty passphrase
        DeterministicKeyChain chain = new DeterministicKeyChain(entropy, passphrase, keyToUse.getCreationTimeSeconds());
        if (aesKey != null) {
            chain = chain.toEncrypted(checkNotNull(basic.getKeyCrypter()), aesKey);
        }
        chains.add(chain);
        return chain;
    }

    /** Returns true if the group contains random keys but no HD chains. */
    public boolean isDeterministicUpgradeRequired() {
        return basic.numKeys() > 0 && chains.isEmpty();
    }

    private static EnumMap<KeyChain.KeyPurpose, DeterministicKey> createCurrentKeysMap(List<DeterministicKeyChain> chains) {
        DeterministicKeyChain activeChain = chains.get(chains.size() - 1);

        EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys = new EnumMap<KeyChain.KeyPurpose, DeterministicKey>(KeyChain.KeyPurpose.class);

        // assuming that only RECEIVE and CHANGE keys are being used at the moment, we will treat latest issued external key
        // as current RECEIVE key and latest issued internal key as CHANGE key. This should be changed as soon as other
        // kinds of KeyPurpose are introduced.
        if (activeChain.getIssuedExternalKeys() > 0) {
            DeterministicKey currentExternalKey = activeChain.getKeyByPath(
                    ImmutableList.of(ChildNumber.ZERO_HARDENED, ChildNumber.ZERO, new ChildNumber(activeChain.getIssuedExternalKeys() - 1))
            );
            currentKeys.put(KeyChain.KeyPurpose.RECEIVE_FUNDS, currentExternalKey);
        }

        if (activeChain.getIssuedInternalKeys() > 0) {
            DeterministicKey currentInternalKey = activeChain.getKeyByPath(
                    ImmutableList.of(ChildNumber.ZERO_HARDENED, new ChildNumber(1), new ChildNumber(activeChain.getIssuedInternalKeys() - 1))
            );
            currentKeys.put(KeyChain.KeyPurpose.CHANGE, currentInternalKey);
        }
        return currentKeys;
    }

    private static Multimap<DeterministicKey, DeterministicKeyChain> extractFollowingKeychains(List<DeterministicKeyChain> chains) {
        // look for following key chains and map them to the watch keys of followed keychains
        Multimap<DeterministicKey, DeterministicKeyChain> followingKeychains = HashMultimap.create();
        List<DeterministicKeyChain> followingChains = new ArrayList<DeterministicKeyChain>();
        for (Iterator<DeterministicKeyChain> it = chains.iterator(); it.hasNext(); ) {
            DeterministicKeyChain chain = it.next();
            if (chain.isFollowing()) {
                followingChains.add(chain);
                it.remove();
            } else if (!followingChains.isEmpty()) {
                followingKeychains.putAll(chain.getWatchingKey(), followingChains);
                followingChains.clear();
            }
        }
        return followingKeychains;
    }

    public String toString(boolean includePrivateKeys) {
        final StringBuilder builder = new StringBuilder();
        if (basic != null) {
            List<ECKey> keys = basic.getKeys();
            Collections.sort(keys, ECKey.AGE_COMPARATOR);
            for (ECKey key : keys)
                formatKeyWithAddress(includePrivateKeys, key, builder);
        }
        List<String> chainStrs = Lists.newLinkedList();
        for (DeterministicKeyChain chain : chains) {
            final StringBuilder builder2 = new StringBuilder();
            DeterministicSeed seed = chain.getSeed();
            if (seed != null) {
                if (seed.isEncrypted()) {
                    builder2.append(String.format("Seed is encrypted%n"));
                } else if (includePrivateKeys) {
                    final List<String> words = seed.getMnemonicCode();
                    builder2.append(
                            String.format("Seed as words: %s%nSeed as hex:   %s%n", Joiner.on(' ').join(words),
                                    seed.toHexString())
                    );
                }
                builder2.append(String.format("Seed birthday: %d  [%s]%n", seed.getCreationTimeSeconds(), new Date(seed.getCreationTimeSeconds() * 1000)));
            }
            final DeterministicKey watchingKey = chain.getWatchingKey();
            // Don't show if it's been imported from a watching wallet already, because it'd result in a weird/
            // unintuitive result where the watching key in a watching wallet is not the one it was created with
            // due to the parent fingerprint being missing/not stored. In future we could store the parent fingerprint
            // optionally as well to fix this, but it seems unimportant for now.
            if (watchingKey.getParent() != null) {
                builder2.append(String.format("Key to watch:  %s%n", watchingKey.serializePubB58()));
            }
            if (isMarried(chain)) {
                Collection<DeterministicKeyChain> followingChains = followingKeychains.get(chain.getWatchingKey());
                for (DeterministicKeyChain followingChain : followingChains) {
                    builder2.append(String.format("Following chain:  %s%n", followingChain.getWatchingKey().serializePubB58()));
                }
                builder2.append(String.format("%n"));
                for (RedeemData redeemData : marriedKeysRedeemData.values())
                    formatScript(ScriptBuilder.createP2SHOutputScript(redeemData.redeemScript), builder2);
            } else {
                for (ECKey key : chain.getKeys(false))
                    formatKeyWithAddress(includePrivateKeys, key, builder2);
            }
            chainStrs.add(builder2.toString());
        }
        builder.append(Joiner.on(String.format("%n")).join(chainStrs));
        return builder.toString();
    }

    private void formatScript(Script script, StringBuilder builder) {
        builder.append("  addr:");
        builder.append(script.getToAddress(params));
        builder.append("  hash160:");
        builder.append(Utils.HEX.encode(script.getPubKeyHash()));
        builder.append("\n");
    }

    private void formatKeyWithAddress(boolean includePrivateKeys, ECKey key, StringBuilder builder) {
        final Address address = key.toAddress(params);
        builder.append("  addr:");
        builder.append(address.toString());
        builder.append("  hash160:");
        builder.append(Utils.HEX.encode(key.getPubKeyHash()));
        if (key instanceof DeterministicKey) {
            builder.append("  (");
            builder.append((((DeterministicKey) key).getPathAsString()));
            builder.append(")");
        }
        builder.append("\n");
        if (includePrivateKeys) {
            builder.append("  ");
            builder.append(key.toStringWithPrivate());
            builder.append("\n");
        }
    }

    /** Returns a copy of the current list of chains. */
    public List<DeterministicKeyChain> getDeterministicKeyChains() {
        return new ArrayList<DeterministicKeyChain>(chains);
    }

    /**
     * Returns the number of signatures required to spend transactions for this KeyChainGroup. It's the N from
     * N-of-M CHECKMULTISIG script for P2SH transactions and always 1 for other transaction types.
     */
    public int getSigsRequiredToSpend() {
        return sigsRequiredToSpend;
    }

    /**
     * Returns a counter that increases (by an arbitrary amount) each time new keys have been calculated due to
     * lookahead and thus the Bloom filter that was previously calculated has become stale.
     */
    public int getCombinedKeyLookaheadEpochs() {
        int epoch = 0;
        for (DeterministicKeyChain chain : chains)
            epoch += chain.getKeyLookaheadEpoch();
        return epoch;
    }
}
