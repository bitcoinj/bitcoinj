/*
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

import com.google.common.collect.*;
import com.google.protobuf.*;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.*;
import org.bitcoinj.script.Script.ScriptType;
import org.bitcoinj.utils.*;
import org.bitcoinj.wallet.listeners.KeyChainEventListener;
import org.slf4j.*;
import org.bouncycastle.crypto.params.*;

import javax.annotation.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A KeyChainGroup is used by the {@link Wallet} and manages: a {@link BasicKeyChain} object
 * (which will normally be empty), and zero or more {@link DeterministicKeyChain}s. The last added
 * deterministic keychain is always the default active keychain, that's the one we normally derive keys and
 * addresses from.</p>
 *
 * <p>There can be active keychains for each output script type. However this class almost entirely only works on
 * the default active keychain (see {@link #getActiveKeyChain()}). The other active keychains
 * (see {@link #getActiveKeyChain(ScriptType, long)}) are meant as fallback for if a sender doesn't understand a
 * certain new script type (e.g. P2WPKH which comes with the new Bech32 address format). Active keychains
 * share the same seed, so that upgrading the wallet
 * (see {@link #upgradeToDeterministic(ScriptType, KeyChainGroupStructure, long, KeyParameter)}) to understand
 * a new script type doesn't require a fresh backup.</p>
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

    /**
     * Builder for {@link KeyChainGroup}. Use {@link KeyChainGroup#builder(NetworkParameters)} to acquire an instance.
     */
    public static class Builder {
        private final NetworkParameters params;
        private final KeyChainGroupStructure structure;
        private final List<DeterministicKeyChain> chains = new LinkedList<>();
        private int lookaheadSize = -1, lookaheadThreshold = -1;

        private Builder(NetworkParameters params, KeyChainGroupStructure structure) {
            this.params = params;
            this.structure = structure;
        }

        /**
         * <p>Add chain from a random source.</p>
         * <p>In the case of P2PKH, just a P2PKH chain is created and activated which is then the default chain for fresh
         * addresses. It can be upgraded to P2WPKH later.</p>
         * <p>In the case of P2WPKH, both a P2PKH and a P2WPKH chain are created and activated, the latter being the default
         * chain. This behaviour will likely be changed with bitcoinj 0.16 such that only a P2WPKH chain is created and
         * activated.</p>
         * @param outputScriptType type of addresses (aka output scripts) to generate for receiving
         */
        public Builder fromRandom(Script.ScriptType outputScriptType) {
            DeterministicSeed seed = new DeterministicSeed(new SecureRandom(),
                    DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS, "");
            fromSeed(seed, outputScriptType);
            return this;
        }

        /**
         * <p>Add chain from a given seed.</p>
         * <p>In the case of P2PKH, just a P2PKH chain is created and activated which is then the default chain for fresh
         * addresses. It can be upgraded to P2WPKH later.</p>
         * <p>In the case of P2WPKH, both a P2PKH and a P2WPKH chain are created and activated, the latter being the default
         * chain. This behaviour will likely be changed with bitcoinj 0.16 such that only a P2WPKH chain is created and
         * activated.</p>
         * @param seed deterministic seed to derive all keys from
         * @param outputScriptType type of addresses (aka output scripts) to generate for receiving
         */
        public Builder fromSeed(DeterministicSeed seed, Script.ScriptType outputScriptType) {
            if (outputScriptType == Script.ScriptType.P2PKH) {
                DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(seed)
                        .outputScriptType(Script.ScriptType.P2PKH)
                        .accountPath(structure.accountPathFor(Script.ScriptType.P2PKH)).build();
                this.chains.clear();
                this.chains.add(chain);
            } else if (outputScriptType == Script.ScriptType.P2WPKH) {
                DeterministicKeyChain fallbackChain = DeterministicKeyChain.builder().seed(seed)
                        .outputScriptType(Script.ScriptType.P2PKH)
                        .accountPath(structure.accountPathFor(Script.ScriptType.P2PKH)).build();
                DeterministicKeyChain defaultChain = DeterministicKeyChain.builder().seed(seed)
                        .outputScriptType(Script.ScriptType.P2WPKH)
                        .accountPath(structure.accountPathFor(Script.ScriptType.P2WPKH)).build();
                this.chains.clear();
                this.chains.add(fallbackChain);
                this.chains.add(defaultChain);
            } else {
                throw new IllegalArgumentException(outputScriptType.toString());
            }
            return this;
        }

        /**
         * Add a single chain.
         * @param chain to add
         */
        public Builder addChain(DeterministicKeyChain chain) {
            this.chains.add(chain);
            return this;
        }

        /**
         * Add multiple chains.
         * @param chains to add
         */
        public Builder chains(List<DeterministicKeyChain> chains) {
            this.chains.clear();
            this.chains.addAll(chains);
            return this;
        }

        /**
         * Set a custom lookahead size for all deterministic chains
         * @param lookaheadSize lookahead size
         */
        public Builder lookaheadSize(int lookaheadSize) {
            this.lookaheadSize = lookaheadSize;
            return this;
        }

        /**
         * Set a custom lookahead threshold for all deterministic chains
         * @param lookaheadThreshold lookahead threshold
         */
        public Builder lookaheadThreshold(int lookaheadThreshold) {
            this.lookaheadThreshold = lookaheadThreshold;
            return this;
        }

        public KeyChainGroup build() {
            return new KeyChainGroup(params, null, chains, lookaheadSize, lookaheadThreshold, null, null);
        }
    }

    static {
        // Init proper random number generator, as some old Android installations have bugs that make it unsecure.
        if (Utils.isAndroidRuntime())
            new LinuxSecureRandom();
    }

    private static final Logger log = LoggerFactory.getLogger(KeyChainGroup.class);

    private BasicKeyChain basic;
    private final NetworkParameters params;
    // Keychains for deterministically derived keys. If this is null, no chains should be created automatically.
    protected final @Nullable LinkedList<DeterministicKeyChain> chains;
    // currentKeys is used for normal, non-multisig/married wallets. currentAddresses is used when we're handing out
    // P2SH addresses. They're mutually exclusive.
    private final EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys;
    private final EnumMap<KeyChain.KeyPurpose, Address> currentAddresses;
    @Nullable private KeyCrypter keyCrypter;
    private int lookaheadSize = -1;
    private int lookaheadThreshold = -1;

    /** Creates a keychain group with just a basic chain. No deterministic chains will be created automatically. */
    public static KeyChainGroup createBasic(NetworkParameters params) {
        return new KeyChainGroup(params, new BasicKeyChain(), null, -1, -1, null, null);
    }

    public static KeyChainGroup.Builder builder(NetworkParameters params) {
        return new Builder(params, KeyChainGroupStructure.DEFAULT);
    }

    public static KeyChainGroup.Builder builder(NetworkParameters params, KeyChainGroupStructure structure) {
        return new Builder(params, structure);
    }

    private KeyChainGroup(NetworkParameters params, @Nullable BasicKeyChain basicKeyChain,
            @Nullable List<DeterministicKeyChain> chains, int lookaheadSize, int lookaheadThreshold,
            @Nullable EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys, @Nullable KeyCrypter crypter) {
        this.params = params;
        this.basic = basicKeyChain == null ? new BasicKeyChain() : basicKeyChain;
        if (chains != null) {
            if (lookaheadSize > -1)
                this.lookaheadSize = lookaheadSize;
            else if (params.getId().equals(NetworkParameters.ID_UNITTESTNET))
                this.lookaheadSize = 5; // Cut down excess computation for unit tests.
            if (lookaheadThreshold > -1)
                this.lookaheadThreshold = lookaheadThreshold;
            this.chains = new LinkedList<>(chains);
            for (DeterministicKeyChain chain : this.chains) {
                if (this.lookaheadSize > -1)
                    chain.setLookaheadSize(this.lookaheadSize);
                if (this.lookaheadThreshold > -1)
                    chain.setLookaheadThreshold(this.lookaheadThreshold);
            }
        } else {
            this.chains = null;
        }
        this.keyCrypter = crypter;
        this.currentKeys = currentKeys == null
                ? new EnumMap<KeyChain.KeyPurpose, DeterministicKey>(KeyChain.KeyPurpose.class)
                : currentKeys;
        this.currentAddresses = new EnumMap<>(KeyChain.KeyPurpose.class);

        if (isMarried()) {
            maybeLookaheadScripts();
            for (Map.Entry<KeyChain.KeyPurpose, DeterministicKey> entry : this.currentKeys.entrySet()) {
                Address address = ScriptBuilder
                        .createP2SHOutputScript(getActiveKeyChain().getRedeemData(entry.getValue()).redeemScript)
                        .getToAddress(params);
                currentAddresses.put(entry.getKey(), address);
            }
        }
    }

    /** Returns true if it contains any deterministic keychain or one could be created. */
    public boolean isSupportsDeterministicChains() {
        return chains != null;
    }

    // This keeps married redeem data in sync with the number of keys issued
    private void maybeLookaheadScripts() {
        for (DeterministicKeyChain chain : chains) {
            chain.maybeLookAheadScripts();
        }
    }

    /**
     * Adds an HD chain to the chains list, and make it the default chain (from which keys are issued).
     * Useful for adding a complex pre-configured keychain, such as a married wallet.
     */
    public void addAndActivateHDChain(DeterministicKeyChain chain) {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        log.info("Activating a new HD chain: {}", chain);
        for (ListenerRegistration<KeyChainEventListener> registration : basic.getListeners())
            chain.addEventListener(registration.listener, registration.executor);
        if (lookaheadSize >= 0)
            chain.setLookaheadSize(lookaheadSize);
        if (lookaheadThreshold >= 0)
            chain.setLookaheadThreshold(lookaheadThreshold);
        chains.add(chain);
        currentKeys.clear();
        currentAddresses.clear();
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
        if (chain.isMarried()) {
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
        Script.ScriptType outputScriptType = chain.getOutputScriptType();
        if (chain.isMarried()) {
            Address current = currentAddresses.get(purpose);
            if (current == null) {
                current = freshAddress(purpose);
                currentAddresses.put(purpose, current);
            }
            return current;
        } else if (outputScriptType == Script.ScriptType.P2PKH || outputScriptType == Script.ScriptType.P2WPKH) {
            return Address.fromKey(params, currentKey(purpose), outputScriptType);
        } else {
            throw new IllegalStateException(chain.getOutputScriptType().toString());
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
        if (chain.isMarried()) {
            throw new UnsupportedOperationException("Key is not suitable to receive coins for married keychains." +
                    " Use freshAddress to get P2SH address instead");
        }
        return chain.getKeys(purpose, numberOfKeys);   // Always returns the next key along the key chain.
    }

    /**
     * <p>Returns a fresh address for a given {@link KeyChain.KeyPurpose} and of a given
     * {@link Script.ScriptType}.</p>
     * <p>This method is meant for when you really need a fallback address. Normally, you should be
     * using {@link #freshAddress(KeyChain.KeyPurpose)} or
     * {@link #currentAddress(KeyChain.KeyPurpose)}.</p>
     */
    public Address freshAddress(KeyChain.KeyPurpose purpose, Script.ScriptType outputScriptType, long keyRotationTimeSecs) {
        DeterministicKeyChain chain = getActiveKeyChain(outputScriptType, keyRotationTimeSecs);
        return Address.fromKey(params, chain.getKey(purpose), outputScriptType);
    }

    /**
     * Returns address for a {@link #freshKey(KeyChain.KeyPurpose)}
     */
    public Address freshAddress(KeyChain.KeyPurpose purpose) {
        DeterministicKeyChain chain = getActiveKeyChain();
        Script.ScriptType outputScriptType = chain.getOutputScriptType();
        if (chain.isMarried()) {
            Script outputScript = chain.freshOutputScript(purpose);
            checkState(ScriptPattern.isP2SH(outputScript)); // Only handle P2SH for now
            Address freshAddress = LegacyAddress.fromScriptHash(params,
                    ScriptPattern.extractHashFromP2SH(outputScript));
            maybeLookaheadScripts();
            currentAddresses.put(purpose, freshAddress);
            return freshAddress;
        } else if (outputScriptType == Script.ScriptType.P2PKH || outputScriptType == Script.ScriptType.P2WPKH) {
            return Address.fromKey(params, freshKey(purpose), outputScriptType);
        } else {
            throw new IllegalStateException(chain.getOutputScriptType().toString());
        }
    }

    /**
     * Returns the key chains that are used for generation of fresh/current keys, in the order of how they
     * were added. The default active chain will come last in the list.
     */
    public List<DeterministicKeyChain> getActiveKeyChains(long keyRotationTimeSecs) {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        List<DeterministicKeyChain> activeChains = new LinkedList<>();
        for (DeterministicKeyChain chain : chains)
            if (chain.getEarliestKeyCreationTime() >= keyRotationTimeSecs)
                activeChains.add(chain);
        return activeChains;
    }

    /**
     * Returns the key chain that's used for generation of fresh/current keys of the given type. If it's not the default
     * type and no active chain for this type exists, {@code null} is returned. No upgrade or downgrade is tried.
     */
    public final DeterministicKeyChain getActiveKeyChain(Script.ScriptType outputScriptType, long keyRotationTimeSecs) {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        for (DeterministicKeyChain chain : ImmutableList.copyOf(chains).reverse())
            if (chain.getOutputScriptType() == outputScriptType
                    && chain.getEarliestKeyCreationTime() >= keyRotationTimeSecs)
                return chain;
        return null;
    }

    /**
     * Returns the key chain that's used for generation of default fresh/current keys. This is always the newest
     * deterministic chain. If no deterministic chain is present but imported keys instead, a deterministic upgrate is
     * tried.
     */
    public final DeterministicKeyChain getActiveKeyChain() {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        if (chains.isEmpty())
            throw new DeterministicUpgradeRequiredException();
        return chains.get(chains.size() - 1);
    }

    /**
     * Merge all active chains from the given keychain group into this keychain group.
     */
    public final void mergeActiveKeyChains(KeyChainGroup from, long keyRotationTimeSecs) {
        checkArgument(isEncrypted() == from.isEncrypted(), "encrypted and non-encrypted keychains cannot be mixed");
        for (DeterministicKeyChain chain : from.getActiveKeyChains(keyRotationTimeSecs))
            addAndActivateHDChain(chain);
    }

    /**
     * Gets the current lookahead size being used for ALL deterministic key chains. See
     * {@link DeterministicKeyChain#setLookaheadSize(int)}
     * for more information.
     */
    public int getLookaheadSize() {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        if (lookaheadSize == -1)
            return getActiveKeyChain().getLookaheadSize();
        else
            return lookaheadSize;
    }

    /**
     * Gets the current lookahead threshold being used for ALL deterministic key chains. See
     * {@link DeterministicKeyChain#setLookaheadThreshold(int)}
     * for more information.
     */
    public int getLookaheadThreshold() {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
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

    @Override
    @Nullable
    public RedeemData findRedeemDataFromScriptHash(byte[] scriptHash) {
        if (chains != null) {
            // Iterate in reverse order, since the active keychain is the one most likely to have the hit
            for (Iterator<DeterministicKeyChain> iter = chains.descendingIterator(); iter.hasNext();) {
                DeterministicKeyChain chain = iter.next();
                RedeemData redeemData = chain.findRedeemDataByScriptHash(ByteString.copyFrom(scriptHash));
                if (redeemData != null)
                    return redeemData;
            }
        }
        return null;
    }

    public void markP2SHAddressAsUsed(LegacyAddress address) {
        checkArgument(address.getOutputScriptType() == ScriptType.P2SH);
        RedeemData data = findRedeemDataFromScriptHash(address.getHash());
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
    public ECKey findKeyFromPubKeyHash(byte[] pubKeyHash, @Nullable Script.ScriptType scriptType) {
        ECKey result;
        // BasicKeyChain can mix output script types.
        if ((result = basic.findKeyFromPubHash(pubKeyHash)) != null)
            return result;
        if (chains != null) {
            for (DeterministicKeyChain chain : chains) {
                // This check limits DeterministicKeyChain to specific output script usage.
                if (scriptType != null && scriptType != chain.getOutputScriptType())
                    continue;
                if ((result = chain.findKeyFromPubHash(pubKeyHash)) != null)
                    return result;
            }
        }
        return null;
    }

    /**
     * Mark the DeterministicKeys as used, if they match the pubKeyHash
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    public void markPubKeyHashAsUsed(byte[] pubKeyHash) {
        if (chains != null) {
            for (DeterministicKeyChain chain : chains) {
                DeterministicKey key;
                if ((key = chain.markPubHashAsUsed(pubKeyHash)) != null) {
                    maybeMarkCurrentKeyAsUsed(key);
                    return;
                }
            }
        }
    }

    /** If the given P2SH address is "current", advance it to a new one. */
    private void maybeMarkCurrentAddressAsUsed(LegacyAddress address) {
        checkArgument(address.getOutputScriptType() == ScriptType.P2SH);
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
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                if (chain.hasKey(key))
                    return true;
        return false;
    }

    @Nullable
    @Override
    public ECKey findKeyFromPubKey(byte[] pubKey) {
        ECKey result;
        if ((result = basic.findKeyFromPubKey(pubKey)) != null)
            return result;
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                if ((result = chain.findKeyFromPubKey(pubKey)) != null)
                    return result;
        return null;
    }

    /**
     * Mark the DeterministicKeys as used, if they match the pubkey
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    public void markPubKeyAsUsed(byte[] pubkey) {
        if (chains != null) {
            for (DeterministicKeyChain chain : chains) {
                DeterministicKey key;
                if ((key = chain.markPubKeyAsUsed(pubkey)) != null) {
                    maybeMarkCurrentKeyAsUsed(key);
                    return;
                }
            }
        }
    }

    /** Returns the number of keys managed by this group, including the lookahead buffers. */
    public int numKeys() {
        int result = basic.numKeys();
        if (chains != null)
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
     * Whether the active keychain is married.  A keychain is married when it vends P2SH addresses
     * from multiple keychains in a multisig relationship.
     * @see org.bitcoinj.wallet.MarriedKeyChain
     */
    public final boolean isMarried() {
        return chains != null && !chains.isEmpty() && getActiveKeyChain().isMarried();
    }

    /**
     * Encrypt the keys in the group using the KeyCrypter and the AES key. A good default KeyCrypter to use is
     * {@link KeyCrypterScrypt}.
     *
     * @throws org.bitcoinj.crypto.KeyCrypterException Thrown if the wallet encryption fails for some reason,
     *         leaving the group unchanged.
     * @throws DeterministicUpgradeRequiredException Thrown if there are random keys but no HD chain.
     */
    public void encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        checkNotNull(keyCrypter);
        checkNotNull(aesKey);
        checkState((chains != null && !chains.isEmpty()) || basic.numKeys() != 0, "can't encrypt entirely empty wallet");

        BasicKeyChain newBasic = basic.toEncrypted(keyCrypter, aesKey);
        List<DeterministicKeyChain> newChains = new ArrayList<>();
        if (chains != null) {
            for (DeterministicKeyChain chain : chains)
                newChains.add(chain.toEncrypted(keyCrypter, aesKey));
        }

        // Code below this point must be exception safe.
        this.keyCrypter = keyCrypter;
        this.basic = newBasic;
        if (chains != null) {
            this.chains.clear();
            this.chains.addAll(newChains);
        }
    }

    /**
     * Decrypt the keys in the group using the previously given key crypter and the AES key. A good default
     * KeyCrypter to use is {@link KeyCrypterScrypt}.
     *
     * @throws org.bitcoinj.crypto.KeyCrypterException Thrown if the wallet decryption fails for some reason, leaving the group unchanged.
     */
    public void decrypt(KeyParameter aesKey) {
        checkNotNull(aesKey);

        BasicKeyChain newBasic = basic.toDecrypted(aesKey);
        if (chains != null) {
            List<DeterministicKeyChain> newChains = new ArrayList<>(chains.size());
            for (DeterministicKeyChain chain : chains)
                newChains.add(chain.toDecrypted(aesKey));

            // Code below this point must be exception safe.
            this.chains.clear();
            this.chains.addAll(newChains);
        }
        this.basic = newBasic;
        this.keyCrypter = null;
    }

    /** Returns true if the group is encrypted. */
    public boolean isEncrypted() {
        return keyCrypter != null;
    }

    /**
     * Returns whether this chain has only watching keys (unencrypted keys with no private part). Mixed chains are
     * forbidden.
     * 
     * @throws IllegalStateException if there are no keys, or if there is a mix between watching and non-watching keys.
     */
    public boolean isWatching() {
        BasicKeyChain.State basicState = basic.isWatching();
        BasicKeyChain.State activeState = BasicKeyChain.State.EMPTY;
        if (chains != null && !chains.isEmpty()) {
            if (getActiveKeyChain().isWatching())
                activeState = BasicKeyChain.State.WATCHING;
            else
                activeState = BasicKeyChain.State.REGULAR;
        }
        if (basicState == BasicKeyChain.State.EMPTY) {
            if (activeState == BasicKeyChain.State.EMPTY)
                throw new IllegalStateException("Empty key chain group: cannot answer isWatching() query");
            return activeState == BasicKeyChain.State.WATCHING;
        } else if (activeState == BasicKeyChain.State.EMPTY)
            return basicState == BasicKeyChain.State.WATCHING;
        else {
            if (activeState != basicState)
                throw new IllegalStateException("Mix of watching and non-watching keys in wallet");
            return activeState == BasicKeyChain.State.WATCHING;
        }
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
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                time = Math.min(time, chain.getEarliestKeyCreationTime());
        return time;
    }

    public int getBloomFilterElementCount() {
        int result = basic.numBloomFilterEntries();
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                result += chain.numBloomFilterEntries();
        return result;
    }

    public BloomFilter getBloomFilter(int size, double falsePositiveRate, long nTweak) {
        BloomFilter filter = new BloomFilter(size, falsePositiveRate, nTweak);
        if (basic.numKeys() > 0)
            filter.merge(basic.getFilter(size, falsePositiveRate, nTweak));
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                filter.merge(chain.getFilter(size, falsePositiveRate, nTweak));
        return filter;
    }

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
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                chain.addEventListener(listener, executor);
    }

    /** Removes a listener for events that are run when keys are added. */
    public boolean removeEventListener(KeyChainEventListener listener) {
        checkNotNull(listener);
        if (chains != null)
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
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                result.addAll(chain.serializeToProtobuf());
        return result;
    }

    static KeyChainGroup fromProtobufUnencrypted(NetworkParameters params, List<Protos.Key> keys) throws UnreadableWalletException {
        return fromProtobufUnencrypted(params, keys, new DefaultKeyChainFactory());
    }

    public static KeyChainGroup fromProtobufUnencrypted(NetworkParameters params, List<Protos.Key> keys, KeyChainFactory factory) throws UnreadableWalletException {
        BasicKeyChain basicKeyChain = BasicKeyChain.fromProtobufUnencrypted(keys);
        List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(keys, null, factory);
        int lookaheadSize = -1, lookaheadThreshold = -1;
        EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys = null;
        if (!chains.isEmpty()) {
            DeterministicKeyChain activeChain = chains.get(chains.size() - 1);
            lookaheadSize = activeChain.getLookaheadSize();
            lookaheadThreshold = activeChain.getLookaheadThreshold();
            currentKeys = createCurrentKeysMap(chains);
        }
        extractFollowingKeychains(chains);
        return new KeyChainGroup(params, basicKeyChain, chains, lookaheadSize, lookaheadThreshold, currentKeys, null);
    }

    static KeyChainGroup fromProtobufEncrypted(NetworkParameters params, List<Protos.Key> keys, KeyCrypter crypter) throws UnreadableWalletException {
        return fromProtobufEncrypted(params, keys, crypter, new DefaultKeyChainFactory());
    }

    public static KeyChainGroup fromProtobufEncrypted(NetworkParameters params, List<Protos.Key> keys, KeyCrypter crypter, KeyChainFactory factory) throws UnreadableWalletException {
        checkNotNull(crypter);
        BasicKeyChain basicKeyChain = BasicKeyChain.fromProtobufEncrypted(keys, crypter);
        List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(keys, crypter, factory);
        int lookaheadSize = -1, lookaheadThreshold = -1;
        EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys = null;
        if (!chains.isEmpty()) {
            DeterministicKeyChain activeChain = chains.get(chains.size() - 1);
            lookaheadSize = activeChain.getLookaheadSize();
            lookaheadThreshold = activeChain.getLookaheadThreshold();
            currentKeys = createCurrentKeysMap(chains);
        }
        extractFollowingKeychains(chains);
        return new KeyChainGroup(params, basicKeyChain, chains, lookaheadSize, lookaheadThreshold, currentKeys, crypter);
    }

    /**
     * <p>This method will upgrade the wallet along the following path: {@code Basic --> P2PKH --> P2WPKH}</p>
     * <p>It won't skip any steps in that upgrade path because the user might be restoring from a backup and
     * still expects money on the P2PKH chain.</p>
     * <p>It will extract and reuse the seed from the current wallet, so that a fresh backup isn't required
     * after upgrading. If coming from a basic chain containing only random keys this means it will pick the
     * oldest non-rotating private key as a seed.</p>
     * <p>Note that for upgrading an encrypted wallet, the decryption key is needed. In future, we could skip
     * that requirement for a {@code P2PKH --> P2WPKH} upgrade and just clone the encryped seed, but currently
     * the key is needed even for that.</p>
     *
     * @param preferredScriptType desired script type for the active keychain
     * @param structure keychain group structure to derive an account path from
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
     */
    public void upgradeToDeterministic(Script.ScriptType preferredScriptType, KeyChainGroupStructure structure,
            long keyRotationTimeSecs, @Nullable KeyParameter aesKey)
            throws DeterministicUpgradeRequiresPassword, AllRandomKeysRotating {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        checkNotNull(structure);
        checkArgument(keyRotationTimeSecs >= 0);
        if (!isDeterministicUpgradeRequired(preferredScriptType, keyRotationTimeSecs))
            return; // Nothing to do.

        // Basic --> P2PKH upgrade
        if (basic.numKeys() > 0 && getActiveKeyChain(Script.ScriptType.P2PKH, keyRotationTimeSecs) == null) {
            // Subtract one because the key rotation time might have been set to the creation time of the first known good
            // key, in which case, that's the one we want to find.
            ECKey keyToUse = basic.findOldestKeyAfter(keyRotationTimeSecs - 1);
            if (keyToUse == null)
                throw new AllRandomKeysRotating();
            boolean keyWasEncrypted = keyToUse.isEncrypted();
            if (keyWasEncrypted) {
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

            log.info(
                    "Upgrading from basic keychain to P2PKH deterministic keychain. Using oldest non-rotating private key (address: {})",
                    LegacyAddress.fromKey(params, keyToUse));
            byte[] entropy = checkNotNull(keyToUse.getSecretBytes());
            // Private keys should be at least 128 bits long.
            checkState(entropy.length >= DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8);
            // We reduce the entropy here to 128 bits because people like to write their seeds down on paper, and 128
            // bits should be sufficient forever unless the laws of the universe change or ECC is broken; in either case
            // we all have bigger problems.
            entropy = Arrays.copyOfRange(entropy, 0, DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8);    // final argument is exclusive range.
            checkState(entropy.length == DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8);
            DeterministicKeyChain chain = DeterministicKeyChain.builder()
                    .entropy(entropy, keyToUse.getCreationTimeSeconds())
                    .outputScriptType(Script.ScriptType.P2PKH)
                    .accountPath(structure.accountPathFor(Script.ScriptType.P2PKH)).build();
            if (keyWasEncrypted)
                chain = chain.toEncrypted(checkNotNull(keyCrypter), aesKey);
            addAndActivateHDChain(chain);
        }

        // P2PKH --> P2WPKH upgrade
        if (preferredScriptType == Script.ScriptType.P2WPKH
                && getActiveKeyChain(Script.ScriptType.P2WPKH, keyRotationTimeSecs) == null) {
            DeterministicSeed seed = getActiveKeyChain(Script.ScriptType.P2PKH, keyRotationTimeSecs).getSeed();
            boolean seedWasEncrypted = seed.isEncrypted();
            if (seedWasEncrypted) {
                if (aesKey == null)
                    throw new DeterministicUpgradeRequiresPassword();
                seed = seed.decrypt(keyCrypter, "", aesKey);
            }
            log.info("Upgrading from P2PKH to P2WPKH deterministic keychain. Using seed: {}", seed);
            DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(seed)
                    .outputScriptType(Script.ScriptType.P2WPKH)
                    .accountPath(structure.accountPathFor(Script.ScriptType.P2WPKH)).build();
            if (seedWasEncrypted)
                chain = chain.toEncrypted(checkNotNull(keyCrypter), aesKey);
            addAndActivateHDChain(chain);
        }
    }

    /**
     * Returns true if a call to {@link #upgradeToDeterministic(ScriptType, KeyChainGroupStructure, long, KeyParameter)} is required
     * in order to have an active deterministic keychain of the desired script type.
     */
    public boolean isDeterministicUpgradeRequired(Script.ScriptType preferredScriptType, long keyRotationTimeSecs) {
        if (!isSupportsDeterministicChains())
            return false;
        if (getActiveKeyChain(preferredScriptType, keyRotationTimeSecs) == null)
            return true;
        return false;
    }

    private static EnumMap<KeyChain.KeyPurpose, DeterministicKey> createCurrentKeysMap(List<DeterministicKeyChain> chains) {
        DeterministicKeyChain activeChain = chains.get(chains.size() - 1);

        EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys = new EnumMap<>(KeyChain.KeyPurpose.class);

        // assuming that only RECEIVE and CHANGE keys are being used at the moment, we will treat latest issued external key
        // as current RECEIVE key and latest issued internal key as CHANGE key. This should be changed as soon as other
        // kinds of KeyPurpose are introduced.
        if (activeChain.getIssuedExternalKeys() > 0) {
            DeterministicKey currentExternalKey = activeChain.getKeyByPath(
                    HDUtils.append(
                            HDUtils.concat(activeChain.getAccountPath(), DeterministicKeyChain.EXTERNAL_SUBPATH),
                            new ChildNumber(activeChain.getIssuedExternalKeys() - 1)));
            currentKeys.put(KeyChain.KeyPurpose.RECEIVE_FUNDS, currentExternalKey);
        }

        if (activeChain.getIssuedInternalKeys() > 0) {
            DeterministicKey currentInternalKey = activeChain.getKeyByPath(
                    HDUtils.append(
                            HDUtils.concat(activeChain.getAccountPath(), DeterministicKeyChain.INTERNAL_SUBPATH),
                            new ChildNumber(activeChain.getIssuedInternalKeys() - 1)));
            currentKeys.put(KeyChain.KeyPurpose.CHANGE, currentInternalKey);
        }
        return currentKeys;
    }

    private static void extractFollowingKeychains(List<DeterministicKeyChain> chains) {
        // look for following key chains and map them to the watch keys of followed keychains
        List<DeterministicKeyChain> followingChains = Lists.newArrayList();
        for (Iterator<DeterministicKeyChain> it = chains.iterator(); it.hasNext(); ) {
            DeterministicKeyChain chain = it.next();
            if (chain.isFollowing()) {
                followingChains.add(chain);
                it.remove();
            } else if (!followingChains.isEmpty()) {
                if (!(chain instanceof MarriedKeyChain))
                    throw new IllegalStateException();
                ((MarriedKeyChain)chain).setFollowingKeyChains(followingChains);
                followingChains = Lists.newArrayList();
            }
        }
    }

    public String toString(boolean includeLookahead, boolean includePrivateKeys, @Nullable KeyParameter aesKey) {
        final StringBuilder builder = new StringBuilder();
        if (basic != null)
            builder.append(basic.toString(includePrivateKeys, aesKey, params));
        if (chains != null)
            for (DeterministicKeyChain chain : chains)
                builder.append(chain.toString(includeLookahead, includePrivateKeys, aesKey, params)).append('\n');
        return builder.toString();
    }

    /** Returns a copy of the current list of chains. */
    public List<DeterministicKeyChain> getDeterministicKeyChains() {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        return new ArrayList<>(chains);
    }
    /**
     * Returns a counter that increases (by an arbitrary amount) each time new keys have been calculated due to
     * lookahead and thus the Bloom filter that was previously calculated has become stale.
     */
    public int getCombinedKeyLookaheadEpochs() {
        checkState(isSupportsDeterministicChains(), "doesn't support deterministic chains");
        int epoch = 0;
        for (DeterministicKeyChain chain : chains)
            epoch += chain.getKeyLookaheadEpoch();
        return epoch;
    }
}
