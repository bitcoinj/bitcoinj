/*
 * Copyright by the original author or authors.
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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;

import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A multi-signature keychain using synchronized HD keys (a.k.a HDM)</p>
 * <p>This keychain keeps track of following keychains that follow the account key of this keychain.
 * You can get P2SH addresses to receive coins to from this chain. The threshold - sigsRequiredToSpend
 * specifies how many signatures required to spend transactions for this married keychain. This value should not exceed
 * total number of keys involved (one followed key plus number of following keys), otherwise IllegalArgumentException
 * will be thrown.</p>
 * <p>IMPORTANT: As of Bitcoin Core 0.9 all bare (non-P2SH) multisig transactions which require more than 3 public keys are non-standard
 * and such spends won't be processed by peers with default settings, essentially making such transactions almost
 * nonspendable</p>
 * <p>This method will throw an IllegalStateException, if the keychain is already married or already has leaf keys
 * issued.</p>
 */
public class MarriedKeyChain extends DeterministicKeyChain {
    // The map holds P2SH redeem script and corresponding ECKeys issued by this KeyChainGroup (including lookahead)
    // mapped to redeem script hashes.
    private LinkedHashMap<ByteString, RedeemData> marriedKeysRedeemData = new LinkedHashMap<>();

    private List<DeterministicKeyChain> followingKeyChains;

    /** Builds a {@link MarriedKeyChain} */
    public static class Builder<T extends Builder<T>> extends DeterministicKeyChain.Builder<T> {
        private List<DeterministicKey> followingKeys;
        private int threshold;

        protected Builder() {
        }

        public T followingKeys(List<DeterministicKey> followingKeys) {
            this.followingKeys = followingKeys;
            return self();
        }

        public T followingKeys(DeterministicKey followingKey, DeterministicKey ...followingKeys) {
            this.followingKeys = Lists.asList(followingKey, followingKeys);
            return self();
        }

        /**
         * <p>Threshold, or {@code (followingKeys.size() + 1) / 2 + 1)} (majority) if unspecified.</p>
         * <p>IMPORTANT: As of Bitcoin Core 0.9 all multisig transactions which require more than 3 public keys are non-standard
         * and such spends won't be processed by peers with default settings, essentially making such transactions almost
         * nonspendable</p>
         */
        public T threshold(int threshold) {
            this.threshold = threshold;
            return self();
        }

        @Override
        public MarriedKeyChain build() {
            checkNotNull(followingKeys, "followingKeys must be provided");

            if (threshold == 0)
                threshold = (followingKeys.size() + 1) / 2 + 1;
            if (accountPath == null)
                accountPath = ACCOUNT_ZERO_PATH;

            MarriedKeyChain chain;
            if (random != null)
                chain = new MarriedKeyChain(new DeterministicSeed(random, bits, getPassphrase()), null, outputScriptType, accountPath);
            else if (entropy != null)
                chain = new MarriedKeyChain(new DeterministicSeed(entropy, getPassphrase(), creationTimeSecs), null,
                        outputScriptType, accountPath);
            else if (seed != null)
                chain = new MarriedKeyChain(seed, null, outputScriptType, accountPath);
            else if (watchingKey != null)
                chain = new MarriedKeyChain(watchingKey, outputScriptType);
            else
                throw new IllegalStateException();
            chain.addFollowingAccountKeys(followingKeys, threshold);
            return chain;
        }
    }

    public static Builder<?> builder() {
        return new Builder();
    }

    /**
     * This constructor is not stable across releases! If you need a stable API, use {@link #builder()} to use a
     * {@link Builder}.
     */
    protected MarriedKeyChain(DeterministicKey accountKey, Script.ScriptType outputScriptType) {
        super(accountKey, false, true, outputScriptType);
    }

    /**
     * This constructor is not stable across releases! If you need a stable API, use {@link #builder()} to use a
     * {@link Builder}.
     */
    protected MarriedKeyChain(DeterministicSeed seed, KeyCrypter crypter, Script.ScriptType outputScriptType, List<ChildNumber> accountPath) {
        super(seed, crypter, outputScriptType, accountPath);
    }

    void setFollowingKeyChains(List<DeterministicKeyChain> followingKeyChains) {
        checkArgument(!followingKeyChains.isEmpty());
        this.followingKeyChains = followingKeyChains;
    }

    @Override
    public boolean isMarried() {
        return true;
    }

    /** Create a new married key and return the matching output script */
    @Override
    public Script freshOutputScript(KeyPurpose purpose) {
        DeterministicKey followedKey = getKey(purpose);
        ImmutableList.Builder<ECKey> keys = ImmutableList.<ECKey>builder().add(followedKey);
        for (DeterministicKeyChain keyChain : followingKeyChains) {
            DeterministicKey followingKey = keyChain.getKey(purpose);
            checkState(followedKey.getChildNumber().equals(followingKey.getChildNumber()), "Following keychains should be in sync");
            keys.add(followingKey);
        }
        List<ECKey> marriedKeys = keys.build();
        Script redeemScript = ScriptBuilder.createRedeemScript(sigsRequiredToSpend, marriedKeys);
        return ScriptBuilder.createP2SHOutputScript(redeemScript);
    }

    private List<ECKey> getMarriedKeysWithFollowed(DeterministicKey followedKey) {
        ImmutableList.Builder<ECKey> keys = ImmutableList.builder();
        for (DeterministicKeyChain keyChain : followingKeyChains) {
            keyChain.maybeLookAhead();
            keys.add(keyChain.getKeyByPath(followedKey.getPath()));
        }
        keys.add(followedKey);
        return keys.build();
    }

    /** Get the redeem data for a key in this married chain */
    @Override
    public RedeemData getRedeemData(DeterministicKey followedKey) {
        List<ECKey> marriedKeys = getMarriedKeysWithFollowed(followedKey);
        Script redeemScript = ScriptBuilder.createRedeemScript(sigsRequiredToSpend, marriedKeys);
        return RedeemData.of(marriedKeys, redeemScript);
    }

    private void addFollowingAccountKeys(List<DeterministicKey> followingAccountKeys, int sigsRequiredToSpend) {
        checkArgument(sigsRequiredToSpend <= followingAccountKeys.size() + 1, "Multisig threshold can't exceed total number of keys");
        checkState(numLeafKeysIssued() == 0, "Active keychain already has keys in use");
        checkState(followingKeyChains == null);

        List<DeterministicKeyChain> followingKeyChains = new ArrayList<>();

        for (DeterministicKey key : followingAccountKeys) {
            checkArgument(key.getPath().size() == getAccountPath().size(), "Following keys have to be account keys");
            DeterministicKeyChain chain = DeterministicKeyChain.builder().watchAndFollow(key)
                    .outputScriptType(getOutputScriptType()).build();
            if (lookaheadSize >= 0)
                chain.setLookaheadSize(lookaheadSize);
            if (lookaheadThreshold >= 0)
                chain.setLookaheadThreshold(lookaheadThreshold);
            followingKeyChains.add(chain);
        }

        this.sigsRequiredToSpend = sigsRequiredToSpend;
        this.followingKeyChains = followingKeyChains;
    }

    @Override
    public void setLookaheadSize(int lookaheadSize) {
        lock.lock();
        try {
            super.setLookaheadSize(lookaheadSize);
            if (followingKeyChains != null) {
                for (DeterministicKeyChain followingChain : followingKeyChains) {
                    followingChain.setLookaheadSize(lookaheadSize);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<Protos.Key> serializeToProtobuf() {
        List<Protos.Key> result = new ArrayList<>();
        lock.lock();
        try {
            for (DeterministicKeyChain chain : followingKeyChains) {
                result.addAll(chain.serializeMyselfToProtobuf());
            }
            result.addAll(serializeMyselfToProtobuf());
        } finally {
            lock.unlock();
        }
        return result;
    }

    @Override
    protected void formatAddresses(boolean includeLookahead, boolean includePrivateKeys, @Nullable KeyParameter aesKey,
            NetworkParameters params, StringBuilder builder) {
        for (DeterministicKeyChain followingChain : followingKeyChains)
            builder.append("Following chain:  ").append(followingChain.getWatchingKey().serializePubB58(params))
                    .append('\n');
        builder.append('\n');
        for (RedeemData redeemData : marriedKeysRedeemData.values())
            formatScript(ScriptBuilder.createP2SHOutputScript(redeemData.redeemScript), builder, params);
    }

    private void formatScript(Script script, StringBuilder builder, NetworkParameters params) {
        builder.append("  addr:");
        builder.append(script.getToAddress(params));
        builder.append("  hash160:");
        builder.append(Utils.HEX.encode(script.getPubKeyHash()));
        if (script.getCreationTimeSeconds() > 0)
            builder.append("  creationTimeSeconds:").append(script.getCreationTimeSeconds());
        builder.append('\n');
    }

    @Override
    public void maybeLookAheadScripts() {
        super.maybeLookAheadScripts();
        int numLeafKeys = getLeafKeys().size();

        checkState(marriedKeysRedeemData.size() <= numLeafKeys, "Number of scripts is greater than number of leaf keys");
        if (marriedKeysRedeemData.size() == numLeafKeys)
            return;

        maybeLookAhead();
        for (DeterministicKey followedKey : getLeafKeys()) {
            RedeemData redeemData = getRedeemData(followedKey);
            Script scriptPubKey = ScriptBuilder.createP2SHOutputScript(redeemData.redeemScript);
            marriedKeysRedeemData.put(ByteString.copyFrom(scriptPubKey.getPubKeyHash()), redeemData);
        }
    }

    @Nullable
    @Override
    public RedeemData findRedeemDataByScriptHash(ByteString bytes) {
        return marriedKeysRedeemData.get(bytes);
    }

    @Override
    public BloomFilter getFilter(int size, double falsePositiveRate, long tweak) {
        lock.lock();
        BloomFilter filter;
        try {
            filter = new BloomFilter(size, falsePositiveRate, tweak);
            for (Map.Entry<ByteString, RedeemData> entry : marriedKeysRedeemData.entrySet()) {
                filter.insert(entry.getKey().toByteArray());
                filter.insert(entry.getValue().redeemScript.getProgram());
            }
        } finally {
            lock.unlock();
        }
        return filter;
    }

    @Override
    public int numBloomFilterEntries() {
        maybeLookAhead();
        return getLeafKeys().size() * 2;
    }
}
