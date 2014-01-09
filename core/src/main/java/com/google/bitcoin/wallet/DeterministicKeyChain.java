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
import com.google.bitcoin.utils.Threading;
import com.google.common.collect.ImmutableList;
import org.bitcoinj.wallet.Protos;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;

/**
 * <p>A deterministic key chain is a {@link KeyChain} that uses the BIP 32
 * {@link com.google.bitcoin.crypto.DeterministicHierarchy} to derive all the keys in the keychain from a master seed.
 * This type of wallet is extremely convenient and flexible. Although backing up full wallet files is always a good
 * idea, to recover money only the root seed needs to be preserved and that is a number small enough that it can be
 * written down on paper or, when represented using a BIP 39 {@link com.google.bitcoin.crypto.MnemonicCode},
 * dictated over the phone (possibly even memorized).</p>
 *
 * <p>Deterministic key chains have other advantages: parts of the key tree can be selectively revealed to allow
 * for auditing, and new public keys can be generated without access to the private keys, yielding a highly secure
 * configuration for web servers which can accept payments into a wallet but not spend from them.</p>
 */
public class DeterministicKeyChain implements KeyChain {
    private static final Logger log = LoggerFactory.getLogger(DeterministicKeyChain.class);
    private final ReentrantLock lock = Threading.lock("DeterministicKeyChain");

    private final DeterministicHierarchy hierarchy;
    private final DeterministicKey rootKey;
    private final byte[] seed;
    private final long seedCreationTimeSecs;  // Seconds since the epoch.
    private WeakReference<MnemonicCode> mnemonicCode;

    // Paths through the key tree. External keys are ones that are communicated to other parties. Internal keys are
    // keys created for change addresses, coinbases, mixing, etc - anything that isn't communicated. The distinction
    // is somewhat arbitrary but can be useful for audits.
    private final ImmutableList<ChildNumber> externalPath, internalPath;
    // How many keys have been issued on each path.
    private int externalCount, internalCount;

    // We simplify by wrapping a basic key chain and that way we get some functionality like key lookup and event
    // listeners "for free".
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
        this.seed = seed;
        this.seedCreationTimeSecs = seedCreationTimeSecs;
        rootKey = HDKeyDerivation.createMasterPrivateKey(seed);
        hierarchy = new DeterministicHierarchy(rootKey);
        basicKeyChain = new BasicKeyChain();
        // The first number is the "account number" but we don't use that feature.
        externalPath = ImmutableList.of(new ChildNumber(0, true), new ChildNumber(0, true));
        internalPath = ImmutableList.of(new ChildNumber(0, true), new ChildNumber(1, true));
    }

    /** Returns a list of words that represent the seed. */
    public List<String> toMnemonicCode() {
        try {
            return toMnemonicCode(getCachedMnemonicCode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns a list of words that represent the seed. */
    public List<String> toMnemonicCode(MnemonicCode code) {
        try {
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

    /** Returns the time in seconds since the UNIX epoch at which the seed was randomly generated. */
    public long getSeedCreationTimeSecs() {
        return seedCreationTimeSecs;
    }

    @Override
    public ECKey getKey(KeyPurpose purpose) {
        lock.lock();
        try {
            ImmutableList<ChildNumber> path;
            if (purpose == KeyPurpose.RECEIVE_FUNDS) {
                path = externalPath;
                externalCount++;
            } else if (purpose == KeyPurpose.CHANGE) {
                path = internalPath;
                internalCount++;
            } else
                throw new IllegalArgumentException("Unknown key purpose " + purpose);
            DeterministicKey key = hierarchy.deriveNextChild(path, true, true, true);
            basicKeyChain.importKeys(ImmutableList.of(key));
            return key;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        lock.lock();
        try {
            return basicKeyChain.findKeyFromPubHash(pubkeyHash);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        lock.lock();
        try {
            return basicKeyChain.findKeyFromPubKey(pubkey);
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

    @Override
    public List<Protos.Key> serializeToProtobuf() {
        return null;
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
}
