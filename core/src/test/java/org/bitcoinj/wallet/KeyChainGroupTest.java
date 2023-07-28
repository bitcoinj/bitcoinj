/*
 * Copyright 2014 Mike Hearn
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

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.KeyChain.KeyPurpose;
import org.bitcoinj.wallet.listeners.KeyChainEventListener;
import org.bitcoinj.protobuf.wallet.Protos;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class KeyChainGroupTest {
    // Number of initial keys in this tests HD wallet, including interior keys.
    private static final int INITIAL_KEYS = 4;
    private static final int LOOKAHEAD_SIZE = 5;
    private static final String XPUB = "xpub68KFnj3bqUx1s7mHejLDBPywCAKdJEu1b49uniEEn2WSbHmZ7xbLqFTjJbtx1LUcAt1DwhoqWHmo2s5WMJp6wi38CiF2hYD49qVViKVvAoi";
    private static final byte[] ENTROPY = Sha256Hash.hash("don't use a string seed like this in real life".getBytes());
    private static final KeyCrypterScrypt KEY_CRYPTER = new KeyCrypterScrypt(2);
    private static final AesKey AES_KEY = KEY_CRYPTER.deriveKey("password");
    private static final double LOW_FALSE_POSITIVE_RATE = 0.00001;
    private KeyChainGroup group;
    private DeterministicKey watchingAccountKey;

    @Before
    public void setup() {
        BriefLogFormatter.init();
        TimeUtils.setMockClock();
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).lookaheadSize(LOOKAHEAD_SIZE).fromRandom(ScriptType.P2PKH)
                .build();
        group.getActiveKeyChain();  // Force create a chain.

        watchingAccountKey = DeterministicKey.deserializeB58(null, XPUB, BitcoinNetwork.MAINNET);
    }

    @Test
    public void createDeterministic_P2PKH() {
        KeyChainGroup kcg = KeyChainGroup.builder(BitcoinNetwork.MAINNET).fromRandom(ScriptType.P2PKH).build();
        // check default
        Address address = kcg.currentAddress(KeyPurpose.RECEIVE_FUNDS);
        assertEquals(ScriptType.P2PKH, address.getOutputScriptType());
    }

    @Test
    public void createDeterministic_P2WPKH() {
        KeyChainGroup kcg = KeyChainGroup.builder(BitcoinNetwork.MAINNET).fromRandom(ScriptType.P2WPKH).build();
        // check default
        Address address = kcg.currentAddress(KeyPurpose.RECEIVE_FUNDS);
        assertEquals(ScriptType.P2WPKH, address.getOutputScriptType());
        // check fallback (this will go away at some point)
        address = kcg.freshAddress(KeyPurpose.RECEIVE_FUNDS, ScriptType.P2PKH, null);
        assertEquals(ScriptType.P2PKH, address.getOutputScriptType());
    }

    @Test
    public void freshCurrentKeys() {
        int numKeys = ((group.getLookaheadSize() + group.getLookaheadThreshold()) * 2)   // * 2 because of internal/external
                + 1  // keys issued
                + group.getActiveKeyChain().getAccountPath().size() + 2  /* account key + int/ext parent keys */;
        assertEquals(numKeys, group.numKeys());
        assertEquals(2 * numKeys, group.getBloomFilterElementCount());
        ECKey r1 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(numKeys, group.numKeys());
        assertEquals(2 * numKeys, group.getBloomFilterElementCount());

        ECKey i1 = new ECKey();
        group.importKeys(i1);
        numKeys++;
        assertEquals(numKeys, group.numKeys());
        assertEquals(2 * numKeys, group.getBloomFilterElementCount());

        ECKey r2 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(r1, r2);
        ECKey c1 = group.currentKey(KeyChain.KeyPurpose.CHANGE);
        assertNotEquals(r1, c1);
        ECKey r3 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertNotEquals(r1, r3);
        ECKey c2 = group.freshKey(KeyChain.KeyPurpose.CHANGE);
        assertNotEquals(r3, c2);
        // Current key has not moved and will not under marked as used.
        ECKey r4 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(r2, r4);
        ECKey c3 = group.currentKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(c1, c3);
        // Mark as used. Current key is now different.
        group.markPubKeyAsUsed(r4.getPubKey());
        ECKey r5 = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertNotEquals(r4, r5);
    }

    @Test
    public void imports() {
        ECKey key1 = new ECKey();
        int numKeys = group.numKeys();
        assertFalse(group.removeImportedKey(key1));
        assertEquals(1, group.importKeys(Collections.singletonList(key1)));
        assertEquals(numKeys + 1, group.numKeys());   // Lookahead is triggered by requesting a key, so none yet.
        group.removeImportedKey(key1);
        assertEquals(numKeys, group.numKeys());
    }

    @Test
    public void findKey() {
        ECKey a = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey b = group.freshKey(KeyChain.KeyPurpose.CHANGE);
        ECKey c = new ECKey();
        ECKey d = new ECKey();   // Not imported.
        group.importKeys(c);
        assertTrue(group.hasKey(a));
        assertTrue(group.hasKey(b));
        assertTrue(group.hasKey(c));
        assertFalse(group.hasKey(d));
        ECKey result = group.findKeyFromPubKey(a.getPubKey());
        assertEquals(a, result);
        result = group.findKeyFromPubKey(b.getPubKey());
        assertEquals(b, result);
        result = group.findKeyFromPubKeyHash(a.getPubKeyHash(), null);
        assertEquals(a, result);
        result = group.findKeyFromPubKeyHash(b.getPubKeyHash(), null);
        assertEquals(b, result);
        result = group.findKeyFromPubKey(c.getPubKey());
        assertEquals(c, result);
        result = group.findKeyFromPubKeyHash(c.getPubKeyHash(), null);
        assertEquals(c, result);
        assertNull(group.findKeyFromPubKey(d.getPubKey()));
        assertNull(group.findKeyFromPubKeyHash(d.getPubKeyHash(), null));
    }

    // Check encryption with and without a basic keychain.

    @Test
    public void encryptionWithoutImported() {
        encryption(false);
    }

    @Test
    public void encryptionWithImported() {
        encryption(true);
    }

    private void encryption(boolean withImported) {
        Instant now = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS);
        TimeUtils.setMockClock(now);
        ECKey a = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(now, group.earliestKeyCreationTime());
        Instant yesterday = now.minus(1, ChronoUnit.DAYS);
        TimeUtils.setMockClock(yesterday);
        ECKey b = new ECKey();

        assertFalse(group.isEncrypted());
        try {
            group.checkPassword("foo");   // Cannot check password of an unencrypted group.
            fail();
        } catch (IllegalStateException e) {
        }
        if (withImported) {
            assertEquals(now, group.earliestKeyCreationTime());
            group.importKeys(b);
            assertEquals(yesterday, group.earliestKeyCreationTime());
        }
        group.encrypt(KEY_CRYPTER, AES_KEY);
        assertTrue(group.isEncrypted());
        assertTrue(group.checkPassword("password"));
        assertFalse(group.checkPassword("wrong password"));
        final ECKey ea = group.findKeyFromPubKey(a.getPubKey());
        assertTrue(Objects.requireNonNull(ea).isEncrypted());
        if (withImported) {
            assertTrue(Objects.requireNonNull(group.findKeyFromPubKey(b.getPubKey())).isEncrypted());
            assertEquals(yesterday, group.earliestKeyCreationTime());
        } else {
            assertEquals(now, group.earliestKeyCreationTime());
        }
        try {
            ea.sign(Sha256Hash.ZERO_HASH);
            fail();
        } catch (ECKey.KeyIsEncryptedException e) {
            // Ignored.
        }
        if (withImported) {
            ECKey c = new ECKey();
            try {
                group.importKeys(c);
                fail();
            } catch (KeyCrypterException e) {
            }
            group.importKeysAndEncrypt(Collections.singletonList(c), AES_KEY);
            ECKey ec = group.findKeyFromPubKey(c.getPubKey());
            try {
                group.importKeysAndEncrypt(Collections.singletonList(ec), AES_KEY);
                fail();
            } catch (IllegalArgumentException e) {
            }
        }

        try {
            group.decrypt(KEY_CRYPTER.deriveKey("WRONG PASSWORD"));
            fail();
        } catch (KeyCrypterException e) {
        }

        group.decrypt(AES_KEY);
        assertFalse(group.isEncrypted());
        assertFalse(Objects.requireNonNull(group.findKeyFromPubKey(a.getPubKey())).isEncrypted());
        if (withImported) {
            assertFalse(Objects.requireNonNull(group.findKeyFromPubKey(b.getPubKey())).isEncrypted());
            assertEquals(yesterday, group.earliestKeyCreationTime());
        } else {
            assertEquals(now, group.earliestKeyCreationTime());
        }
    }

    @Test
    public void encryptionWhilstEmpty() {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).lookaheadSize(5).fromRandom(ScriptType.P2PKH).build();
        group.encrypt(KEY_CRYPTER, AES_KEY);
        assertTrue(group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).isEncrypted());
        final ECKey key = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        group.decrypt(AES_KEY);
        assertFalse(Objects.requireNonNull(group.findKeyFromPubKey(key.getPubKey())).isEncrypted());
    }

    @Test
    public void bloom() {
        ECKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey key2 = new ECKey();
        BloomFilter filter = group.getBloomFilter(group.getBloomFilterElementCount(), LOW_FALSE_POSITIVE_RATE, new Random().nextInt());
        assertTrue(filter.contains(key1.getPubKeyHash()));
        assertTrue(filter.contains(key1.getPubKey()));
        assertFalse(filter.contains(key2.getPubKey()));
        // Check that the filter contains the lookahead buffer and threshold zone.
        for (int i = 0; i < LOOKAHEAD_SIZE + group.getLookaheadThreshold(); i++) {
            ECKey k = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
            assertTrue(filter.contains(k.getPubKeyHash()));
        }
        // We ran ahead of the lookahead buffer.
        assertFalse(filter.contains(group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKey()));
        group.importKeys(key2);
        filter = group.getBloomFilter(group.getBloomFilterElementCount(), LOW_FALSE_POSITIVE_RATE, new Random().nextInt());
        assertTrue(filter.contains(key1.getPubKeyHash()));
        assertTrue(filter.contains(key1.getPubKey()));
        assertTrue(filter.contains(key2.getPubKey()));
    }

    @Test
    public void earliestKeyTime() {
        Instant now = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS);
        TimeUtils.setMockClock(now);
        assertEquals(now, group.earliestKeyCreationTime());
        TimeUtils.rollMockClock(Duration.ofSeconds(10_000));
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        TimeUtils.rollMockClock(Duration.ofSeconds(10_000));
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        // Check that all keys are assumed to be created at the same instant the seed is.
        assertEquals(now, group.earliestKeyCreationTime());
        ECKey key = new ECKey();
        Instant yesterday = now.minus(1, ChronoUnit.DAYS);
        key.setCreationTime(yesterday);
        group.importKeys(key);
        assertEquals(yesterday, group.earliestKeyCreationTime());
    }

    @Test
    public void events() {
        // Check that events are registered with the right chains and that if a chain is added, it gets the event
        // listeners attached properly even post-hoc.
        final AtomicReference<ECKey> ran = new AtomicReference<>(null);
        final KeyChainEventListener listener = keys -> ran.set(keys.get(0));
        group.addEventListener(listener, Threading.SAME_THREAD);
        ECKey key = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(key, ran.getAndSet(null));
        ECKey key2 = new ECKey();
        group.importKeys(key2);
        assertEquals(key2, ran.getAndSet(null));
        group.removeEventListener(listener);
        ECKey key3 = new ECKey();
        group.importKeys(key3);
        assertNull(ran.get());
    }

    @Test
    public void serialization() throws Exception {
        int initialKeys = INITIAL_KEYS + group.getActiveKeyChain().getAccountPath().size() - 1;
        assertEquals(initialKeys + 1 /* for the seed */, group.serializeToProtobuf().size());
        group = KeyChainGroup.fromProtobufUnencrypted(BitcoinNetwork.MAINNET, group.serializeToProtobuf());
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = group.freshKey(KeyChain.KeyPurpose.CHANGE);
        group.getBloomFilterElementCount();
        List<Protos.Key> protoKeys1 = group.serializeToProtobuf();
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 1, protoKeys1.size());
        group.importKeys(new ECKey());
        List<Protos.Key> protoKeys2 = group.serializeToProtobuf();
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 2, protoKeys2.size());

        group = KeyChainGroup.fromProtobufUnencrypted(BitcoinNetwork.MAINNET, protoKeys1);
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1)  * 2)  + 1 /* for the seed */ + 1, protoKeys1.size());
        assertTrue(group.hasKey(key1));
        assertTrue(group.hasKey(key2));
        assertEquals(key2, group.currentKey(KeyChain.KeyPurpose.CHANGE));
        assertEquals(key1, group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS));
        group = KeyChainGroup.fromProtobufUnencrypted(BitcoinNetwork.MAINNET, protoKeys2);
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 2, protoKeys2.size());
        assertTrue(group.hasKey(key1));
        assertTrue(group.hasKey(key2));

        group.encrypt(KEY_CRYPTER, AES_KEY);
        List<Protos.Key> protoKeys3 = group.serializeToProtobuf();
        group = KeyChainGroup.fromProtobufEncrypted(BitcoinNetwork.MAINNET, protoKeys3, KEY_CRYPTER);
        assertTrue(group.isEncrypted());
        assertTrue(group.checkPassword("password"));
        group.decrypt(AES_KEY);

        // No need for extensive contents testing here, as that's done in the keychain class tests.
    }

    @Test
    public void serializeWatching() throws Exception {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).lookaheadSize(LOOKAHEAD_SIZE).addChain(DeterministicKeyChain.builder()
                .watch(watchingAccountKey).outputScriptType(ScriptType.P2PKH).build()).build();
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        group.freshKey(KeyChain.KeyPurpose.CHANGE);
        group.getBloomFilterElementCount();  // Force lookahead.
        List<Protos.Key> protoKeys1 = group.serializeToProtobuf();
        assertEquals(3 + (group.getLookaheadSize() + group.getLookaheadThreshold() + 1) * 2, protoKeys1.size());
        group = KeyChainGroup.fromProtobufUnencrypted(BitcoinNetwork.MAINNET, protoKeys1);
        assertEquals(3 + (group.getLookaheadSize() + group.getLookaheadThreshold() + 1) * 2, group.serializeToProtobuf().size());
    }

    @Test
    public void constructFromSeed() {
        ECKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        final DeterministicSeed seed = Objects.requireNonNull(group.getActiveKeyChain().getSeed());
        KeyChainGroup group2 = KeyChainGroup.builder(BitcoinNetwork.MAINNET).lookaheadSize(5)
                .addChain(DeterministicKeyChain.builder().seed(seed).outputScriptType(ScriptType.P2PKH).build())
                .build();
        ECKey key2 = group2.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(key1, key2);
    }

    @Test
    public void addAndActivateHDChain_freshCurrentAddress() {
        DeterministicSeed seed = DeterministicSeed.ofEntropy(ENTROPY, "");
        DeterministicKeyChain chain1 = DeterministicKeyChain.builder().seed(seed)
                .accountPath(DeterministicKeyChain.ACCOUNT_ZERO_PATH).outputScriptType(ScriptType.P2PKH).build();
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).addChain(chain1).build();
        assertEquals("1M5T5k9yKtGWRtWYMjQtGx3K2sshrABzCT", group.currentAddress(KeyPurpose.RECEIVE_FUNDS).toString());

        final DeterministicKeyChain chain2 = DeterministicKeyChain.builder().seed(seed)
                .accountPath(DeterministicKeyChain.ACCOUNT_ONE_PATH).outputScriptType(ScriptType.P2PKH).build();
        group.addAndActivateHDChain(chain2);
        assertEquals("1JLnjJEXcyByAaW6sqSxNvGiiSEWRhdvPb", group.currentAddress(KeyPurpose.RECEIVE_FUNDS).toString());

        final DeterministicKeyChain chain3 = DeterministicKeyChain.builder().seed(seed)
                .accountPath(DeterministicKeyChain.BIP44_ACCOUNT_ZERO_PATH).outputScriptType(ScriptType.P2WPKH)
                .build();
        group.addAndActivateHDChain(chain3);
        assertEquals("bc1q5fa84aghxd6uzk5g2ywkppmzlut5d77vg8cd20",
                group.currentAddress(KeyPurpose.RECEIVE_FUNDS).toString());
    }

    @Test(expected = DeterministicUpgradeRequiredException.class)
    public void deterministicUpgradeRequired() {
        // Check that if we try to use HD features in a KCG that only has random keys, we get an exception.
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).build();
        group.importKeys(new ECKey(), new ECKey());
        assertTrue(group.isDeterministicUpgradeRequired(ScriptType.P2PKH, null));
        assertTrue(group.isDeterministicUpgradeRequired(ScriptType.P2WPKH, null));
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);   // throws
    }

    @Test
    public void deterministicUpgradeUnencrypted() throws Exception {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).fromRandom(ScriptType.P2PKH).lookaheadSize(LOOKAHEAD_SIZE).build();

        List<Protos.Key> protobufs = group.serializeToProtobuf();
        group.upgradeToDeterministic(ScriptType.P2PKH, KeyChainGroupStructure.BIP32, null, null);
        assertFalse(group.isEncrypted());
        assertFalse(group.isDeterministicUpgradeRequired(ScriptType.P2PKH, null));
        assertTrue(group.isDeterministicUpgradeRequired(ScriptType.P2WPKH, null));
        DeterministicKey dkey1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicSeed seed1 = group.getActiveKeyChain().getSeed();
        assertNotNull(seed1);

        group = KeyChainGroup.fromProtobufUnencrypted(BitcoinNetwork.MAINNET, protobufs);
        group.upgradeToDeterministic(ScriptType.P2PKH, KeyChainGroupStructure.BIP32, null, null);  // Should give same result as last time.
        assertFalse(group.isEncrypted());
        assertFalse(group.isDeterministicUpgradeRequired(ScriptType.P2PKH, null));
        assertTrue(group.isDeterministicUpgradeRequired(ScriptType.P2WPKH, null));
        DeterministicKey dkey2 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicSeed seed2 = group.getActiveKeyChain().getSeed();
        assertEquals(seed1, seed2);
        assertEquals(dkey1, dkey2);
    }

    @Test
    public void deterministicUpgradeEncrypted() throws Exception {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).fromRandom(ScriptType.P2PKH).build();
        group.encrypt(KEY_CRYPTER, AES_KEY);
        assertTrue(group.isEncrypted());
        assertFalse(group.isDeterministicUpgradeRequired(ScriptType.P2PKH, null));
        assertTrue(group.isDeterministicUpgradeRequired(ScriptType.P2WPKH, null));
        final DeterministicSeed deterministicSeed = group.getActiveKeyChain().getSeed();
        assertNotNull(deterministicSeed);
        assertTrue(deterministicSeed.isEncrypted());
        byte[] entropy = Objects.requireNonNull(group.getActiveKeyChain().toDecrypted(AES_KEY).getSeed()).getEntropyBytes();
    }

    @Test
    public void markAsUsed() {
        Address addr1 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        Address addr2 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(addr1, addr2);
        group.markPubKeyHashAsUsed(addr1.getHash());
        Address addr3 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertNotEquals(addr2, addr3);
    }

    @Test
    public void isNotWatching() {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).fromRandom(ScriptType.P2PKH).build();
        final ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        group.importKeys(key);
        assertFalse(group.isWatching());
    }

    @Test
    public void isWatching() {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET)
                .addChain(DeterministicKeyChain.builder().watch(DeterministicKey.deserializeB58(
                        "xpub69bjfJ91ikC5ghsqsVDHNq2dRGaV2HHVx7Y9LXi27LN9BWWAXPTQr4u8U3wAtap8bLdHdkqPpAcZmhMS5SnrMQC4ccaoBccFhh315P4UYzo",
                        BitcoinNetwork.MAINNET)).outputScriptType(ScriptType.P2PKH).build())
                .build();
        final ECKey watchingKey = ECKey.fromPublicOnly(new ECKey());
        group.importKeys(watchingKey);
        assertTrue(group.isWatching());
    }

    @Test(expected = IllegalStateException.class)
    public void isWatchingNoKeys() {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).build();
        group.isWatching();
    }

    @Test(expected = IllegalStateException.class)
    public void isWatchingMixedKeys() {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET)
                .addChain(DeterministicKeyChain.builder().watch(DeterministicKey.deserializeB58(
                        "xpub69bjfJ91ikC5ghsqsVDHNq2dRGaV2HHVx7Y9LXi27LN9BWWAXPTQr4u8U3wAtap8bLdHdkqPpAcZmhMS5SnrMQC4ccaoBccFhh315P4UYzo",
                        BitcoinNetwork.MAINNET)).outputScriptType(ScriptType.P2PKH).build())
                .build();
        final ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        group.importKeys(key);
        group.isWatching();
    }

    @Test
    public void segwitKeyChainGroup() throws Exception {
        group = KeyChainGroup.builder(BitcoinNetwork.MAINNET).lookaheadSize(LOOKAHEAD_SIZE)
                .addChain(DeterministicKeyChain.builder().entropy(ENTROPY, TimeUtils.currentTime()).outputScriptType(ScriptType.P2WPKH)
                        .accountPath(DeterministicKeyChain.ACCOUNT_ONE_PATH).build())
                .build();
        assertEquals(ScriptType.P2WPKH, group.getActiveKeyChain().getOutputScriptType());
        assertEquals("bc1qhcurdec849thpjjp3e27atvya43gy2snrechd9",
                group.currentAddress(KeyPurpose.RECEIVE_FUNDS).toString());
        assertEquals("bc1qw8sf3mwuwn74qnhj83gjg0cwkk78fun2pxl9t2", group.currentAddress(KeyPurpose.CHANGE).toString());

        // round-trip through protobuf
        group = KeyChainGroup.fromProtobufUnencrypted(BitcoinNetwork.MAINNET, group.serializeToProtobuf());
        assertEquals(ScriptType.P2WPKH, group.getActiveKeyChain().getOutputScriptType());
        assertEquals("bc1qhcurdec849thpjjp3e27atvya43gy2snrechd9",
                group.currentAddress(KeyPurpose.RECEIVE_FUNDS).toString());
        assertEquals("bc1qw8sf3mwuwn74qnhj83gjg0cwkk78fun2pxl9t2", group.currentAddress(KeyPurpose.CHANGE).toString());

        // encryption
        group.encrypt(KEY_CRYPTER, AES_KEY);
        assertEquals(ScriptType.P2WPKH, group.getActiveKeyChain().getOutputScriptType());
        assertEquals("bc1qhcurdec849thpjjp3e27atvya43gy2snrechd9",
                group.currentAddress(KeyPurpose.RECEIVE_FUNDS).toString());
        assertEquals("bc1qw8sf3mwuwn74qnhj83gjg0cwkk78fun2pxl9t2", group.currentAddress(KeyPurpose.CHANGE).toString());

        // round-trip encrypted again, then dectypt
        group = KeyChainGroup.fromProtobufEncrypted(BitcoinNetwork.MAINNET, group.serializeToProtobuf(), KEY_CRYPTER);
        group.decrypt(AES_KEY);
        assertEquals(ScriptType.P2WPKH, group.getActiveKeyChain().getOutputScriptType());
        assertEquals("bc1qhcurdec849thpjjp3e27atvya43gy2snrechd9",
                group.currentAddress(KeyPurpose.RECEIVE_FUNDS).toString());
        assertEquals("bc1qw8sf3mwuwn74qnhj83gjg0cwkk78fun2pxl9t2", group.currentAddress(KeyPurpose.CHANGE).toString());
    }

    @Test
    public void onlyBasicKeyEncryptionAndDecryption() {
        group = KeyChainGroup.createBasic(BitcoinNetwork.MAINNET);
        final ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        group.importKeys(key);
        group.encrypt(KEY_CRYPTER, AES_KEY);
        group.decrypt(AES_KEY);
    }
}
