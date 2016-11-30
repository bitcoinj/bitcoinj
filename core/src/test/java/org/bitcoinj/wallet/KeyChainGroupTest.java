/*
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.listeners.KeyChainEventListener;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.Arrays;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class KeyChainGroupTest {
    // Number of initial keys in this tests HD wallet, including interior keys.
    private static final int INITIAL_KEYS = 4;
    private static final int LOOKAHEAD_SIZE = 5;
    private static final NetworkParameters PARAMS = MainNetParams.get();
    private static final String XPUB = "xpub68KFnj3bqUx1s7mHejLDBPywCAKdJEu1b49uniEEn2WSbHmZ7xbLqFTjJbtx1LUcAt1DwhoqWHmo2s5WMJp6wi38CiF2hYD49qVViKVvAoi";
    private KeyChainGroup group;
    private DeterministicKey watchingAccountKey;

    @Before
    public void setup() {
        BriefLogFormatter.init();
        Utils.setMockClock();
        group = new KeyChainGroup(PARAMS);
        group.setLookaheadSize(LOOKAHEAD_SIZE);   // Don't want slow tests.
        group.getActiveKeyChain();  // Force create a chain.

        watchingAccountKey = DeterministicKey.deserializeB58(null, XPUB, PARAMS);
    }

    private KeyChainGroup createMarriedKeyChainGroup() {
        KeyChainGroup group = new KeyChainGroup(PARAMS);
        DeterministicKeyChain chain = createMarriedKeyChain();
        group.addAndActivateHDChain(chain);
        group.setLookaheadSize(LOOKAHEAD_SIZE);
        group.getActiveKeyChain();
        return group;
    }

    private MarriedKeyChain createMarriedKeyChain() {
        byte[] entropy = Sha256Hash.hash("don't use a seed like this in real life".getBytes());
        DeterministicSeed seed = new DeterministicSeed(entropy, "", MnemonicCode.BIP39_STANDARDISATION_TIME_SECS);
        MarriedKeyChain chain = MarriedKeyChain.builder()
                .seed(seed)
                .followingKeys(watchingAccountKey)
                .threshold(2).build();
        return chain;
    }

    @Test
    public void freshCurrentKeys() throws Exception {
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
    public void freshCurrentKeysForMarriedKeychain() throws Exception {
        group = createMarriedKeyChainGroup();

        try {
            group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
            fail();
        } catch (UnsupportedOperationException e) {
        }

        try {
            group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
            fail();
        } catch (UnsupportedOperationException e) {
        }
    }

    @Test
    public void imports() throws Exception {
        ECKey key1 = new ECKey();
        int numKeys = group.numKeys();
        assertFalse(group.removeImportedKey(key1));
        assertEquals(1, group.importKeys(ImmutableList.of(key1)));
        assertEquals(numKeys + 1, group.numKeys());   // Lookahead is triggered by requesting a key, so none yet.
        group.removeImportedKey(key1);
        assertEquals(numKeys, group.numKeys());
    }

    @Test
    public void findKey() throws Exception {
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
        result = group.findKeyFromPubHash(a.getPubKeyHash());
        assertEquals(a, result);
        result = group.findKeyFromPubHash(b.getPubKeyHash());
        assertEquals(b, result);
        result = group.findKeyFromPubKey(c.getPubKey());
        assertEquals(c, result);
        result = group.findKeyFromPubHash(c.getPubKeyHash());
        assertEquals(c, result);
        assertNull(group.findKeyFromPubKey(d.getPubKey()));
        assertNull(group.findKeyFromPubHash(d.getPubKeyHash()));
    }

    @Test
    public void currentP2SHAddress() throws Exception {
        group = createMarriedKeyChainGroup();
        Address a1 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(a1.isP2SHAddress());
        Address a2 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(a1, a2);
        Address a3 = group.currentAddress(KeyChain.KeyPurpose.CHANGE);
        assertNotEquals(a2, a3);
    }

    @Test
    public void freshAddress() throws Exception {
        group = createMarriedKeyChainGroup();
        Address a1 = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        Address a2 = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(a1.isP2SHAddress());
        assertNotEquals(a1, a2);
        group.getBloomFilterElementCount();
        assertEquals(((group.getLookaheadSize() + group.getLookaheadThreshold()) * 2)   // * 2 because of internal/external
                + (2 - group.getLookaheadThreshold())  // keys issued
                + group.getActiveKeyChain().getAccountPath().size() + 3  /* master, account, int, ext */, group.numKeys());

        Address a3 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(a2, a3);
    }

    @Test
    public void findRedeemData() throws Exception {
        group = createMarriedKeyChainGroup();

        // test script hash that we don't have
        assertNull(group.findRedeemDataFromScriptHash(new ECKey().getPubKey()));

        // test our script hash
        Address address = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        RedeemData redeemData = group.findRedeemDataFromScriptHash(address.getHash160());
        assertNotNull(redeemData);
        assertNotNull(redeemData.redeemScript);
        assertEquals(2, redeemData.keys.size());
    }

    // Check encryption with and without a basic keychain.

    @Test
    public void encryptionWithoutImported() throws Exception {
        encryption(false);
    }

    @Test
    public void encryptionWithImported() throws Exception {
        encryption(true);
    }

    public void encryption(boolean withImported) throws Exception {
        Utils.rollMockClock(0);
        long now = Utils.currentTimeSeconds();
        ECKey a = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(now, group.getEarliestKeyCreationTime());
        Utils.rollMockClock(-86400);
        long yesterday = Utils.currentTimeSeconds();
        ECKey b = new ECKey();

        assertFalse(group.isEncrypted());
        try {
            group.checkPassword("foo");   // Cannot check password of an unencrypted group.
            fail();
        } catch (IllegalStateException e) {
        }
        if (withImported) {
            assertEquals(now, group.getEarliestKeyCreationTime());
            group.importKeys(b);
            assertEquals(yesterday, group.getEarliestKeyCreationTime());
        }
        KeyCrypterScrypt scrypt = new KeyCrypterScrypt(2);
        final KeyParameter aesKey = scrypt.deriveKey("password");
        group.encrypt(scrypt, aesKey);
        assertTrue(group.isEncrypted());
        assertTrue(group.checkPassword("password"));
        assertFalse(group.checkPassword("wrong password"));
        final ECKey ea = group.findKeyFromPubKey(a.getPubKey());
        assertTrue(checkNotNull(ea).isEncrypted());
        if (withImported) {
            assertTrue(checkNotNull(group.findKeyFromPubKey(b.getPubKey())).isEncrypted());
            assertEquals(yesterday, group.getEarliestKeyCreationTime());
        } else {
            assertEquals(now, group.getEarliestKeyCreationTime());
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
            group.importKeysAndEncrypt(ImmutableList.of(c), aesKey);
            ECKey ec = group.findKeyFromPubKey(c.getPubKey());
            try {
                group.importKeysAndEncrypt(ImmutableList.of(ec), aesKey);
                fail();
            } catch (IllegalArgumentException e) {
            }
        }

        try {
            group.decrypt(scrypt.deriveKey("WRONG PASSWORD"));
            fail();
        } catch (KeyCrypterException e) {
        }

        group.decrypt(aesKey);
        assertFalse(group.isEncrypted());
        assertFalse(checkNotNull(group.findKeyFromPubKey(a.getPubKey())).isEncrypted());
        if (withImported) {
            assertFalse(checkNotNull(group.findKeyFromPubKey(b.getPubKey())).isEncrypted());
            assertEquals(yesterday, group.getEarliestKeyCreationTime());
        } else {
            assertEquals(now, group.getEarliestKeyCreationTime());
        }
    }

    @Test
    public void encryptionWhilstEmpty() throws Exception {
        group = new KeyChainGroup(PARAMS);
        group.setLookaheadSize(5);
        KeyCrypterScrypt scrypt = new KeyCrypterScrypt(2);
        final KeyParameter aesKey = scrypt.deriveKey("password");
        group.encrypt(scrypt, aesKey);
        assertTrue(group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).isEncrypted());
        final ECKey key = group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        group.decrypt(aesKey);
        assertFalse(checkNotNull(group.findKeyFromPubKey(key.getPubKey())).isEncrypted());
    }

    @Test
    public void bloom() throws Exception {
        ECKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey key2 = new ECKey();
        BloomFilter filter = group.getBloomFilter(group.getBloomFilterElementCount(), 0.001, (long)(Math.random() * Long.MAX_VALUE));
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
        filter = group.getBloomFilter(group.getBloomFilterElementCount(), 0.001, (long) (Math.random() * Long.MAX_VALUE));
        assertTrue(filter.contains(key1.getPubKeyHash()));
        assertTrue(filter.contains(key1.getPubKey()));
        assertTrue(filter.contains(key2.getPubKey()));
    }

    @Test
    public void findRedeemScriptFromPubHash() throws Exception {
        group = createMarriedKeyChainGroup();
        Address address = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(group.findRedeemDataFromScriptHash(address.getHash160()) != null);
        group.getBloomFilterElementCount();
        KeyChainGroup group2 = createMarriedKeyChainGroup();
        group2.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        group2.getBloomFilterElementCount();  // Force lookahead.
        // test address from lookahead zone and lookahead threshold zone
        for (int i = 0; i < group.getLookaheadSize() + group.getLookaheadThreshold(); i++) {
            address = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
            assertTrue(group2.findRedeemDataFromScriptHash(address.getHash160()) != null);
        }
        assertFalse(group2.findRedeemDataFromScriptHash(group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS).getHash160()) != null);
    }

    @Test
    public void bloomFilterForMarriedChains() throws Exception {
        group = createMarriedKeyChainGroup();
        int bufferSize = group.getLookaheadSize() + group.getLookaheadThreshold();
        int expected = bufferSize * 2 /* chains */ * 2 /* elements */;
        assertEquals(expected, group.getBloomFilterElementCount());
        Address address1 = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(expected, group.getBloomFilterElementCount());
        BloomFilter filter = group.getBloomFilter(expected + 2, 0.001, (long)(Math.random() * Long.MAX_VALUE));
        assertTrue(filter.contains(address1.getHash160()));

        Address address2 = group.freshAddress(KeyChain.KeyPurpose.CHANGE);
        assertTrue(filter.contains(address2.getHash160()));

        // Check that the filter contains the lookahead buffer.
        for (int i = 0; i < bufferSize - 1 /* issued address */; i++) {
            Address address = group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
            assertTrue("key " + i, filter.contains(address.getHash160()));
        }
        // We ran ahead of the lookahead buffer.
        assertFalse(filter.contains(group.freshAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS).getHash160()));
    }

    @Test
    public void earliestKeyTime() throws Exception {
        long now = Utils.currentTimeSeconds();   // mock
        long yesterday = now - 86400;
        assertEquals(now, group.getEarliestKeyCreationTime());
        Utils.rollMockClock(10000);
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        Utils.rollMockClock(10000);
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        // Check that all keys are assumed to be created at the same instant the seed is.
        assertEquals(now, group.getEarliestKeyCreationTime());
        ECKey key = new ECKey();
        key.setCreationTimeSeconds(yesterday);
        group.importKeys(key);
        assertEquals(yesterday, group.getEarliestKeyCreationTime());
    }

    @Test
    public void events() throws Exception {
        // Check that events are registered with the right chains and that if a chain is added, it gets the event
        // listeners attached properly even post-hoc.
        final AtomicReference<ECKey> ran = new AtomicReference<>(null);
        final KeyChainEventListener listener = new KeyChainEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> keys) {
                ran.set(keys.get(0));
            }
        };
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
        group = KeyChainGroup.fromProtobufUnencrypted(PARAMS, group.serializeToProtobuf());
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = group.freshKey(KeyChain.KeyPurpose.CHANGE);
        group.getBloomFilterElementCount();
        List<Protos.Key> protoKeys1 = group.serializeToProtobuf();
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 1, protoKeys1.size());
        group.importKeys(new ECKey());
        List<Protos.Key> protoKeys2 = group.serializeToProtobuf();
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 2, protoKeys2.size());

        group = KeyChainGroup.fromProtobufUnencrypted(PARAMS, protoKeys1);
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1)  * 2)  + 1 /* for the seed */ + 1, protoKeys1.size());
        assertTrue(group.hasKey(key1));
        assertTrue(group.hasKey(key2));
        assertEquals(key2, group.currentKey(KeyChain.KeyPurpose.CHANGE));
        assertEquals(key1, group.currentKey(KeyChain.KeyPurpose.RECEIVE_FUNDS));
        group = KeyChainGroup.fromProtobufUnencrypted(PARAMS, protoKeys2);
        assertEquals(initialKeys + ((LOOKAHEAD_SIZE + 1) * 2) + 1 /* for the seed */ + 2, protoKeys2.size());
        assertTrue(group.hasKey(key1));
        assertTrue(group.hasKey(key2));

        KeyCrypterScrypt scrypt = new KeyCrypterScrypt(2);
        final KeyParameter aesKey = scrypt.deriveKey("password");
        group.encrypt(scrypt, aesKey);
        List<Protos.Key> protoKeys3 = group.serializeToProtobuf();
        group = KeyChainGroup.fromProtobufEncrypted(PARAMS, protoKeys3, scrypt);
        assertTrue(group.isEncrypted());
        assertTrue(group.checkPassword("password"));
        group.decrypt(aesKey);

        // No need for extensive contents testing here, as that's done in the keychain class tests.
    }

    @Test
    public void serializeWatching() throws Exception {
        group = new KeyChainGroup(PARAMS, watchingAccountKey);
        group.setLookaheadSize(LOOKAHEAD_SIZE);
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        group.freshKey(KeyChain.KeyPurpose.CHANGE);
        group.getBloomFilterElementCount();  // Force lookahead.
        List<Protos.Key> protoKeys1 = group.serializeToProtobuf();
        assertEquals(3 + (group.getLookaheadSize() + group.getLookaheadThreshold() + 1) * 2, protoKeys1.size());
        group = KeyChainGroup.fromProtobufUnencrypted(PARAMS, protoKeys1);
        assertEquals(3 + (group.getLookaheadSize() + group.getLookaheadThreshold() + 1) * 2, group.serializeToProtobuf().size());
    }

    @Test
    public void serializeMarried() throws Exception {
        group = createMarriedKeyChainGroup();
        Address address1 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(group.isMarried());
        assertEquals(2, group.getActiveKeyChain().getSigsRequiredToSpend());

        List<Protos.Key> protoKeys = group.serializeToProtobuf();
        KeyChainGroup group2 = KeyChainGroup.fromProtobufUnencrypted(PARAMS, protoKeys);
        assertTrue(group2.isMarried());
        assertEquals(2, group.getActiveKeyChain().getSigsRequiredToSpend());
        Address address2 = group2.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(address1, address2);
    }

    @Test
    public void addFollowingAccounts() throws Exception {
        assertFalse(group.isMarried());
        group.addAndActivateHDChain(createMarriedKeyChain());
        assertTrue(group.isMarried());
    }

    @Test
    public void constructFromSeed() throws Exception {
        ECKey key1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        final DeterministicSeed seed = checkNotNull(group.getActiveKeyChain().getSeed());
        KeyChainGroup group2 = new KeyChainGroup(PARAMS, seed);
        group2.setLookaheadSize(5);
        ECKey key2 = group2.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(key1, key2);
    }

    @Test(expected = DeterministicUpgradeRequiredException.class)
    public void deterministicUpgradeRequired() throws Exception {
        // Check that if we try to use HD features in a KCG that only has random keys, we get an exception.
        group = new KeyChainGroup(PARAMS);
        group.importKeys(new ECKey(), new ECKey());
        assertTrue(group.isDeterministicUpgradeRequired());
        group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);   // throws
    }

    @Test
    public void deterministicUpgradeUnencrypted() throws Exception {
        // Check that a group that contains only random keys has its HD chain created using the private key bytes of
        // the oldest random key, so upgrading the same wallet twice gives the same outcome.
        group = new KeyChainGroup(PARAMS);
        group.setLookaheadSize(LOOKAHEAD_SIZE);   // Don't want slow tests.
        ECKey key1 = new ECKey();
        Utils.rollMockClock(86400);
        ECKey key2 = new ECKey();
        group.importKeys(key2, key1);

        List<Protos.Key> protobufs = group.serializeToProtobuf();
        group.upgradeToDeterministic(0, null);
        assertFalse(group.isDeterministicUpgradeRequired());
        DeterministicKey dkey1 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicSeed seed1 = group.getActiveKeyChain().getSeed();
        assertNotNull(seed1);

        group = KeyChainGroup.fromProtobufUnencrypted(PARAMS, protobufs);
        group.upgradeToDeterministic(0, null);  // Should give same result as last time.
        DeterministicKey dkey2 = group.freshKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicSeed seed2 = group.getActiveKeyChain().getSeed();
        assertEquals(seed1, seed2);
        assertEquals(dkey1, dkey2);

        // Check we used the right (oldest) key despite backwards import order.
        byte[] truncatedBytes = Arrays.copyOfRange(key1.getSecretBytes(), 0, 16);
        assertArrayEquals(seed1.getEntropyBytes(), truncatedBytes);
    }

    @Test
    public void deterministicUpgradeRotating() throws Exception {
        group = new KeyChainGroup(PARAMS);
        group.setLookaheadSize(LOOKAHEAD_SIZE);   // Don't want slow tests.
        long now = Utils.currentTimeSeconds();
        ECKey key1 = new ECKey();
        Utils.rollMockClock(86400);
        ECKey key2 = new ECKey();
        Utils.rollMockClock(86400);
        ECKey key3 = new ECKey();
        group.importKeys(key2, key1, key3);
        group.upgradeToDeterministic(now + 10, null);
        DeterministicSeed seed = group.getActiveKeyChain().getSeed();
        assertNotNull(seed);
        // Check we used the right key: oldest non rotating.
        byte[] truncatedBytes = Arrays.copyOfRange(key2.getSecretBytes(), 0, 16);
        assertArrayEquals(seed.getEntropyBytes(), truncatedBytes);
    }

    @Test
    public void deterministicUpgradeEncrypted() throws Exception {
        group = new KeyChainGroup(PARAMS);
        final ECKey key = new ECKey();
        group.importKeys(key);
        final KeyCrypterScrypt crypter = new KeyCrypterScrypt();
        final KeyParameter aesKey = crypter.deriveKey("abc");
        assertTrue(group.isDeterministicUpgradeRequired());
        group.encrypt(crypter, aesKey);
        assertTrue(group.isDeterministicUpgradeRequired());
        try {
            group.upgradeToDeterministic(0, null);
            fail();
        } catch (DeterministicUpgradeRequiresPassword e) {
            // Expected.
        }
        group.upgradeToDeterministic(0, aesKey);
        assertFalse(group.isDeterministicUpgradeRequired());
        final DeterministicSeed deterministicSeed = group.getActiveKeyChain().getSeed();
        assertNotNull(deterministicSeed);
        assertTrue(deterministicSeed.isEncrypted());
        byte[] entropy = checkNotNull(group.getActiveKeyChain().toDecrypted(aesKey).getSeed()).getEntropyBytes();
        // Check we used the right key: oldest non rotating.
        byte[] truncatedBytes = Arrays.copyOfRange(key.getSecretBytes(), 0, 16);
        assertArrayEquals(entropy, truncatedBytes);
    }

    @Test
    public void markAsUsed() throws Exception {
        Address addr1 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        Address addr2 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals(addr1, addr2);
        group.markPubKeyHashAsUsed(addr1.getHash160());
        Address addr3 = group.currentAddress(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertNotEquals(addr2, addr3);
    }

    @Test
    public void isNotWatching() {
        group = new KeyChainGroup(PARAMS);
        final ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        group.importKeys(key);
        assertFalse(group.isWatching());
    }

    @Test
    public void isWatching() {
        group = new KeyChainGroup(
                PARAMS,
                DeterministicKey
                        .deserializeB58(
                                "xpub69bjfJ91ikC5ghsqsVDHNq2dRGaV2HHVx7Y9LXi27LN9BWWAXPTQr4u8U3wAtap8bLdHdkqPpAcZmhMS5SnrMQC4ccaoBccFhh315P4UYzo",
                                PARAMS));
        final ECKey watchingKey = ECKey.fromPublicOnly(new ECKey().getPubKeyPoint());
        group.importKeys(watchingKey);
        assertTrue(group.isWatching());
    }

    @Test(expected = IllegalStateException.class)
    public void isWatchingNoKeys() {
        group = new KeyChainGroup(PARAMS);
        group.isWatching();
    }

    @Test(expected = IllegalStateException.class)
    public void isWatchingMixedKeys() {
        group = new KeyChainGroup(
                PARAMS,
                DeterministicKey
                        .deserializeB58(
                                "xpub69bjfJ91ikC5ghsqsVDHNq2dRGaV2HHVx7Y9LXi27LN9BWWAXPTQr4u8U3wAtap8bLdHdkqPpAcZmhMS5SnrMQC4ccaoBccFhh315P4UYzo",
                                PARAMS));
        final ECKey key = ECKey.fromPrivate(BigInteger.TEN);
        group.importKeys(key);
        group.isWatching();
    }
}
