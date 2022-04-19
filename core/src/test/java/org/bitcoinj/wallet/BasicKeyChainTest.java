/*
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

package org.bitcoinj.wallet;

import com.google.common.collect.Lists;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.listeners.AbstractKeyChainEventListener;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BasicKeyChainTest {
    private BasicKeyChain chain;
    private AtomicReference<List<ECKey>> onKeysAdded;
    private AtomicBoolean onKeysAddedRan;

    @Before
    public void setup() {
        chain = new BasicKeyChain();
        onKeysAdded = new AtomicReference<>();
        onKeysAddedRan = new AtomicBoolean();
        chain.addEventListener(new AbstractKeyChainEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> keys2) {
                onKeysAdded.set(keys2);
                onKeysAddedRan.set(true);
            }
        }, Threading.SAME_THREAD);
    }

    @Test
    public void importKeys() {
        Utils.setMockClock();
        long now = Utils.currentTimeSeconds();
        final ECKey key1 = new ECKey();
        Utils.rollMockClock(86400);
        final ECKey key2 = new ECKey();
        final ArrayList<ECKey> keys = Lists.newArrayList(key1, key2);

        // Import two keys, check the event is correct.
        assertEquals(2, chain.importKeys(keys));
        assertEquals(2, chain.numKeys());
        assertTrue(onKeysAddedRan.getAndSet(false));
        assertArrayEquals(keys.toArray(), onKeysAdded.get().toArray());
        assertEquals(now, chain.getEarliestKeyCreationTime());
        // Check we ignore duplicates.
        final ECKey newKey = new ECKey();
        keys.add(newKey);
        assertEquals(1, chain.importKeys(keys));
        assertTrue(onKeysAddedRan.getAndSet(false));
        assertEquals(newKey, onKeysAdded.getAndSet(null).get(0));
        assertEquals(0, chain.importKeys(keys));
        assertFalse(onKeysAddedRan.getAndSet(false));
        assertNull(onKeysAdded.get());

        assertTrue(chain.hasKey(key1));
        assertTrue(chain.hasKey(key2));
        assertEquals(key1, chain.findKeyFromPubHash(key1.getPubKeyHash()));
        assertEquals(key2, chain.findKeyFromPubKey(key2.getPubKey()));
        assertNull(chain.findKeyFromPubKey(key2.getPubKeyHash()));
    }

    @Test
    public void removeKey() {
        ECKey key = new ECKey();
        chain.importKeys(key);
        assertEquals(1, chain.numKeys());
        assertTrue(chain.removeKey(key));
        assertEquals(0, chain.numKeys());
        assertFalse(chain.removeKey(key));
    }

    @Test
    public void getKey() {
        ECKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(onKeysAddedRan.getAndSet(false));
        assertEquals(key1, onKeysAdded.getAndSet(null).get(0));
        ECKey key2 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertFalse(onKeysAddedRan.getAndSet(false));
        assertEquals(key2, key1);
    }

    @Test(expected = IllegalStateException.class)
    public void checkPasswordNoKeys() {
        chain.checkPassword("test");
    }

    @Test(expected = IllegalStateException.class)
    public void checkPasswordNotEncrypted() {
        final ArrayList<ECKey> keys = Lists.newArrayList(new ECKey(), new ECKey());
        chain.importKeys(keys);
        chain.checkPassword("test");
    }

    @Test(expected = IllegalStateException.class)
    public void doubleEncryptFails() {
        final ArrayList<ECKey> keys = Lists.newArrayList(new ECKey(), new ECKey());
        chain.importKeys(keys);
        chain = chain.toEncrypted("foo");
        chain.toEncrypted("foo");
    }

    @Test
    public void encryptDecrypt() {
        final ECKey key1 = new ECKey();
        chain.importKeys(key1, new ECKey());
        final String PASSWORD = "foobar";
        chain = chain.toEncrypted(PASSWORD);
        final KeyCrypter keyCrypter = chain.getKeyCrypter();
        assertNotNull(keyCrypter);
        assertTrue(keyCrypter instanceof KeyCrypterScrypt);

        assertTrue(chain.checkPassword(PASSWORD));
        assertFalse(chain.checkPassword("wrong"));
        ECKey key = chain.findKeyFromPubKey(key1.getPubKey());
        assertTrue(key.isEncrypted());
        assertTrue(key.isPubKeyOnly());
        assertFalse(key.isWatching());
        assertNull(key.getSecretBytes());

        try {
            // Don't allow import of an unencrypted key.
            chain.importKeys(new ECKey());
            fail();
        } catch (KeyCrypterException e) {
        }

        try {
            chain.toDecrypted(keyCrypter.deriveKey("wrong"));
            fail();
        } catch (KeyCrypterException e) {}
        chain = chain.toDecrypted(PASSWORD);
        key = chain.findKeyFromPubKey(key1.getPubKey());
        assertFalse(key.isEncrypted());
        assertFalse(key.isPubKeyOnly());
        assertFalse(key.isWatching());
        key.getPrivKeyBytes();
    }

    @Test(expected = KeyCrypterException.class)
    public void cannotImportEncryptedKey() {
        final ECKey key1 = new ECKey();
        chain.importKeys(Collections.singletonList(key1));
        chain = chain.toEncrypted("foobar");
        ECKey encryptedKey = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(encryptedKey.isEncrypted());

        BasicKeyChain chain2 = new BasicKeyChain();
        chain2.importKeys(Collections.singletonList(encryptedKey));
    }

    @Test(expected = KeyCrypterException.class)
    public void cannotMixParams() {
        chain = chain.toEncrypted("foobar");
        KeyCrypterScrypt scrypter = new KeyCrypterScrypt(2);    // Some bogus params.
        ECKey key1 = new ECKey().encrypt(scrypter, scrypter.deriveKey("other stuff"));
        chain.importKeys(key1);
    }

    @Test
    public void serializationUnencrypted() throws UnreadableWalletException {
        Utils.setMockClock();
        Date now = Utils.now();
        final ECKey key1 = new ECKey();
        Utils.rollMockClock(5000);
        final ECKey key2 = new ECKey();
        chain.importKeys(Arrays.asList(key1, key2));
        List<Protos.Key> keys = chain.serializeToProtobuf();
        assertEquals(2, keys.size());
        assertArrayEquals(key1.getPubKey(), keys.get(0).getPublicKey().toByteArray());
        assertArrayEquals(key2.getPubKey(), keys.get(1).getPublicKey().toByteArray());
        assertArrayEquals(key1.getPrivKeyBytes(), keys.get(0).getSecretBytes().toByteArray());
        assertArrayEquals(key2.getPrivKeyBytes(), keys.get(1).getSecretBytes().toByteArray());
        long normTime = (long) (Math.floor(now.getTime() / 1000) * 1000);
        assertEquals(normTime, keys.get(0).getCreationTimestamp());
        assertEquals(normTime + 5000 * 1000, keys.get(1).getCreationTimestamp());

        chain = BasicKeyChain.fromProtobufUnencrypted(keys);
        assertEquals(2, chain.getKeys().size());
        assertEquals(key1, chain.getKeys().get(0));
        assertEquals(key2, chain.getKeys().get(1));
    }

    @Test
    public void serializationEncrypted() throws UnreadableWalletException {
        ECKey key1 = new ECKey();
        chain.importKeys(key1);
        chain = chain.toEncrypted("foo bar");
        key1 = chain.getKeys().get(0);
        List<Protos.Key> keys = chain.serializeToProtobuf();
        assertEquals(1, keys.size());
        assertArrayEquals(key1.getPubKey(), keys.get(0).getPublicKey().toByteArray());
        assertFalse(keys.get(0).hasSecretBytes());
        assertTrue(keys.get(0).hasEncryptedData());
        chain = BasicKeyChain.fromProtobufEncrypted(keys, checkNotNull(chain.getKeyCrypter()));
        assertEquals(key1.getEncryptedPrivateKey(), chain.getKeys().get(0).getEncryptedPrivateKey());
        assertTrue(chain.checkPassword("foo bar"));
    }

    @Test
    public void watching() throws UnreadableWalletException {
        ECKey key1 = new ECKey();
        ECKey pub = ECKey.fromPublicOnly(key1);
        chain.importKeys(pub);
        assertEquals(1, chain.numKeys());
        List<Protos.Key> keys = chain.serializeToProtobuf();
        assertEquals(1, keys.size());
        assertTrue(keys.get(0).hasPublicKey());
        assertFalse(keys.get(0).hasSecretBytes());
        chain = BasicKeyChain.fromProtobufUnencrypted(keys);
        assertEquals(1, chain.numKeys());
        assertFalse(chain.findKeyFromPubKey(pub.getPubKey()).hasPrivKey());
    }

    @Test
    public void bloom() {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();
        chain.importKeys(key1, key2);
        assertEquals(2, chain.numKeys());
        assertEquals(4, chain.numBloomFilterEntries());
        final double FALSE_POSITIVE_RATE = 0.001;
        BloomFilter filter = chain.getFilter(4, FALSE_POSITIVE_RATE, 100);
        assertTrue(filter.contains(key1.getPubKey()));
        assertTrue(filter.contains(key1.getPubKeyHash()));
        assertTrue(filter.contains(key2.getPubKey()));
        assertTrue(filter.contains(key2.getPubKeyHash()));
        final int COUNT = 10000;
        int falsePositives = 0;
        for (int i = 0; i < COUNT; i++) {
            ECKey key = new ECKey();
            if (filter.contains(key.getPubKey()))
                falsePositives++;
        }
        double actualRate = (double) falsePositives / COUNT;
        assertTrue("roughly expected: " + FALSE_POSITIVE_RATE + ", actual: " + actualRate,
                actualRate < FALSE_POSITIVE_RATE * 8);
    }

    @Test
    public void keysBeforeAndAfter() {
        Utils.setMockClock();
        long now = Utils.currentTimeSeconds();
        final ECKey key1 = new ECKey();
        Utils.rollMockClock(86400);
        final ECKey key2 = new ECKey();
        final List<ECKey> keys = Lists.newArrayList(key1, key2);
        assertEquals(2, chain.importKeys(keys));

        assertNull(chain.findOldestKeyAfter(now + 86400 * 2));
        assertEquals(key1, chain.findOldestKeyAfter(now - 1));
        assertEquals(key2, chain.findOldestKeyAfter(now + 86400 - 1));

        assertEquals(2, chain.findKeysBefore(now + 86400 * 2).size());
        assertEquals(1, chain.findKeysBefore(now + 1).size());
        assertEquals(0, chain.findKeysBefore(now - 1).size());
    }
}
