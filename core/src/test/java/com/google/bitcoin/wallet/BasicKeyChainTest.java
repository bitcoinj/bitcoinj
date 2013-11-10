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
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterException;
import com.google.bitcoin.crypto.KeyCrypterScrypt;
import com.google.bitcoin.utils.Threading;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.crypto.params.KeyParameter;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

public class BasicKeyChainTest {
    private BasicKeyChain chain;
    private AtomicReference<List<ECKey>> onKeysAdded;
    private AtomicBoolean onKeysAddedRan;

    @Before
    public void setup() {
        chain = new BasicKeyChain();
        onKeysAdded = new AtomicReference<List<ECKey>>();
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
        final ECKey key1 = new ECKey();
        final ECKey key2 = new ECKey();
        final ArrayList<ECKey> keys = Lists.newArrayList(key1, key2);

        // Import two keys, check the event is correct.
        assertEquals(2, chain.importKeys(keys));
        assertTrue(onKeysAddedRan.getAndSet(false));
        assertArrayEquals(keys.toArray(), onKeysAdded.get().toArray());
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
        chain.encrypt("foo");
        chain.encrypt("foo");
    }

    @Test
    public void encryptDecrypt() {
        final AtomicBoolean listenerRan = new AtomicBoolean();
        chain.addEventListener(new AbstractKeyChainEventListener() {
            @Override
            public void onEncrypt() {
                listenerRan.set(true);
            }
        }, Threading.SAME_THREAD);

        final ECKey key1 = new ECKey();
        final ArrayList<ECKey> keys = Lists.newArrayList(key1, new ECKey());
        chain.importKeys(keys);
        KeyParameter aesKey = chain.encrypt("foobar");
        assertNotNull(aesKey);
        assertTrue(listenerRan.getAndSet(false));
        final KeyCrypter keyCrypter = chain.getKeyCrypter();
        assertNotNull(keyCrypter);
        assertTrue(keyCrypter instanceof KeyCrypterScrypt);

        assertTrue(chain.checkPassword("foobar"));
        assertFalse(chain.checkPassword("wrong"));
        ECKey key = chain.findKeyFromPubKey(key1.getPubKey());
        assertTrue(key.isEncrypted());
        assertNull(key.getPrivKeyBytes());

        try {
            chain.decrypt(keyCrypter.deriveKey("wrong"));
            fail();
        } catch (KeyCrypterException e) {}
        chain.decrypt(aesKey);
        assertTrue(listenerRan.getAndSet(false));
        key = chain.findKeyFromPubKey(key1.getPubKey());
        assertFalse(key.isEncrypted());
        key.getPrivKeyBytes();
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotImportEncryptedKey() {
        final ECKey key1 = new ECKey();
        chain.importKeys(ImmutableList.of(key1));
        chain.encrypt("foobar");
        ECKey encryptedKey = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(encryptedKey.isEncrypted());

        BasicKeyChain chain2 = new BasicKeyChain();
        chain2.importKeys(ImmutableList.of(encryptedKey));
    }
}
