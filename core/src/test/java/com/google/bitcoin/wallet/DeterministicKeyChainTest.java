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

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Joiner;
import org.bitcoinj.wallet.Protos;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;

public class DeterministicKeyChainTest {
    private DeterministicKeyChain chain;

    @Before
    public void setup() {
        // You should use a random seed instead.
        final byte[] seed = "don't use a string seed like this in real life".getBytes();
        final long secs = Utils.currentTimeMillis() / 1000;
        chain = new DeterministicKeyChain(Sha256Hash.create(seed).getBytes(), secs);
        assertEquals(secs, chain.getSeedCreationTimeSecs());
    }

    @Test
    public void mnemonicCode() throws Exception {
        assertEquals("aerobic toe save section draw warm cute upon raccoon mother priority pilot taste sweet next traffic fatal sword dentist original crisp team caution rebel",
                Joiner.on(" ").join(chain.toMnemonicCode()));
    }

    @Test
    public void derive() throws Exception {
        ECKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);

        final Address address = new Address(UnitTestParams.get(), "mtCEpdE8NG1H8YDrZ7mnMSwQorHxNoxWR8");
        assertEquals(address, key1.toAddress(UnitTestParams.get()));
        assertEquals("moxUawkcnyiGqQBq8MRhoTKnwi11W1zu2p", key2.toAddress(UnitTestParams.get()).toString());
        assertEquals(key1, chain.findKeyFromPubHash(address.getHash160()));
        assertEquals(key2, chain.findKeyFromPubKey(key2.getPubKey()));

        ECKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals("n2w2rMFRcxvwSnJsRn3euoTxZQiAJqKVa2", key3.toAddress(UnitTestParams.get()).toString());
    }

    @Test
    public void events() throws Exception {
        final AtomicReference<List<ECKey>> listenerKeys = new AtomicReference<List<ECKey>>();
        chain.addEventListener(new AbstractKeyChainEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> keys) {
                listenerKeys.set(keys);
            }
        }, Threading.SAME_THREAD);
        ECKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key, listenerKeys.get().get(0));
    }

    @Ignore
    @Test
    public void serialize() {
        ECKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);

        List<Protos.Key> keys = chain.serializeToProtobuf();
        assertEquals(3, keys.size());   // 1 root seed and 2 derived keys
        assertEquals(Protos.Key.Type.DETERMINISTIC_ROOT_SEED, keys.get(0).getType());
        assertEquals(Protos.Key.Type.DETERMINISTIC_KEY, keys.get(1).getType());
        assertEquals(Protos.Key.Type.DETERMINISTIC_KEY, keys.get(2).getType());
    }
}
