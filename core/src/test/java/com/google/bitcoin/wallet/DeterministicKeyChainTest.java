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
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.store.UnreadableWalletException;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.io.Resources;
import org.bitcoinj.wallet.Protos;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;

public class DeterministicKeyChainTest {
    private DeterministicKeyChain chain;

    @Before
    public void setup() {
        BriefLogFormatter.init();
        // You should use a random seed instead. The secs constant comes from the unit test file, so we can compare
        // serialized data properly.
        long secs = 1389353062L;
        byte[] SEED = Sha256Hash.create("don't use a string seed like this in real life".getBytes()).getBytes();
        chain = new DeterministicKeyChain(SEED, secs);
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

    @Test
    public void random() {
        // Can't test much here but verify the constructor worked and the class is functional. The other tests rely on
        // a fixed seed to be deterministic.
        chain = new DeterministicKeyChain(new SecureRandom());
        chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        chain.getKey(KeyChain.KeyPurpose.CHANGE);
    }

    @Test
    public void serializeUnencrypted() throws IOException, UnreadableWalletException {
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        List<Protos.Key> keys = chain.serializeToProtobuf();
        assertEquals(8, keys.size());   // 1 root seed, 1 master key, 1 account key, 2 internal keys and 3 derived keys

        // Get another key that will be lost during round-tripping, to ensure we can derive it again.
        DeterministicKey key4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        String sb = protoToString(keys);
        final String EXPECTED_SERIALIZATION = Resources.toString(getClass().getResource("deterministic-wallet-serialization.txt"), Charsets.UTF_8);
        assertEquals(EXPECTED_SERIALIZATION, sb);

        // Round trip the data back and forth to check it is preserved.
        chain = DeterministicKeyChain.parseFrom(keys).get(0);
        assertEquals(EXPECTED_SERIALIZATION, protoToString(chain.serializeToProtobuf()));
        assertEquals(key1, chain.findKeyFromPubHash(key1.getPubKeyHash()));
        assertEquals(key2, chain.findKeyFromPubHash(key2.getPubKeyHash()));
        assertEquals(key3, chain.findKeyFromPubHash(key3.getPubKeyHash()));

        assertEquals(key4, chain.getKey(KeyChain.KeyPurpose.CHANGE));
    }

    @Test
    public void encryption() {

    }

    private String protoToString(List<Protos.Key> keys) {
        StringBuilder sb = new StringBuilder();
        for (Protos.Key key : keys) {
            sb.append(key.toString());
            sb.append("\n");
        }
        return sb.toString().trim();
    }
}
