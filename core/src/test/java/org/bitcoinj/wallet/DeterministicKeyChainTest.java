/*
 * Copyright 2013 Google Inc.
 * Copyright 2018 Andreas Schildbach
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

import org.bitcoinj.core.Address;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.listeners.AbstractKeyChainEventListener;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.io.Resources;

import org.junit.Before;
import org.junit.Test;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class DeterministicKeyChainTest {
    private DeterministicKeyChain chain;
    private DeterministicKeyChain segwitChain;
    private DeterministicKeyChain bip44chain;
    private final byte[] ENTROPY = Sha256Hash.hash("don't use a string seed like this in real life".getBytes());
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private static final ImmutableList<ChildNumber> BIP44_ACCOUNT_ONE_PATH = ImmutableList.of(new ChildNumber(44, true),
            new ChildNumber(1, true), ChildNumber.ZERO_HARDENED);

    @Before
    public void setup() {
        BriefLogFormatter.init();
        // You should use a random seed instead. The secs constant comes from the unit test file, so we can compare
        // serialized data properly.
        long secs = 1389353062L;
        chain = DeterministicKeyChain.builder().entropy(ENTROPY, secs)
                .accountPath(DeterministicKeyChain.ACCOUNT_ZERO_PATH).outputScriptType(Script.ScriptType.P2PKH).build();
        chain.setLookaheadSize(10);

        segwitChain = DeterministicKeyChain.builder().entropy(ENTROPY, secs)
                .accountPath(DeterministicKeyChain.ACCOUNT_ONE_PATH).outputScriptType(Script.ScriptType.P2WPKH).build();
        segwitChain.setLookaheadSize(10);

        bip44chain = DeterministicKeyChain.builder().entropy(ENTROPY, secs).accountPath(BIP44_ACCOUNT_ONE_PATH)
                .outputScriptType(Script.ScriptType.P2PKH).build();
        bip44chain.setLookaheadSize(10);
    }

    @Test
    public void derive() throws Exception {
        ECKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertFalse(key1.isPubKeyOnly());
        ECKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertFalse(key2.isPubKeyOnly());

        final Address address = LegacyAddress.fromBase58(UNITTEST, "n1bQNoEx8uhmCzzA5JPG6sFdtsUQhwiQJV");
        assertEquals(address, LegacyAddress.fromKey(UNITTEST, key1));
        assertEquals("mnHUcqUVvrfi5kAaXJDQzBb9HsWs78b42R", LegacyAddress.fromKey(UNITTEST, key2).toString());
        assertEquals(key1, chain.findKeyFromPubHash(address.getHash()));
        assertEquals(key2, chain.findKeyFromPubKey(key2.getPubKey()));

        key1.sign(Sha256Hash.ZERO_HASH);
        assertFalse(key1.isPubKeyOnly());

        ECKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertFalse(key3.isPubKeyOnly());
        assertEquals("mqumHgVDqNzuXNrszBmi7A2UpmwaPMx4HQ", LegacyAddress.fromKey(UNITTEST, key3).toString());
        key3.sign(Sha256Hash.ZERO_HASH);
        assertFalse(key3.isPubKeyOnly());
    }

    @Test
    public void getKeys() throws Exception {
        chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        chain.getKey(KeyChain.KeyPurpose.CHANGE);
        chain.maybeLookAhead();
        assertEquals(2, chain.getKeys(false, false).size());
    }

    @Test
    public void deriveAccountOne() throws Exception {
        final long secs = 1389353062L;
        final ImmutableList<ChildNumber> accountOne = ImmutableList.of(ChildNumber.ONE);
        DeterministicKeyChain chain1 = DeterministicKeyChain.builder().accountPath(accountOne)
                .entropy(ENTROPY, secs).build();
        ECKey key1 = chain1.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey key2 = chain1.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);

        final Address address = LegacyAddress.fromBase58(UNITTEST, "n2nHHRHs7TiZScTuVhZUkzZfTfVgGYwy6X");
        assertEquals(address, LegacyAddress.fromKey(UNITTEST, key1));
        assertEquals("mnp2j9za5zMuz44vNxrJCXXhZsCdh89QXn", LegacyAddress.fromKey(UNITTEST, key2).toString());
        assertEquals(key1, chain1.findKeyFromPubHash(address.getHash()));
        assertEquals(key2, chain1.findKeyFromPubKey(key2.getPubKey()));

        key1.sign(Sha256Hash.ZERO_HASH);

        ECKey key3 = chain1.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals("mpjRhk13rvV7vmnszcUQVYVQzy4HLTPTQU", LegacyAddress.fromKey(UNITTEST, key3).toString());
        key3.sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void serializeAccountOne() throws Exception {
        final long secs = 1389353062L;
        final ImmutableList<ChildNumber> accountOne = ImmutableList.of(ChildNumber.ONE);
        DeterministicKeyChain chain1 = DeterministicKeyChain.builder().accountPath(accountOne)
                .entropy(ENTROPY, secs).build();
        ECKey key1 = chain1.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);

        final Address address = LegacyAddress.fromBase58(UNITTEST, "n2nHHRHs7TiZScTuVhZUkzZfTfVgGYwy6X");
        assertEquals(address, LegacyAddress.fromKey(UNITTEST, key1));

        DeterministicKey watching = chain1.getWatchingKey();

        List<Protos.Key> keys = chain1.serializeToProtobuf();
        chain1 = DeterministicKeyChain.fromProtobuf(keys, null).get(0);
        assertEquals(accountOne, chain1.getAccountPath());

        ECKey key2 = chain1.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertEquals("mnp2j9za5zMuz44vNxrJCXXhZsCdh89QXn", LegacyAddress.fromKey(UNITTEST, key2).toString());
        assertEquals(key1, chain1.findKeyFromPubHash(address.getHash()));
        assertEquals(key2, chain1.findKeyFromPubKey(key2.getPubKey()));

        key1.sign(Sha256Hash.ZERO_HASH);

        ECKey key3 = chain1.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals("mpjRhk13rvV7vmnszcUQVYVQzy4HLTPTQU", LegacyAddress.fromKey(UNITTEST, key3).toString());
        key3.sign(Sha256Hash.ZERO_HASH);

        assertEquals(watching, chain1.getWatchingKey());
    }

    @Test
    public void signMessage() throws Exception {
        ECKey key = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        key.verifyMessage("test", key.signMessage("test"));
    }

    @Test
    public void events() throws Exception {
        // Check that we get the right events at the right time.
        final List<List<ECKey>> listenerKeys = Lists.newArrayList();
        long secs = 1389353062L;
        chain = DeterministicKeyChain.builder().entropy(ENTROPY, secs).outputScriptType(Script.ScriptType.P2PKH)
                .build();
        chain.addEventListener(new AbstractKeyChainEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> keys) {
                listenerKeys.add(keys);
            }
        }, Threading.SAME_THREAD);
        assertEquals(0, listenerKeys.size());
        chain.setLookaheadSize(5);
        assertEquals(0, listenerKeys.size());
        ECKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(1, listenerKeys.size());  // 1 event
        final List<ECKey> firstEvent = listenerKeys.get(0);
        assertEquals(1, firstEvent.size());
        assertTrue(firstEvent.contains(key));   // order is not specified.
        listenerKeys.clear();

        chain.maybeLookAhead();
        final List<ECKey> secondEvent = listenerKeys.get(0);
        assertEquals(12, secondEvent.size());  // (5 lookahead keys, +1 lookahead threshold) * 2 chains
        listenerKeys.clear();

        chain.getKey(KeyChain.KeyPurpose.CHANGE);
        // At this point we've entered the threshold zone so more keys won't immediately trigger more generations.
        assertEquals(0, listenerKeys.size());  // 1 event
        final int lookaheadThreshold = chain.getLookaheadThreshold() + chain.getLookaheadSize();
        for (int i = 0; i < lookaheadThreshold; i++)
            chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(1, listenerKeys.size());  // 1 event
        assertEquals(1, listenerKeys.get(0).size());  // 1 key.
    }

    @Test
    public void random() {
        // Can't test much here but verify the constructor worked and the class is functional. The other tests rely on
        // a fixed seed to be deterministic.
        chain = DeterministicKeyChain.builder().random(new SecureRandom(), 384).build();
        chain.setLookaheadSize(10);
        chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).sign(Sha256Hash.ZERO_HASH);
        chain.getKey(KeyChain.KeyPurpose.CHANGE).sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void serializeUnencrypted() throws UnreadableWalletException {
        chain.maybeLookAhead();
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        List<Protos.Key> keys = chain.serializeToProtobuf();
        // 1 mnemonic/seed, 1 master key, 1 account key, 2 internal keys, 3 derived, 20 lookahead and 5 lookahead threshold.
        int numItems =
                1  // mnemonic/seed
              + 1  // master key
              + 1  // account key
              + 2  // ext/int parent keys
              + (chain.getLookaheadSize() + chain.getLookaheadThreshold()) * 2   // lookahead zone on each chain
        ;
        assertEquals(numItems, keys.size());

        // Get another key that will be lost during round-tripping, to ensure we can derive it again.
        DeterministicKey key4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        final String EXPECTED_SERIALIZATION = checkSerialization(keys, "deterministic-wallet-serialization.txt");

        // Round trip the data back and forth to check it is preserved.
        int oldLookaheadSize = chain.getLookaheadSize();
        chain = DeterministicKeyChain.fromProtobuf(keys, null).get(0);
        assertEquals(DeterministicKeyChain.ACCOUNT_ZERO_PATH, chain.getAccountPath());
        assertEquals(EXPECTED_SERIALIZATION, protoToString(chain.serializeToProtobuf()));
        assertEquals(key1, chain.findKeyFromPubHash(key1.getPubKeyHash()));
        assertEquals(key2, chain.findKeyFromPubHash(key2.getPubKeyHash()));
        assertEquals(key3, chain.findKeyFromPubHash(key3.getPubKeyHash()));
        assertEquals(key4, chain.getKey(KeyChain.KeyPurpose.CHANGE));
        key1.sign(Sha256Hash.ZERO_HASH);
        key2.sign(Sha256Hash.ZERO_HASH);
        key3.sign(Sha256Hash.ZERO_HASH);
        key4.sign(Sha256Hash.ZERO_HASH);
        assertEquals(oldLookaheadSize, chain.getLookaheadSize());
    }

    @Test
    public void serializeSegwitUnencrypted() throws UnreadableWalletException {
        segwitChain.maybeLookAhead();
        DeterministicKey key1 = segwitChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = segwitChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = segwitChain.getKey(KeyChain.KeyPurpose.CHANGE);
        List<Protos.Key> keys = segwitChain.serializeToProtobuf();
        // 1 mnemonic/seed, 1 master key, 1 account key, 2 internal keys, 3 derived, 20 lookahead and 5 lookahead threshold.
        int numItems =
                1  // mnemonic/seed
              + 1  // master key
              + 1  // account key
              + 2  // ext/int parent keys
              + (segwitChain.getLookaheadSize() + segwitChain.getLookaheadThreshold()) * 2   // lookahead zone on each chain
        ;
        assertEquals(numItems, keys.size());

        // Get another key that will be lost during round-tripping, to ensure we can derive it again.
        DeterministicKey key4 = segwitChain.getKey(KeyChain.KeyPurpose.CHANGE);

        final String EXPECTED_SERIALIZATION = checkSerialization(keys, "deterministic-wallet-segwit-serialization.txt");

        // Round trip the data back and forth to check it is preserved.
        int oldLookaheadSize = segwitChain.getLookaheadSize();
        segwitChain = DeterministicKeyChain.fromProtobuf(keys, null).get(0);
        assertEquals(EXPECTED_SERIALIZATION, protoToString(segwitChain.serializeToProtobuf()));
        assertEquals(key1, segwitChain.findKeyFromPubHash(key1.getPubKeyHash()));
        assertEquals(key2, segwitChain.findKeyFromPubHash(key2.getPubKeyHash()));
        assertEquals(key3, segwitChain.findKeyFromPubHash(key3.getPubKeyHash()));
        assertEquals(key4, segwitChain.getKey(KeyChain.KeyPurpose.CHANGE));
        key1.sign(Sha256Hash.ZERO_HASH);
        key2.sign(Sha256Hash.ZERO_HASH);
        key3.sign(Sha256Hash.ZERO_HASH);
        key4.sign(Sha256Hash.ZERO_HASH);
        assertEquals(oldLookaheadSize, segwitChain.getLookaheadSize());
    }

    @Test
    public void serializeUnencryptedBIP44() throws UnreadableWalletException {
        bip44chain.maybeLookAhead();
        DeterministicKey key1 = bip44chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = bip44chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = bip44chain.getKey(KeyChain.KeyPurpose.CHANGE);
        List<Protos.Key> keys = bip44chain.serializeToProtobuf();
        // 1 mnemonic/seed, 1 master key, 1 account key, 2 internal keys, 3 derived, 20 lookahead and 5 lookahead
        // threshold.
        int numItems = 3 // mnemonic/seed
                + 1 // master key
                + 1 // account key
                + 2 // ext/int parent keys
                + (bip44chain.getLookaheadSize() + bip44chain.getLookaheadThreshold()) * 2 // lookahead zone on each chain
        ;
        assertEquals(numItems, keys.size());

        // Get another key that will be lost during round-tripping, to ensure we can derive it again.
        DeterministicKey key4 = bip44chain.getKey(KeyChain.KeyPurpose.CHANGE);

        final String EXPECTED_SERIALIZATION = checkSerialization(keys, "deterministic-wallet-bip44-serialization.txt");

        // Round trip the data back and forth to check it is preserved.
        int oldLookaheadSize = bip44chain.getLookaheadSize();
        bip44chain = DeterministicKeyChain.fromProtobuf(keys, null).get(0);
        assertEquals(BIP44_ACCOUNT_ONE_PATH, bip44chain.getAccountPath());
        assertEquals(EXPECTED_SERIALIZATION, protoToString(bip44chain.serializeToProtobuf()));
        assertEquals(key1, bip44chain.findKeyFromPubHash(key1.getPubKeyHash()));
        assertEquals(key2, bip44chain.findKeyFromPubHash(key2.getPubKeyHash()));
        assertEquals(key3, bip44chain.findKeyFromPubHash(key3.getPubKeyHash()));
        assertEquals(key4, bip44chain.getKey(KeyChain.KeyPurpose.CHANGE));
        key1.sign(Sha256Hash.ZERO_HASH);
        key2.sign(Sha256Hash.ZERO_HASH);
        key3.sign(Sha256Hash.ZERO_HASH);
        key4.sign(Sha256Hash.ZERO_HASH);
        assertEquals(oldLookaheadSize, bip44chain.getLookaheadSize());
    }

    @Test(expected = IllegalStateException.class)
    public void notEncrypted() {
        chain.toDecrypted("fail");
    }

    @Test(expected = IllegalStateException.class)
    public void encryptTwice() {
        chain = chain.toEncrypted("once");
        chain = chain.toEncrypted("twice");
    }

    private void checkEncryptedKeyChain(DeterministicKeyChain encChain, DeterministicKey key1) {
        // Check we can look keys up and extend the chain without the AES key being provided.
        DeterministicKey encKey1 = encChain.findKeyFromPubKey(key1.getPubKey());
        DeterministicKey encKey2 = encChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertFalse(key1.isEncrypted());
        assertTrue(encKey1.isEncrypted());
        assertEquals(encKey1.getPubKeyPoint(), key1.getPubKeyPoint());
        final KeyParameter aesKey = checkNotNull(encChain.getKeyCrypter()).deriveKey("open secret");
        encKey1.sign(Sha256Hash.ZERO_HASH, aesKey);
        encKey2.sign(Sha256Hash.ZERO_HASH, aesKey);
        assertTrue(encChain.checkAESKey(aesKey));
        assertFalse(encChain.checkPassword("access denied"));
        assertTrue(encChain.checkPassword("open secret"));
    }

    @Test
    public void encryption() throws UnreadableWalletException {
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKeyChain encChain = chain.toEncrypted("open secret");
        DeterministicKey encKey1 = encChain.findKeyFromPubKey(key1.getPubKey());
        checkEncryptedKeyChain(encChain, key1);

        // Round-trip to ensure de/serialization works and that we can store two chains and they both deserialize.
        List<Protos.Key> serialized = encChain.serializeToProtobuf();
        List<Protos.Key> doubled = Lists.newArrayListWithExpectedSize(serialized.size() * 2);
        doubled.addAll(serialized);
        doubled.addAll(serialized);
        final List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(doubled, encChain.getKeyCrypter());
        assertEquals(2, chains.size());
        encChain = chains.get(0);
        checkEncryptedKeyChain(encChain, chain.findKeyFromPubKey(key1.getPubKey()));
        encChain = chains.get(1);
        checkEncryptedKeyChain(encChain, chain.findKeyFromPubKey(key1.getPubKey()));

        DeterministicKey encKey2 = encChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        // Decrypt and check the keys match.
        DeterministicKeyChain decChain = encChain.toDecrypted("open secret");
        DeterministicKey decKey1 = decChain.findKeyFromPubHash(encKey1.getPubKeyHash());
        DeterministicKey decKey2 = decChain.findKeyFromPubHash(encKey2.getPubKeyHash());
        assertEquals(decKey1.getPubKeyPoint(), encKey1.getPubKeyPoint());
        assertEquals(decKey2.getPubKeyPoint(), encKey2.getPubKeyPoint());
        assertFalse(decKey1.isEncrypted());
        assertFalse(decKey2.isEncrypted());
        assertNotEquals(encKey1.getParent(), decKey1.getParent());   // parts of a different hierarchy
        // Check we can once again derive keys from the decrypted chain.
        decChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).sign(Sha256Hash.ZERO_HASH);
        decChain.getKey(KeyChain.KeyPurpose.CHANGE).sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void watchingChain() throws UnreadableWalletException {
        Utils.setMockClock();
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey key4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        DeterministicKey watchingKey = chain.getWatchingKey();
        final String pub58 = watchingKey.serializePubB58(MAINNET);
        assertEquals("xpub69KR9epSNBM59KLuasxMU5CyKytMJjBP5HEZ5p8YoGUCpM6cM9hqxB9DDPCpUUtqmw5duTckvPfwpoWGQUFPmRLpxs5jYiTf2u6xRMcdhDf", pub58);
        watchingKey = DeterministicKey.deserializeB58(null, pub58, MAINNET);
        watchingKey.setCreationTimeSeconds(100000);
        chain = DeterministicKeyChain.builder().watch(watchingKey).outputScriptType(chain.getOutputScriptType())
                .build();
        assertEquals(100000, chain.getEarliestKeyCreationTime());
        chain.setLookaheadSize(10);
        chain.maybeLookAhead();

        assertEquals(key1.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        assertEquals(key2.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        final DeterministicKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key3.getPubKeyPoint(), key.getPubKeyPoint());
        try {
            // Can't sign with a key from a watching chain.
            key.sign(Sha256Hash.ZERO_HASH);
            fail();
        } catch (ECKey.MissingPrivateKeyException e) {
            // Ignored.
        }
        // Test we can serialize and deserialize a watching chain OK.
        List<Protos.Key> serialization = chain.serializeToProtobuf();
        checkSerialization(serialization, "watching-wallet-serialization.txt");
        chain = DeterministicKeyChain.fromProtobuf(serialization, null).get(0);
        assertEquals(DeterministicKeyChain.ACCOUNT_ZERO_PATH, chain.getAccountPath());
        final DeterministicKey rekey4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key4.getPubKeyPoint(), rekey4.getPubKeyPoint());
    }

    @Test
    public void watchingChainArbitraryPath() throws UnreadableWalletException {
        Utils.setMockClock();
        DeterministicKey key1 = bip44chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = bip44chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = bip44chain.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey key4 = bip44chain.getKey(KeyChain.KeyPurpose.CHANGE);

        DeterministicKey watchingKey = bip44chain.getWatchingKey();
        watchingKey = watchingKey.dropPrivateBytes().dropParent();
        watchingKey.setCreationTimeSeconds(100000);
        chain = DeterministicKeyChain.builder().watch(watchingKey).outputScriptType(bip44chain.getOutputScriptType())
                .build();
        assertEquals(100000, chain.getEarliestKeyCreationTime());
        chain.setLookaheadSize(10);
        chain.maybeLookAhead();

        assertEquals(key1.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        assertEquals(key2.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        final DeterministicKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key3.getPubKeyPoint(), key.getPubKeyPoint());
        try {
            // Can't sign with a key from a watching chain.
            key.sign(Sha256Hash.ZERO_HASH);
            fail();
        } catch (ECKey.MissingPrivateKeyException e) {
            // Ignored.
        }
        // Test we can serialize and deserialize a watching chain OK.
        List<Protos.Key> serialization = chain.serializeToProtobuf();
        checkSerialization(serialization, "watching-wallet-arbitrary-path-serialization.txt");
        chain = DeterministicKeyChain.fromProtobuf(serialization, null).get(0);
        assertEquals(BIP44_ACCOUNT_ONE_PATH, chain.getAccountPath());
        final DeterministicKey rekey4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key4.getPubKeyPoint(), rekey4.getPubKeyPoint());
    }

    @Test
    public void watchingChainAccountOne() throws UnreadableWalletException {
        Utils.setMockClock();
        final ImmutableList<ChildNumber> accountOne = ImmutableList.of(ChildNumber.ONE);
        DeterministicKeyChain chain1 = DeterministicKeyChain.builder().accountPath(accountOne)
                .seed(chain.getSeed()).build();
        DeterministicKey key1 = chain1.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = chain1.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = chain1.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey key4 = chain1.getKey(KeyChain.KeyPurpose.CHANGE);

        DeterministicKey watchingKey = chain1.getWatchingKey();
        final String pub58 = watchingKey.serializePubB58(MAINNET);
        assertEquals("xpub69KR9epJ2Wp6ywiv4Xu5WfBUpX4GLu6D5NUMd4oUkCFoZoRNyk3ZCxfKPDkkGvCPa16dPgEdY63qoyLqEa5TQQy1nmfSmgWcagRzimyV7uA", pub58);
        watchingKey = DeterministicKey.deserializeB58(null, pub58, MAINNET);
        watchingKey.setCreationTimeSeconds(100000);
        chain = DeterministicKeyChain.builder().watch(watchingKey).outputScriptType(chain1.getOutputScriptType())
                .build();
        assertEquals(accountOne, chain.getAccountPath());
        assertEquals(100000, chain.getEarliestKeyCreationTime());
        chain.setLookaheadSize(10);
        chain.maybeLookAhead();

        assertEquals(key1.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        assertEquals(key2.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        final DeterministicKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key3.getPubKeyPoint(), key.getPubKeyPoint());
        try {
            // Can't sign with a key from a watching chain.
            key.sign(Sha256Hash.ZERO_HASH);
            fail();
        } catch (ECKey.MissingPrivateKeyException e) {
            // Ignored.
        }
        // Test we can serialize and deserialize a watching chain OK.
        List<Protos.Key> serialization = chain.serializeToProtobuf();
        checkSerialization(serialization, "watching-wallet-serialization-account-one.txt");
        chain = DeterministicKeyChain.fromProtobuf(serialization, null).get(0);
        assertEquals(accountOne, chain.getAccountPath());
        final DeterministicKey rekey4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key4.getPubKeyPoint(), rekey4.getPubKeyPoint());
    }

    @Test
    public void watchingSegwitChain() throws UnreadableWalletException {
        Utils.setMockClock();
        DeterministicKey key1 = segwitChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = segwitChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = segwitChain.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey key4 = segwitChain.getKey(KeyChain.KeyPurpose.CHANGE);

        DeterministicKey watchingKey = segwitChain.getWatchingKey();
        final String pub58 = watchingKey.serializePubB58(MAINNET, segwitChain.getOutputScriptType());
        assertEquals("zpub6nywkzAGfYS2siEfJtm9mo3hwDk8eUtL8EJ31XeWSd7C7x7esnfMMWmWiSs8od5jRt11arTjKLLbxCXuWNSXcxpi9PMSAphMt2ZE2gLnXGE", pub58);
        watchingKey = DeterministicKey.deserializeB58(null, pub58, MAINNET);
        watchingKey.setCreationTimeSeconds(100000);
        segwitChain = DeterministicKeyChain.builder().watch(watchingKey)
                .outputScriptType(segwitChain.getOutputScriptType()).build();
        assertEquals(100000, segwitChain.getEarliestKeyCreationTime());
        segwitChain.setLookaheadSize(10);
        segwitChain.maybeLookAhead();

        assertEquals(key1.getPubKeyPoint(), segwitChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        assertEquals(key2.getPubKeyPoint(), segwitChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        final DeterministicKey key = segwitChain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key3.getPubKeyPoint(), key.getPubKeyPoint());
        try {
            // Can't sign with a key from a watching chain.
            key.sign(Sha256Hash.ZERO_HASH);
            fail();
        } catch (ECKey.MissingPrivateKeyException e) {
            // Ignored.
        }
        // Test we can serialize and deserialize a watching chain OK.
        List<Protos.Key> serialization = segwitChain.serializeToProtobuf();
        checkSerialization(serialization, "watching-wallet-p2wpkh-serialization.txt");
        final DeterministicKeyChain chain = DeterministicKeyChain.fromProtobuf(serialization, null).get(0);
        assertEquals(DeterministicKeyChain.ACCOUNT_ONE_PATH, chain.getAccountPath());
        assertEquals(Script.ScriptType.P2WPKH, chain.getOutputScriptType());
        final DeterministicKey rekey4 = segwitChain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key4.getPubKeyPoint(), rekey4.getPubKeyPoint());
    }

    @Test
    public void spendingChain() throws UnreadableWalletException {
        Utils.setMockClock();
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey key4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        NetworkParameters params = MainNetParams.get();
        DeterministicKey watchingKey = chain.getWatchingKey();
        final String prv58 = watchingKey.serializePrivB58(params);
        assertEquals("xprv9vL4k9HYXonmvqGSUrRM6wGEmx3ruGTXi4JxHRiwEvwDwYmTocPbQNpjN89gpqPrFofmfvALwgnNFBCH2grse1YDf8ERAwgdvbjRtoMfsbV", prv58);
        watchingKey = DeterministicKey.deserializeB58(null, prv58, params);
        watchingKey.setCreationTimeSeconds(100000);
        chain = DeterministicKeyChain.builder().spend(watchingKey).outputScriptType(chain.getOutputScriptType())
                .build();
        assertEquals(100000, chain.getEarliestKeyCreationTime());
        chain.setLookaheadSize(10);
        chain.maybeLookAhead();

        assertEquals(key1.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        assertEquals(key2.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        final DeterministicKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key3.getPubKeyPoint(), key.getPubKeyPoint());
        try {
            // We can sign with a key from a spending chain.
            key.sign(Sha256Hash.ZERO_HASH);
        } catch (ECKey.MissingPrivateKeyException e) {
            fail();
        }
        // Test we can serialize and deserialize a watching chain OK.
        List<Protos.Key> serialization = chain.serializeToProtobuf();
        checkSerialization(serialization, "spending-wallet-serialization.txt");
        chain = DeterministicKeyChain.fromProtobuf(serialization, null).get(0);
        assertEquals(DeterministicKeyChain.ACCOUNT_ZERO_PATH, chain.getAccountPath());
        final DeterministicKey rekey4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key4.getPubKeyPoint(), rekey4.getPubKeyPoint());
    }

    @Test
    public void spendingChainAccountTwo() throws UnreadableWalletException {
        Utils.setMockClock();
        final long secs = 1389353062L;
        final ImmutableList<ChildNumber> accountTwo = ImmutableList.of(new ChildNumber(2, true));
        chain = DeterministicKeyChain.builder().accountPath(accountTwo).entropy(ENTROPY, secs).build();
        DeterministicKey firstReceiveKey = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey secondReceiveKey = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey firstChangeKey = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey secondChangeKey = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        NetworkParameters params = MainNetParams.get();
        DeterministicKey watchingKey = chain.getWatchingKey();

        final String prv58 = watchingKey.serializePrivB58(params);
        assertEquals("xprv9vL4k9HYXonmzR7UC1ngJ3hTjxkmjLLUo3RexSfUGSWcACHzghWBLJAwW6xzs59XeFizQxFQWtscoTfrF9PSXrUgAtBgr13Nuojax8xTBRz", prv58);
        watchingKey = DeterministicKey.deserializeB58(null, prv58, params);
        watchingKey.setCreationTimeSeconds(secs);
        chain = DeterministicKeyChain.builder().spend(watchingKey).outputScriptType(chain.getOutputScriptType())
                .build();
        assertEquals(accountTwo, chain.getAccountPath());
        assertEquals(secs, chain.getEarliestKeyCreationTime());
        chain.setLookaheadSize(10);
        chain.maybeLookAhead();

        verifySpendableKeyChain(firstReceiveKey, secondReceiveKey, firstChangeKey, secondChangeKey, chain, "spending-wallet-account-two-serialization.txt");
    }

    @Test
    public void masterKeyAccount() throws UnreadableWalletException {
        Utils.setMockClock();
        long secs = 1389353062L;
        DeterministicKey firstReceiveKey = bip44chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey secondReceiveKey = bip44chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey firstChangeKey = bip44chain.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey secondChangeKey = bip44chain.getKey(KeyChain.KeyPurpose.CHANGE);

        NetworkParameters params = MainNetParams.get();
        DeterministicKey watchingKey = bip44chain.getWatchingKey(); //m/44'/1'/0'
        DeterministicKey coinLevelKey = bip44chain.getWatchingKey().getParent(); //m/44'/1'

        //Simulate Wallet.fromSpendingKeyB58(PARAMS, prv58, secs)
        final String prv58 = watchingKey.serializePrivB58(params);
        assertEquals("xprv9yYQhynAmWWuz62PScx5Q2frBET2F1raaXna5A2E9Lj8XWgmKBL7S98Yand8F736j9UCTNWQeiB4yL5pLZP7JDY2tY8eszGQkiKDwBkezeS", prv58);
        watchingKey = DeterministicKey.deserializeB58(null, prv58, params);
        watchingKey.setCreationTimeSeconds(secs);
        DeterministicKeyChain fromPrivBase58Chain = DeterministicKeyChain.builder().spend(watchingKey)
                .outputScriptType(bip44chain.getOutputScriptType()).build();
        assertEquals(secs, fromPrivBase58Chain.getEarliestKeyCreationTime());
        fromPrivBase58Chain.setLookaheadSize(10);
        fromPrivBase58Chain.maybeLookAhead();

        verifySpendableKeyChain(firstReceiveKey, secondReceiveKey, firstChangeKey, secondChangeKey, fromPrivBase58Chain, "spending-wallet-from-bip44-serialization.txt");

        //Simulate Wallet.fromMasterKey(params, coinLevelKey, 0)
        DeterministicKey accountKey = HDKeyDerivation.deriveChildKey(coinLevelKey, new ChildNumber(0, true));
        accountKey = accountKey.dropParent();
        accountKey.setCreationTimeSeconds(watchingKey.getCreationTimeSeconds());
        KeyChainGroup group = KeyChainGroup.builder(params).addChain(DeterministicKeyChain.builder().spend(accountKey)
                .outputScriptType(bip44chain.getOutputScriptType()).build()).build();
        DeterministicKeyChain fromMasterKeyChain = group.getActiveKeyChain();
        assertEquals(BIP44_ACCOUNT_ONE_PATH, fromMasterKeyChain.getAccountPath());
        assertEquals(secs, fromMasterKeyChain.getEarliestKeyCreationTime());
        fromMasterKeyChain.setLookaheadSize(10);
        fromMasterKeyChain.maybeLookAhead();

        verifySpendableKeyChain(firstReceiveKey, secondReceiveKey, firstChangeKey, secondChangeKey, fromMasterKeyChain, "spending-wallet-from-bip44-serialization-two.txt");
    }

    /**
     * verifySpendableKeyChain
     *
     * firstReceiveKey and secondReceiveKey are the first two keys of the external chain of a known key chain
     * firstChangeKey and secondChangeKey are the first two keys of the internal chain of a known key chain
     * keyChain is a DeterministicKeyChain loaded from a serialized format or derived in some other way from
     * the known key chain
     *
     * This method verifies that known keys match a newly created keyChain and that keyChain's protobuf
     * matches the serializationFile.
     */
    private void verifySpendableKeyChain(DeterministicKey firstReceiveKey, DeterministicKey secondReceiveKey,
                                         DeterministicKey firstChangeKey, DeterministicKey secondChangeKey,
                                         DeterministicKeyChain keyChain, String serializationFile) throws UnreadableWalletException {

        //verify that the keys are the same as the keyChain
        assertEquals(firstReceiveKey.getPubKeyPoint(), keyChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        assertEquals(secondReceiveKey.getPubKeyPoint(), keyChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        final DeterministicKey key = keyChain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(firstChangeKey.getPubKeyPoint(), key.getPubKeyPoint());

        try {
            key.sign(Sha256Hash.ZERO_HASH);
        } catch (ECKey.MissingPrivateKeyException e) {
            // We can sign with a key from a spending chain.
            fail();
        }

        // Test we can serialize and deserialize the chain OK
        List<Protos.Key> serialization = keyChain.serializeToProtobuf();
        checkSerialization(serialization, serializationFile);

        // Check that the second change key matches after loading from the serialization, serializing and deserializing
        long secs = keyChain.getEarliestKeyCreationTime();
        keyChain = DeterministicKeyChain.fromProtobuf(serialization, null).get(0);
        serialization = keyChain.serializeToProtobuf();
        checkSerialization(serialization, serializationFile);
        assertEquals(secs, keyChain.getEarliestKeyCreationTime());
        final DeterministicKey nextChangeKey = keyChain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(secondChangeKey.getPubKeyPoint(), nextChangeKey.getPubKeyPoint());
    }

    @Test(expected = IllegalStateException.class)
    public void watchingCannotEncrypt() throws Exception {
        final DeterministicKey accountKey = chain.getKeyByPath(DeterministicKeyChain.ACCOUNT_ZERO_PATH);
        chain = DeterministicKeyChain.builder().watch(accountKey.dropPrivateBytes().dropParent())
                .outputScriptType(chain.getOutputScriptType()).build();
        assertEquals(DeterministicKeyChain.ACCOUNT_ZERO_PATH, chain.getAccountPath());
        chain = chain.toEncrypted("this doesn't make any sense");
    }

    @Test
    public void bloom1() {
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);

        int numEntries =
                (((chain.getLookaheadSize() + chain.getLookaheadThreshold()) * 2)   // * 2 because of internal/external
              + chain.numLeafKeysIssued()
              + 4  // one root key + one account key + two chain keys (internal/external)
                ) * 2;  // because the filter contains keys and key hashes.
        assertEquals(numEntries, chain.numBloomFilterEntries());
        BloomFilter filter = chain.getFilter(numEntries, 0.001, 1);
        assertTrue(filter.contains(key1.getPubKey()));
        assertTrue(filter.contains(key1.getPubKeyHash()));
        assertTrue(filter.contains(key2.getPubKey()));
        assertTrue(filter.contains(key2.getPubKeyHash()));

        // The lookahead zone is tested in bloom2 and via KeyChainGroupTest.bloom
    }

    @Test
    public void bloom2() throws Exception {
        // Verify that if when we watch a key, the filter contains at least 100 keys.
        DeterministicKey[] keys = new DeterministicKey[100];
        for (int i = 0; i < keys.length; i++)
            keys[i] = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        chain = DeterministicKeyChain.builder().watch(chain.getWatchingKey().dropPrivateBytes().dropParent())
                .outputScriptType(chain.getOutputScriptType()).build();
        int e = chain.numBloomFilterEntries();
        BloomFilter filter = chain.getFilter(e, 0.001, 1);
        for (DeterministicKey key : keys)
            assertTrue("key " + key, filter.contains(key.getPubKeyHash()));
    }

    private String protoToString(List<Protos.Key> keys) {
        StringBuilder sb = new StringBuilder();
        for (Protos.Key key : keys) {
            sb.append(key.toString());
            sb.append("\n");
        }
        return sb.toString().trim();
    }

    private String checkSerialization(List<Protos.Key> keys, String filename) {
        try {
            String sb = protoToString(keys);
            List<String> lines = Resources.readLines(getClass().getResource(filename), StandardCharsets.UTF_8);
            String expected = Joiner.on('\n').join(lines);
            assertEquals(expected, sb);
            return expected;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
