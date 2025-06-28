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

package org.bitcoinj.crypto;

import org.bitcoinj.base.Network;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.Test;

import java.util.Objects;

import static org.junit.Assert.assertEquals;

/**
 * Test BIP-85 key derivation.  Align with test vectors from <a href="https://bips.xyz/85">https://bips.xyz/85</a>
 * and <a href="https://iancoleman.io/bip39/">https://iancoleman.io/bip39/</a>.
 */
public class DeterministicEntropyTest {

    /**
     * Test derived BIP-85 keys match <a href="https://iancoleman.io/bip39/">https://iancOleman.io/bip39/</a>
     */
    @Test
    public void testIanColeman() throws Exception {

        String mnemonicWords = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        DeterministicSeed seed = DeterministicSeed.ofMnemonic(mnemonicWords, "");
        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(Objects.requireNonNull(seed.getSeedBytes()));

        assertEquals("73c5da0a", Integer.toHexString(key.getFingerprint()));

        assertEquals("prosper short ramp prepare exchange stove life snack client enough purpose fold",
                String.join(" ", DeterministicEntropy.deriveBIP85Mnemonic(key, 12, 0)));

        assertEquals("prosper short ramp prepare exchange stove life snack client enough purpose fold",
                String.join(" ", DeterministicEntropy.deriveBIP85Mnemonic(key, DeterministicEntropy.Language.English, 12, 0)));

        assertEquals("winter brother stamp provide uniform useful doctor prevent venue upper peasant auto view club next clerk tone fox",
                String.join(" ", DeterministicEntropy.deriveBIP85Mnemonic(key, 18, 0)));

        assertEquals("stick exact spice sock filter ginger museum horse kit multiply manual wear grief demand derive alert quiz fault december lava picture immune decade jaguar",
                String.join(" ", DeterministicEntropy.deriveBIP85Mnemonic(key, 24, 0)));
    }

    @Test
    public void testExceptionForInvalidWordCounts() {
        String mnemonicWords = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        DeterministicSeed seed = DeterministicSeed.ofMnemonic(mnemonicWords, "");
        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(Objects.requireNonNull(seed.getSeedBytes()));

        for (int wordCount = 0; wordCount < 30; wordCount++) {
            switch (wordCount) {

                case 12:
                case 18:
                case 24:
                    DeterministicEntropy.deriveBIP85Mnemonic(key, DeterministicEntropy.Language.English, wordCount, 0);
                    break;

                default:
                    try {
                        DeterministicEntropy.deriveBIP85Mnemonic(key, DeterministicEntropy.Language.English, wordCount, 0);
                        throw new RuntimeException("Invalid word count did not throw IllegalArgumentException: " + wordCount);
                    } catch (IllegalArgumentException e) {
                        // we expect failure here
                    }
            }
        }
    }

    /**
     * Test derived BIP-85 keys match test vectors from <a href="https://bips.xyz/85#12-english-words">https://bips.xyz/85#12-english-words</a>
     */
    @Test
    public void test12Words() {
        // Test vector from https://bips.xyz/85#12-english-words
        String xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        Network network = MainNetParams.get().network();
        DeterministicKey masterKey = DeterministicKey.deserializeB58(xprv, network);
        assertEquals("627ef3a6", Integer.toHexString(masterKey.getFingerprint()));

        assertEquals("girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
                String.join(" ", DeterministicEntropy.deriveBIP85Mnemonic(masterKey, 12, 0)));
    }

    /**
     * Test derived BIP-85 keys match test vectors from <a href="https://bips.xyz/85#12-english-words">https://bips.xyz/85#12-english-words</a>
     */
    @Test
    public void test18Words() {
        // Test vector from https://bips.xyz/85#12-english-words
        String xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        Network network = MainNetParams.get().network();
        DeterministicKey masterKey = DeterministicKey.deserializeB58(xprv, network);
        assertEquals("627ef3a6", Integer.toHexString(masterKey.getFingerprint()));

        assertEquals("near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token",
                String.join(" ", DeterministicEntropy.deriveBIP85Mnemonic(masterKey, 18, 0)));
    }

    /**
     * Test derived BIP-85 keys match test vectors from <a href="https://bips.xyz/85#12-english-words">https://bips.xyz/85#12-english-words</a>
     */
    @Test
    public void test24Words() {
        // Test vector from https://bips.xyz/85#12-english-words
        String xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        Network network = MainNetParams.get().network();
        DeterministicKey masterKey = DeterministicKey.deserializeB58(xprv, network);
        assertEquals("627ef3a6", Integer.toHexString(masterKey.getFingerprint()));

        assertEquals("puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano",
                String.join(" ", DeterministicEntropy.deriveBIP85Mnemonic(masterKey, 24, 0)));
    }
}
