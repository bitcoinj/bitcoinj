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

import org.bitcoinj.base.internal.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class for working with BIP-85, generating wallets, etc. (<a href="https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki">https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki</a>).
 * <p>
 * See test class org.bitcoinj.crypto.DeterministicEntropyTest for examples on how to use this class.
 */
public class DeterministicEntropy {
    private static final Logger logger = LoggerFactory.getLogger(DeterministicEntropy.class);

    private DeterministicEntropy() {
    }

    /**
     * Derive a BIP-85 key and return the corresponding BIP-39 mnemonic seed phrase.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param language         0 for English, see BIP-39 for other languages <a href="https://bips.xyz/85#bip39">https://bips.xyz/85#bip39</a>.
     * @param wordCount        12, 18, or 24 for BIP-39 word counts.
     * @param index            0 to 9999 for the index of the child key.
     * @return Seed Phrase for the derived BIP-85 deterministic key.
     */
    public static String deriveBIP85Mnemonic(DeterministicKey masterPrivateKey, int language, int wordCount, int index) {
        int[] derivationPath = {83696968, 39, language, wordCount, index};
        return deriveBIP85Mnemonic(masterPrivateKey, derivationPath);
    }

    /**
     * Derive a BIP-85 key and return the corresponding BIP-39 mnemonic seed phrase.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param wordCount        12, 18, or 24 for BIP-39 word counts.
     * @param index            0 to 9999 for the index of the child key.
     * @return Seed Phrase for the derived BIP-85 deterministic key.
     */
    public static String deriveBIP85Mnemonic(DeterministicKey masterPrivateKey, int wordCount, int index) {
        int[] derivationPath = {83696968, 39, 0, wordCount, index};
        return deriveBIP85Mnemonic(masterPrivateKey, derivationPath);
    }

    /**
     * Derive the entropy for a BIP-85 derived key.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param derivationPath   path of derivation.
     * @return Entropy for the derived BIP-85 deterministic key.
     */
    public static byte[] deriveBIP85Entropy(DeterministicKey masterPrivateKey, int[] derivationPath) {
        byte[] fullEntropy = deriveKey(masterPrivateKey, derivationPath);
        byte[] entropy512Bits = generateBIP85Entropy(fullEntropy);
        int newLength;

        switch (derivationPath[3]) {
            case 12:
                newLength = 16;
                break;

            case 18:
                newLength = 24;
                break;

            case 24:
                newLength = 32;
                break;

            default:
                throw new IllegalArgumentException("Invalid word count: " + derivationPath[3]);
        }

        byte[] entropy = Arrays.copyOf(entropy512Bits, newLength); // 16 = 128 bits, 24 = 18 words, 32 = 256 bits for 24 words

        if (logger.isDebugEnabled()) {
            HexFormat hex = new HexFormat();
            logger.debug("deriveBIP85Mnemonic() BIP-85 Child Private Key (hex): {}", hex.formatHex(fullEntropy));
            logger.debug("deriveBIP85Mnemonic() BIP-85 Entropy (hex)a: {}", hex.formatHex(entropy));
            logger.debug("deriveBIP85Mnemonic() BIP-85 Entropy 512bits (hex): {}", hex.formatHex(entropy512Bits));
            logger.debug("deriveBIP85Mnemonic() BIP-85 Entropy full (hex): {}", hex.formatHex(fullEntropy));
        }

        return entropy;
    }

    /**
     * Derive a BIP-39 mnemonic seed phrase for a BIP-85 derived key.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param derivationPath   path of derivation.  Example: {83696968, 39, 0, 12, 0} for BIP-39 English 12-word mnemonic, index 0.
     * @return Seed Phrase for the derived BIP-85 deterministic key.
     */
    public static String deriveBIP85Mnemonic(DeterministicKey masterPrivateKey, int[] derivationPath) {
        // Convert entropy to BIP-39 mnemonic (12 words) using English wordlist
        List<String> wordList = MnemonicCode.INSTANCE.toMnemonic(deriveBIP85Entropy(masterPrivateKey, derivationPath));
        return String.join(" ", wordList);
    }

    private static byte[] deriveKey(DeterministicKey childKey, int[] vals) {
        for (int val : vals) {
            childKey = childKey.derive(val);
        }

        byte[] fullEntropy = childKey.getPrivKeyBytes();

        if (fullEntropy.length != 32) {
            throw new IllegalStateException("Expected 32 bytes of private key, got " + fullEntropy.length);
        }
        return fullEntropy;
    }

    private static byte[] generateBIP85Entropy(byte[] privateKey) {
        // BIP-85: HMAC-SHA512 with key "bip-entropy-from-k"
        String hmacKey = "bip-entropy-from-k";
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA512");
        try {
            mac.init(secretKeySpec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(privateKey);
    }
}
