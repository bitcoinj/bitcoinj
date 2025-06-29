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
import org.bitcoinj.wallet.DeterministicSeed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.crypto.ChildNumber.HARDENED_BIT;

/**
 * Utility class for working with BIP-85, generating wallets, etc. (<a href="https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki">https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki</a>).
 * <p>
 * See test class org.bitcoinj.crypto.DeterministicEntropyTest for examples on how to use this class.
 */
public class DeterministicEntropy {
    private static final Logger logger = LoggerFactory.getLogger(DeterministicEntropy.class);

    private static ChildNumber createHardenedChildNumber(int childNumber) {
        return new ChildNumber(childNumber & ~HARDENED_BIT, true);
    }

    private static final ChildNumber BIP85_PATH_ROOT = createHardenedChildNumber(83696968);
    private static final ChildNumber BIP39_APPLICATION_NUMBER = createHardenedChildNumber(39);


    public enum Language {
        English(0),
        Japanese(1),
        Korean(2),
        Spanish(3),
        ChineseSimplified(4),
        ChineseTraditional(5),
        French(6),
        Italian(7),
        Czech(8),
        Portuguese(9);

        private final int intValue;

        Language(int intValue) {
            this.intValue = intValue;
        }

        public ChildNumber childNumber() {
            return createHardenedChildNumber(intValue);
        }
    }

    public enum WordCount {
        Twelve(12, 16),
        Eighteen(18, 24),
        TwentyFour(24, 32);

        private final int intValue;
        private final int bitCount;

        WordCount(int intValue, int bits) {
            this.intValue = intValue;
            this.bitCount = bits;
        }

        public static WordCount forWordCount(int wordCount) {
            switch (wordCount) {
                case 12:
                case -2147483636: // 12 hardened
                    return Twelve;
                case 18:
                case -2147483630: // 18 hardened
                    return Eighteen;
                case 24:
                case -2147483624: // 24 hardened
                    return TwentyFour;
                default:
                    throw new IllegalArgumentException(wordCount + " is not a valid word count");
            }
        }

        public ChildNumber childNumber() {
            return createHardenedChildNumber(intValue);
        }
    }


    private DeterministicEntropy() {
    }

    /**
     * Perform a BIP-85 derivation and return the DeterministicSeed.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param hdPath           path of derivation.  Example: {83696968, 39, 0, 12, 0} for BIP-39 English 12-word mnemonic, index 0.
     * @return Seed for the BIP-85 derivation.
     */
    public static DeterministicSeed deriveBIP85Seed(DeterministicKey masterPrivateKey, HDPath hdPath) {
        byte[] data = deriveBIP85Entropy(masterPrivateKey, hdPath);
        return DeterministicSeed.ofEntropy(data, "");
    }

    /**
     * Perform a BIP-85 derivation and return the DeterministicSeed.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param language         Language <a href="https://bips.xyz/85#bip39">https://bips.xyz/85#bip39</a>.
     * @param wordCount        Number of words in generated seed.
     * @param index            0 to 9999 for the index of the child key.
     * @return Seed for the BIP-85 derivation.
     */
    public static DeterministicSeed deriveBIP85Seed(DeterministicKey masterPrivateKey, Language language, WordCount wordCount, int index) {
        // BIP-85 does not specify an upper limit on the index.  The index must be >= 0.
        if (index < 0) throw new IllegalArgumentException("index must be >= 0");

        HDPath.HDFullPath path = HDPath.m(BIP85_PATH_ROOT,
                BIP39_APPLICATION_NUMBER,
                language.childNumber(),
                wordCount.childNumber(),
                createHardenedChildNumber(index));

        return deriveBIP85Seed(masterPrivateKey, path);
    }


    /**
     * Perform a BIP-85 derivation and return the DeterministicSeed.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param wordCount        Number of words in generated seed.
     * @param index            0 to 9999 for the index of the child key.
     * @return Seed for the BIP-85 derivation.
     */
    public static DeterministicSeed deriveBIP85Seed(DeterministicKey masterPrivateKey, WordCount wordCount, int index) {
        return deriveBIP85Seed(masterPrivateKey, Language.English, wordCount, index);
    }

    /**
     * Derive the entropy for a BIP-85 derived key.
     *
     * @param masterPrivateKey DeterministicKey to derive from.
     * @param hdPath           path of derivation.
     * @return Entropy for the derived BIP-85 deterministic key.
     */
    private static byte[] deriveBIP85Entropy(DeterministicKey masterPrivateKey, HDPath hdPath) {
        byte[] fullEntropy = deriveKey(masterPrivateKey, hdPath);
        byte[] entropy512Bits = generateBIP85Entropy(fullEntropy);
        byte[] entropy = Arrays.copyOf(entropy512Bits, WordCount.forWordCount(hdPath.children[3]).bitCount);

        if (logger.isDebugEnabled()) {
            HexFormat hex = new HexFormat();
            logger.debug("deriveBIP85Entropy() BIP-85 Child Private Key (hex): {}", hex.formatHex(fullEntropy));
            logger.debug("deriveBIP85Entropy() BIP-85 Entropy (hex)a: {}", hex.formatHex(entropy));
            logger.debug("deriveBIP85Entropy() BIP-85 Entropy 512bits (hex): {}", hex.formatHex(entropy512Bits));
            logger.debug("deriveBIP85Entropy() BIP-85 Entropy full (hex): {}", hex.formatHex(fullEntropy));
        }

        return entropy;
    }

    private static byte[] deriveKey(DeterministicKey childKey, HDPath hdPath) {
        for (int val : hdPath.children) {
            childKey = HDKeyDerivation.deriveChildKey(childKey, val);
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
