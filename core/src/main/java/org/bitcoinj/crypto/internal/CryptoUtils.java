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
package org.bitcoinj.crypto.internal;

import org.bitcoinj.base.Sha256Hash;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Utilities for the crypto module (e.g. wrapping built-in primitives and/or Bouncy Castle)
 */
public class CryptoUtils {
    /**
     * Calculate RIPEMD160(SHA256(input)). This is used in Address calculations.
     * @param input bytes to hash
     * @return RIPEMD160(SHA256(input))
     */
    public static byte[] sha256hash160(byte[] input) {
        byte[] sha256 = Sha256Hash.hash(input);
        return digestRipeMd160(sha256);
    }

    /**
     * Calculate RIPEMD160(input).
     * @param input bytes to hash
     * @return RIPEMD160(input)
     */
    public static byte[] digestRipeMd160(byte[] input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(input, 0, input.length);
        byte[] ripmemdHash = new byte[20];
        digest.doFinal(ripmemdHash, 0);
        return ripmemdHash;
    }

    /**
     * Generate a MAC using a <i>binary</i> key and data
     * @param key The key in binary format
     * @param data The message data to process
     * @return The final result of the MAC operation
     */
    public static byte[] hmacSha512(byte[] key, byte[] data) {
        // HmacSHA512 is built-in on Java since at least Java 8 and Android since API Level 1
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA512");
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA512");
            mac.init(secretKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return mac.doFinal(data);
    }

    /**
     * Generate a MAC using a {@link String} tag and data. For example, this is used in our BIP-32
     * implementation with a tag {@code String} of {@code "Bitcoin seed"}. The {@link Charset} parameter
     * is typically {@link StandardCharsets#US_ASCII}.
     * @param tag The tag
     * @param charset The {@link Charset} to be used to encode the tag {@code String}
     * @param data The message data to process
     * @return The final result of the MAC operation
     */
    public static byte[] hmacSha512(String tag, Charset charset, byte[] data) {
        return hmacSha512(tag.getBytes(charset), data);
    }

    /**
     * Calculate a SHA3-256 digest. Suitable for TOR Onion checksums.
     * @param inputs An ordered collection of inputs to be hashed
     * @return A SHA3 256-bit hash
     */
    public static byte[] sha3Digest(byte[] ...inputs) {
        SHA3.Digest256 digest = new SHA3.Digest256();
        for (byte[] input : inputs) {
            digest.update(input, 0, input.length);
        }
        return digest.digest();
    }
}
