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
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Utilities for the crypto module (e.g. using Bouncy Castle)
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

    public static byte[] hmacSha512(byte[] key, byte[] data) {
        // HmacSHA512 is built-in on Java and Android for all versions we support
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

    public static byte[] hmacSha512(String key, byte[] data) {
        return hmacSha512(key.getBytes(), data);
    }
}
