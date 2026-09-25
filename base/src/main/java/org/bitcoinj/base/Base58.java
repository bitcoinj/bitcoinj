/*
 * Copyright 2011 Google Inc.
 * Copyright 2018 Andreas Schildbach
 * Copyright 2026 OpenSea, Inc.
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

package org.bitcoinj.base;

import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.base.internal.ByteUtils;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Base58 is a way to encode Bitcoin addresses (or arbitrary data) as alphanumeric strings.
 * <p>
 * Note that this is not the same base58 as used by Flickr, which you may find referenced around the Internet.
 * <p>
 * You may want to consider working with {@code org.bitcoinj.core.EncodedPrivateKey} instead, which
 * adds support for testing the prefix and suffix bytes commonly found in addresses.
 * <p>
 * Satoshi explains: why base-58 instead of standard base-64 encoding?
 * <ul>
 * <li>Don't want 0OIl characters that look the same in some fonts and
 *     could be used to create visually identical looking account numbers.</li>
 * <li>A string with non-alphanumeric characters is not as easily accepted as an account number.</li>
 * <li>E-mail usually won't line-break if there's no punctuation to break at.</li>
 * <li>Doubleclicking selects the whole number as one word if it's all alphanumeric.</li>
 * </ul>
 * <p>
 * The basic idea of the encoding is to treat the data bytes as a large number represented using
 * base-256 digits, convert the number to be represented using base-58 digits, preserve the exact
 * number of leading zeros (which are otherwise lost during the mathematical operations on the
 * numbers), and finally represent the resulting base-58 digits as alphanumeric ASCII characters.
 * <p>
 * This implementation uses fixed-width 32-bit limb arithmetic with 5-digit batching
 * (58<sup>5</sup> = 656,356,768 fits in a {@code long} alongside a 32-bit limb), which reduces
 * encode/decode to O(n<sup>2</sup>/k) work with a small constant factor instead of the
 * byte-level O(n<sup>2</sup>) divmod used by earlier versions.
 */
public class Base58 {
    public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char ENCODED_ZERO = ALPHABET[0];
    private static final int[] INDEXES = new int[128];
    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    // Batch BATCH_SIZE base-58 digits per pass over the limb array. 58^5 = 656356768 fits
    // in a long alongside a 32-bit limb without overflowing (max intermediate value is
    // 0xFFFFFFFF * 656356768 + 656356767 < 2^63).
    private static final int BATCH_SIZE = 5;
    private static final long BATCH_POWER = 656_356_768L; // 58^5

    /**
     * Encodes the given bytes as a base58 string (no checksum is appended).
     *
     * @param input the bytes to encode
     * @return the base58-encoded string
     */
    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        // Count leading zeros (preserved as leading '1' characters in the output).
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            ++zeros;
        }
        // Pack the big-endian input into little-endian 32-bit limbs.
        int numLimbs = (input.length + 3) / 4;
        int[] limbs = new int[numLimbs];
        for (int pos = 0; pos < input.length; pos++) {
            int byteVal = input[input.length - 1 - pos] & 0xFF;
            int limbIdx = pos >>> 2;
            int shift = (pos & 3) << 3;
            limbs[limbIdx] |= byteVal << shift;
        }

        // Upper bound on output length. log_58(256) ≈ 1.366, so each input byte produces at
        // most ~1.37 output chars. Using 2*len is a safe (if loose) ceiling. We add BATCH_SIZE
        // slack so the final partial batch is never truncated.
        char[] encoded = new char[input.length * 2 + BATCH_SIZE];
        int charPos = encoded.length;

        int activeLimbs = numLimbs;
        while (activeLimbs > 0 && limbs[activeLimbs - 1] == 0) activeLimbs--;

        // Repeatedly divide the limb-represented number by 58^BATCH_SIZE and emit BATCH_SIZE
        // base-58 digits per iteration (LSD first, written right-to-left into `encoded`).
        while (activeLimbs > 0) {
            long remainder = 0L;
            for (int idx = activeLimbs - 1; idx >= 0; idx--) {
                long value = (remainder << 32) | (limbs[idx] & 0xFFFFFFFFL);
                limbs[idx] = (int) (value / BATCH_POWER);
                remainder = value % BATCH_POWER;
            }

            for (int d = 0; d < BATCH_SIZE; d++) {
                encoded[--charPos] = ALPHABET[(int) (remainder % 58L)];
                remainder /= 58L;
            }

            while (activeLimbs > 0 && limbs[activeLimbs - 1] == 0) activeLimbs--;
        }

        // The last iteration may have produced BATCH_SIZE zero-padded '1' chars on the most
        // significant end — strip them. Then re-add the preserved leading zeros.
        while (charPos < encoded.length && encoded[charPos] == ENCODED_ZERO) {
            ++charPos;
        }
        while (--zeros >= 0) {
            encoded[--charPos] = ENCODED_ZERO;
        }
        return new String(encoded, charPos, encoded.length - charPos);
    }

    /**
     * Encodes the given version and bytes as a base58 string. A checksum is appended.
     *
     * @param version the version to encode
     * @param payload the bytes to encode, e.g. pubkey hash
     * @return the base58-encoded string
     */
    public static String encodeChecked(int version, byte[] payload) {
        if (version < 0 || version > 255)
            throw new IllegalArgumentException("Version not in range.");

        // A stringified buffer is:
        // 1 byte version + data bytes + 4 bytes check code (a truncated hash)
        byte[] addressBytes = new byte[1 + payload.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(payload, 0, addressBytes, 1, payload.length);
        byte[] checksum = Sha256Hash.hashTwice(addressBytes, 0, payload.length + 1);
        System.arraycopy(checksum, 0, addressBytes, payload.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    /**
     * Decodes the given base58 string into the original data bytes.
     *
     * @param input the base58-encoded string to decode
     * @return the decoded data bytes
     * @throws AddressFormatException if the given string is not a valid base58 string
     */
    public static byte[] decode(String input) throws AddressFormatException {
        if (input.isEmpty()) {
            return new byte[0];
        }

        // Count leading '1' characters, which encode leading zero bytes.
        int leadingZeros = 0;
        while (leadingZeros < input.length() && input.charAt(leadingZeros) == ENCODED_ZERO) {
            leadingZeros++;
        }
        if (leadingZeros == input.length()) {
            return new byte[leadingZeros];
        }

        int dataLen = input.length() - leadingZeros;
        // log_256(58) ≈ 0.733, so dataLen base-58 digits fit in at most ceil(dataLen*0.733)+1 bytes.
        int estimatedBytes = dataLen * 733 / 1000 + 1;
        int numLimbs = (estimatedBytes + 3) / 4;
        int[] limbs = new int[numLimbs];
        int usedLimbs = 0;

        // Consume base-58 digits in batches of BATCH_SIZE (the last batch may be shorter).
        int i = leadingZeros;
        while (i < input.length()) {
            int remaining = input.length() - i;
            int batchLen = remaining >= BATCH_SIZE ? BATCH_SIZE : remaining;
            long batchBase = pow58(batchLen);

            long acc = 0L;
            for (int k = 0; k < batchLen; k++) {
                char c = input.charAt(i + k);
                int digit = c < 128 ? INDEXES[c] : -1;
                if (digit < 0) {
                    throw new AddressFormatException.InvalidCharacter(c, i + k);
                }
                acc = acc * 58L + digit;
            }
            i += batchLen;

            // limbs := limbs * batchBase + acc (little-endian 32-bit limbs, long-precision carry)
            long carry = acc;
            for (int j = 0; j < usedLimbs; j++) {
                long product = (limbs[j] & 0xFFFFFFFFL) * batchBase + carry;
                limbs[j] = (int) product;
                carry = product >>> 32;
            }
            if (carry != 0L) {
                // The estimated capacity is a ceiling based on log_256(58), so we always have room.
                limbs[usedLimbs] = (int) carry;
                usedLimbs++;
            }
        }

        // Serialize the limbs back to big-endian bytes.
        byte[] bytes = new byte[numLimbs * 4];
        for (int idx = 0; idx < numLimbs; idx++) {
            int offset = (numLimbs - 1 - idx) * 4;
            int limb = limbs[idx];
            bytes[offset]     = (byte) (limb >>> 24);
            bytes[offset + 1] = (byte) (limb >>> 16);
            bytes[offset + 2] = (byte) (limb >>> 8);
            bytes[offset + 3] = (byte) limb;
        }

        // Strip leading zero bytes introduced by the fixed-width limb layout, then prepend
        // exactly `leadingZeros` zero bytes to match the encoded '1' prefix count.
        int stripLeading = 0;
        while (stripLeading < bytes.length && bytes[stripLeading] == 0) {
            stripLeading++;
        }

        byte[] result = new byte[leadingZeros + bytes.length - stripLeading];
        System.arraycopy(bytes, stripLeading, result, leadingZeros, bytes.length - stripLeading);
        return result;
    }

    public static BigInteger decodeToBigInteger(String input) throws AddressFormatException {
        return ByteUtils.bytesToBigInteger(decode(input));
    }

    /**
     * Decodes the given base58 string into the original data bytes, using the checksum in the
     * last 4 bytes of the decoded data to verify that the rest are correct. The checksum is
     * removed from the returned data.
     *
     * @param input the base58-encoded string to decode (which should include the checksum)
     * @throws AddressFormatException if the input is not base 58 or the checksum does not validate.
     */
    public static byte[] decodeChecked(String input) throws AddressFormatException {
        byte[] decoded  = decode(input);
        if (decoded.length < 4)
            throw new AddressFormatException.InvalidDataLength("Input too short: " + decoded.length);
        byte[] data = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
        byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
        byte[] actualChecksum = Arrays.copyOfRange(Sha256Hash.hashTwice(data), 0, 4);
        if (!Arrays.equals(checksum, actualChecksum))
            throw new AddressFormatException.InvalidChecksum();
        return data;
    }

    // 58^n for 0 <= n <= BATCH_SIZE.
    private static long pow58(int n) {
        long p = 1L;
        for (int i = 0; i < n; i++) p *= 58L;
        return p;
    }
}
