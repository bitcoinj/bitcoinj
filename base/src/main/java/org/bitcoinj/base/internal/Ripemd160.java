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

package org.bitcoinj.base.internal;

import org.bitcoinj.base.Sha256Hash;

import java.util.Arrays;
import java.util.Objects;

import static java.lang.Integer.rotateLeft;

/**
 * Pure Java implementation of the RIPEMD-160 hash function.
 * <p>
 * This avoids a dependency on Bouncy Castle for a hash that is not available
 * in the standard JDK {@link java.security.MessageDigest} providers. The
 * implementation follows the specification at
 * <a href="https://homes.esat.kuleuven.be/~bosselaers/ripemd160.html">
 * https://homes.esat.kuleuven.be/~bosselaers/ripemd160.html</a>.
 * <p>
 * Not instantiable.
 */
public final class Ripemd160 {

    /** Length of a RIPEMD-160 hash in bytes. */
    public static final int HASH_LENGTH = 20;

    private static final int BLOCK_LEN = 64; // bytes

    /**
     * Computes the RIPEMD-160 hash of the given message.
     *
     * @param msg the input bytes to hash
     * @return a new 20-byte array containing the hash
     */
    public static byte[] hash(byte[] msg) {
        Objects.requireNonNull(msg);

        // Initial hash values from the spec
        int[] state = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

        // Process complete 64-byte blocks
        int off = msg.length / BLOCK_LEN * BLOCK_LEN;
        compress(state, msg, off);

        // Pad the final block: append 0x80, zeros, then bit-length in little-endian
        byte[] block = new byte[BLOCK_LEN];
        System.arraycopy(msg, off, block, 0, msg.length - off);
        off = msg.length % block.length;
        block[off] = (byte) 0x80;
        off++;
        if (off + 8 > block.length) {
            // Not enough room for the 8-byte length; need an extra block
            compress(state, block, block.length);
            Arrays.fill(block, (byte) 0);
        }
        long len = (long) msg.length << 3;
        for (int i = 0; i < 8; i++)
            block[block.length - 8 + i] = (byte) (len >>> (i * 8));
        compress(state, block, block.length);

        // Serialize state to bytes in little-endian order
        byte[] result = new byte[HASH_LENGTH];
        for (int i = 0; i < result.length; i++)
            result[i] = (byte) (state[i / 4] >>> (i % 4 * 8));
        return result;
    }

    /**
     * Computes RIPEMD160(SHA256(input)), commonly known as HASH160 in Bitcoin.
     * This is the standard hash used for deriving addresses from public keys
     * and for P2SH script hashes.
     *
     * @param input the input bytes (typically a public key or redeem script)
     * @return a new 20-byte array containing the hash
     */
    public static byte[] hash160(byte[] input) {
        byte[] sha256 = Sha256Hash.hash(input);
        return hash(sha256);
    }

    // -- Compression function --

    private static void compress(int[] state, byte[] blocks, int len) {
        if (len % BLOCK_LEN != 0)
            throw new IllegalArgumentException();
        for (int i = 0; i < len; i += BLOCK_LEN) {
            // Parse block into 16 little-endian 32-bit words
            int[] schedule = new int[16];
            for (int j = 0; j < BLOCK_LEN; j++)
                schedule[j / 4] |= (blocks[i + j] & 0xFF) << (j % 4 * 8);

            int al = state[0], ar = state[0];
            int bl = state[1], br = state[1];
            int cl = state[2], cr = state[2];
            int dl = state[3], dr = state[3];
            int el = state[4], er = state[4];

            // 80 rounds: left and right paths processed in parallel
            for (int j = 0; j < 80; j++) {
                int temp;
                temp = rotateLeft(al + f(j, bl, cl, dl) + schedule[RL[j]] + KL[j / 16], SL[j]) + el;
                al = el;
                el = dl;
                dl = rotateLeft(cl, 10);
                cl = bl;
                bl = temp;

                temp = rotateLeft(ar + f(79 - j, br, cr, dr) + schedule[RR[j]] + KR[j / 16], SR[j]) + er;
                ar = er;
                er = dr;
                dr = rotateLeft(cr, 10);
                cr = br;
                br = temp;
            }

            // Combine the two parallel chains and update state
            int temp = state[1] + cl + dr;
            state[1] = state[2] + dl + er;
            state[2] = state[3] + el + ar;
            state[3] = state[4] + al + br;
            state[4] = state[0] + bl + cr;
            state[0] = temp;
        }
    }

    // Non-linear function for each group of 16 rounds (5 groups total)
    private static int f(int i, int x, int y, int z) {
        if (i < 16) return x ^ y ^ z;
        if (i < 32) return (x & y) | (~x & z);
        if (i < 48) return (x | ~y) ^ z;
        if (i < 64) return (x & z) | (y & ~z);
        return x ^ (y | ~z);
    }

    // -- Constants from the RIPEMD-160 specification --

    // Additive constants for left and right rounds
    private static final int[] KL = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
    private static final int[] KR = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};

    // Message word selection for left rounds
    private static final int[] RL = {
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
         7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
         3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
         1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
         4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13};

    // Message word selection for right rounds
    private static final int[] RR = {
         5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
         6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
         8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11};

    // Rotation amounts for left rounds
    private static final int[] SL = {
        11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
         7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
        11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
         9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6};

    // Rotation amounts for right rounds
    private static final int[] SR = {
         8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
         9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
         9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
         8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11};

    private Ripemd160() {}
}
