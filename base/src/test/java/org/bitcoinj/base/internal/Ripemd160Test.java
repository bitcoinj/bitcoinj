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

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * Tests for {@link Ripemd160} using test vectors from the RIPEMD-160 specification
 * and Bitcoin-specific HASH160 vectors.
 */
public class Ripemd160Test {

    // -- RIPEMD-160 specification test vectors --
    // From https://homes.esat.kuleuven.be/~bosselaers/ripemd160.html

    @Test
    public void emptyString() {
        assertHash("9c1185a5c5e9fc54612808977ee8f548b2258d31", "");
    }

    @Test
    public void singleChar() {
        assertHash("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "a");
    }

    @Test
    public void threeChars() {
        assertHash("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc");
    }

    @Test
    public void messageDigest() {
        assertHash("5d0689ef49d2fae572b881b123a85ffa21595f36", "message digest");
    }

    @Test
    public void alphabet() {
        assertHash("f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "abcdefghijklmnopqrstuvwxyz");
    }

    @Test
    public void mixedAlphanumeric() {
        assertHash("12a053384a9c0c88e405a06c27dcf49ada62eb2b",
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    }

    @Test
    public void fullAlphanumeric() {
        assertHash("b0e20b6e3116640286ed3a87a5713079b21f5189",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    }

    @Test
    public void repeatedDigits() {
        assertHash("9b752e45573d4b39f4dbd3323cab82bf63326bfb",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    }

    @Test
    public void millionAs() {
        byte[] input = new byte[1_000_000];
        Arrays.fill(input, (byte) 'a');
        byte[] expected = ByteUtils.parseHex("52783243c1697bdbe16d37f97f68f08325dc1528");
        assertArrayEquals(expected, Ripemd160.hash(input));
    }

    // -- Additional vectors from Wikipedia --

    @Test
    public void quickBrownFoxDog() {
        assertHash("37f332f68db77bd9d7edd4969571ad671cf9dd3b",
                "The quick brown fox jumps over the lazy dog");
    }

    @Test
    public void quickBrownFoxCog() {
        // Demonstrates avalanche effect: one letter change produces completely different hash
        assertHash("132072df690933835eb8b6ad0b77e7b6f14acad7",
                "The quick brown fox jumps over the lazy cog");
    }

    // -- Block boundary tests with known expected hashes --
    // These verify correct padding when the message length is near a 64-byte block boundary.

    @Test
    public void exactly55Zeros() {
        // 55 + 1 padding byte + 8 length bytes = 64 (fits in one padded block)
        assertHashBytes("e323d78db60afc7404def79abb82b8fb73591037", new byte[55]);
    }

    @Test
    public void exactly56Zeros() {
        // 56 + 1 + 8 > 64, so padding spills into a second block
        assertHashBytes("7724d7cdbbe24a75a58958d784e3a325ce0e9c7c", new byte[56]);
    }

    @Test
    public void exactly63Zeros() {
        assertHashBytes("898ce0102e6090a253edde87bd6e025b7a6dad70", new byte[63]);
    }

    @Test
    public void exactly64Zeros() {
        // Exactly one full block before padding
        assertHashBytes("9b8ccc2f374ae313a914763cc9cdfb47bfe1c229", new byte[64]);
    }

    @Test
    public void exactly128Zeros() {
        // Two full blocks before padding
        assertHashBytes("4300a157335cb7c9fc9423e011d7dd51090d093f", new byte[128]);
    }

    // -- HASH160 tests: RIPEMD160(SHA256(x)) --
    // This is the standard Bitcoin address derivation hash.

    @Test
    public void hash160EmptyInput() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // RIPEMD160(above) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
        byte[] expected = ByteUtils.parseHex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
        assertArrayEquals(expected, Ripemd160.hash160(new byte[0]));
    }

    @Test
    public void hash160CompressedPubKey() {
        // Bitcoin wiki example: compressed public key -> HASH160 -> address hash
        // Public key: 0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352
        // Expected HASH160: f54a5851e9372b87810a8e60cdd2e7cfd80b6e31
        byte[] pubkey = ByteUtils.parseHex(
                "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352");
        byte[] expected = ByteUtils.parseHex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");
        assertArrayEquals(expected, Ripemd160.hash160(pubkey));
    }

    @Test
    public void hash160GenesisCoinbasePubKey() {
        // Satoshi's genesis block coinbase public key (uncompressed)
        byte[] pubkey = ByteUtils.parseHex(
                "04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
              + "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
              + "de5c384df7ba0b8d578a4c702b6bf11d5f");
        byte[] expected = ByteUtils.parseHex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
        assertArrayEquals(expected, Ripemd160.hash160(pubkey));
    }

    // -- Property tests --

    @Test
    public void hashLengthConstant() {
        assertEquals(20, Ripemd160.HASH_LENGTH);
    }

    @Test
    public void hashOutputIsAlways20Bytes() {
        // Various sizes including zero, small, and multi-block inputs
        assertEquals(Ripemd160.HASH_LENGTH, Ripemd160.hash(new byte[0]).length);
        assertEquals(Ripemd160.HASH_LENGTH, Ripemd160.hash(new byte[1]).length);
        assertEquals(Ripemd160.HASH_LENGTH, Ripemd160.hash(new byte[64]).length);
        assertEquals(Ripemd160.HASH_LENGTH, Ripemd160.hash(new byte[200]).length);
    }

    @Test
    public void hash160OutputIsAlways20Bytes() {
        assertEquals(Ripemd160.HASH_LENGTH, Ripemd160.hash160(new byte[0]).length);
        assertEquals(Ripemd160.HASH_LENGTH, Ripemd160.hash160(new byte[33]).length);
    }

    @Test
    public void returnsFreshArray() {
        byte[] input = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] hash1 = Ripemd160.hash(input);
        byte[] hash2 = Ripemd160.hash(input);
        assertArrayEquals(hash1, hash2);
        // Mutating one must not affect the other
        hash1[0] ^= 0xFF;
        assertFalse(Arrays.equals(hash1, hash2));
    }

    @Test
    public void inputIsNotModified() {
        byte[] input = "hello".getBytes(StandardCharsets.US_ASCII);
        byte[] copy = input.clone();
        Ripemd160.hash(input);
        assertArrayEquals(copy, input);
    }

    @Test(expected = NullPointerException.class)
    public void nullInputThrows() {
        Ripemd160.hash(null);
    }

    // -- Helpers --

    private static void assertHash(String expectedHex, String asciiInput) {
        byte[] expected = ByteUtils.parseHex(expectedHex);
        byte[] actual = Ripemd160.hash(asciiInput.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(expected, actual);
    }

    private static void assertHashBytes(String expectedHex, byte[] input) {
        byte[] expected = ByteUtils.parseHex(expectedHex);
        assertArrayEquals(expected, Ripemd160.hash(input));
    }
}
