/**
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;

import org.bouncycastle.util.encoders.Hex;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * A Sha256Hash just wraps a byte[] so that equals and hashcode work correctly, allowing it to be used as keys in a
 * map. It also checks that the length is correct and provides a bit more type safety.
 */
public class Sha256Hash implements Serializable {
    private static final long serialVersionUID = 3778897922647016546L;

    private byte[] bytes;
    private int hash = -1;

    /**
     * @see setHashcodeByteLength(int hashcodeByteLength)
     */
    private static int HASHCODE_BYTES_TO_CHECK = 5;
    private static boolean HASHCODE_BYTES_TO_CHECK_CHANGED = false;


    public static final Sha256Hash ZERO_HASH = new Sha256Hash(new byte[32]);

    /**
     * Alters the number of bytes from the backing array to use when generating java hashCodes.
     * <br/><br/>
     * The default value of 5 gives approximately 1 trillion possible unique combinations.
     * Given that an int hashcode only has 4 billion possible values it should be more than enough.
     * <br/><br/>
     * Changing this value after Sha256Hashes have been stored in hashed collections breaks the
     * hashCode contract and will result in unpredictable behaviour.  If this
     * needs to be set to a different value it should be done once and only once
     * and before any calls to hashCode() are made on any instance of Sha256Hash instances.
     * <br/>
     *
     * @param hashcodeByteLength the number of bytes in the hash to use for generating the hashcode.
     * @throws IllegalStateException if called more than once.
     */
    public static void setHashcodeByteLength(int hashcodeByteLength) {
        if (HASHCODE_BYTES_TO_CHECK_CHANGED)
            throw new IllegalStateException("setHashcodeByteLength can only be called once and should be called before any instances of Sha256Hash are constructed");
        HASHCODE_BYTES_TO_CHECK = hashcodeByteLength;
        HASHCODE_BYTES_TO_CHECK_CHANGED = true;
    }

    /**
     * Creates a Sha256Hash by wrapping the given byte array. It must be 32 bytes long.
     */
    public Sha256Hash(byte[] bytes) {
        assert bytes.length == 32;
        this.bytes = bytes;

    }

    private Sha256Hash(byte[] bytes, int hash) {
        assert bytes.length == 32;
        this.bytes = bytes;
        this.hash = hash;
    }

    /**
     * Creates a Sha256Hash by decoding the given hex string. It must be 64 characters long.
     */
    public Sha256Hash(String string) {
        assert string.length() == 64;
        this.bytes = Hex.decode(string);
    }

    /**
     * Calculates the (one-time) hash of contents and returns it as a new wrapped hash.
     */
    public static Sha256Hash create(byte[] contents) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return new Sha256Hash(digest.digest(contents));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Returns true if the hashes are equal.
     */
    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Sha256Hash)) return false;
        return Arrays.equals(bytes, ((Sha256Hash) other).bytes);
    }

    /**
     * Hash code of the byte array as calculated by {@link Arrays#hashCode()}. Note the difference between a SHA256
     * secure bytes and the type of quick/dirty bytes used by the Java hashCode method which is designed for use in
     * bytes tables.
     */
    @Override
    public int hashCode() {
        if (hash == -1) {
            hash = 1;
            for (int i = 0; i < HASHCODE_BYTES_TO_CHECK; i++)
                hash = 31 * hash + bytes[i];
        }
        return hash;
    }

    @Override
    public String toString() {
        return Utils.bytesToHexString(bytes);
    }

    /**
     * Returns the bytes interpreted as a positive integer.
     */
    public BigInteger toBigInteger() {
        return new BigInteger(1, bytes);
    }

    public byte[] getBytes() {
        return bytes;
    }

    public Sha256Hash duplicate() {
        return new Sha256Hash(bytes, hash);
    }
}
