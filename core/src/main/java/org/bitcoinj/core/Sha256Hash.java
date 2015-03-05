/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.core;

import com.google.common.io.ByteStreams;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * A Sha256Hash just wraps a byte[] so that equals and hashcode work correctly, allowing it to be used as keys in a
 * map. It also checks that the length is correct and provides a bit more type safety.
 */
public class Sha256Hash implements Serializable, Comparable<Sha256Hash> {
    private final byte[] bytes;
    public static final Sha256Hash ZERO_HASH = new Sha256Hash(new byte[32]);

    /**
     * Creates a Sha256Hash by wrapping the given byte array. It must be 32 bytes long.
     */
    public Sha256Hash(byte[] rawHashBytes) {
        checkArgument(rawHashBytes.length == 32);
        this.bytes = rawHashBytes;

    }

    /**
     * Creates a Sha256Hash by decoding the given hex string. It must be 64 characters long.
     */
    public Sha256Hash(String hexString) {
        checkArgument(hexString.length() == 64);
        this.bytes = Utils.HEX.decode(hexString);
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
     * Calculates the hash of the hash of the contents. This is a standard operation in Bitcoin.
     */
    public static Sha256Hash createDouble(byte[] contents) {
        return new Sha256Hash(Utils.doubleDigest(contents));
    }

    /**
     * Returns a hash of the given files contents. Reads the file fully into memory before hashing so only use with
     * small files.
     * @throws IOException
     */
    public static Sha256Hash hashFileContents(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        try {
            return create(ByteStreams.toByteArray(in));
        } finally {
            in.close();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Sha256Hash other = (Sha256Hash) o;
        return Arrays.equals(bytes, other.bytes);
    }

    /**
     * Hash code of the byte array as calculated by {@link Arrays#hashCode()}. Note the difference between a SHA256
     * secure bytes and the type of quick/dirty bytes used by the Java hashCode method which is designed for use in
     * bytes tables.
     */
    @Override
    public int hashCode() {
        // Use the last 4 bytes, not the first 4 which are often zeros in Bitcoin.
        return (bytes[31] & 0xFF) | ((bytes[30] & 0xFF) << 8) | ((bytes[29] & 0xFF) << 16) | ((bytes[28] & 0xFF) << 24);
    }

    @Override
    public String toString() {
        return Utils.HEX.encode(bytes);
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
        return new Sha256Hash(bytes);
    }

    @Override
    public int compareTo(Sha256Hash o) {
        int thisCode = this.hashCode();
        int oCode = ((Sha256Hash)o).hashCode();
        return thisCode > oCode ? 1 : (thisCode == oCode ? 0 : -1);
    }
}
