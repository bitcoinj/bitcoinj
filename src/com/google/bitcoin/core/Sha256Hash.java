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

import java.io.Serializable;
import java.util.Arrays;

// TODO: Switch all code/interfaces to using this class.

/**
 * A Sha256Hash just wraps a byte[] so that equals and hashcode work correctly, allowing it to be used as keys in a
 * map. It also checks that the length is correct and provides a bit more type safety.
 */
public class Sha256Hash implements Serializable {
    public byte[] hash;

    public Sha256Hash(byte[] hash) {
        assert hash.length == 32;
        this.hash = hash;
    }

    /** Returns true if the hashes are equal. */
    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Sha256Hash)) return false;
        return Arrays.equals(hash, ((Sha256Hash)other).hash);
    }

    /**
     * Hash code of the byte array as calculated by {@link Arrays#hashCode()}. Note the difference between a SHA256
     * secure hash and the type of quick/dirty hash used by the Java hashCode method which is designed for use in
     * hash tables.
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }

    @Override
    public String toString() {
        return Utils.bytesToHexString(hash);
    }
}
