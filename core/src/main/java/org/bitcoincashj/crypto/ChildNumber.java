/*
 * Copyright 2013 Matija Mazi.
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

package org.bitcoincashj.crypto;

import java.util.Locale;

import com.google.common.primitives.Ints;

/**
 * <p>This is just a wrapper for the i (child number) as per BIP 32 with a boolean getter for the most significant bit
 * and a getter for the actual 0-based child number. A {@link java.util.List} of these forms a <i>path</i> through a
 * {@link DeterministicHierarchy}. This class is immutable.
 */
public class ChildNumber implements Comparable<ChildNumber> {
    /**
     * The bit that's set in the child number to indicate whether this key is "hardened". Given a hardened key, it is
     * not possible to derive a child public key if you know only the hardened public key. With a non-hardened key this
     * is possible, so you can derive trees of public keys given only a public parent, but the downside is that it's
     * possible to leak private keys if you disclose a parent public key and a child private key (elliptic curve maths
     * allows you to work upwards).
     */
    public static final int HARDENED_BIT = 0x80000000;

    public static final ChildNumber ZERO = new ChildNumber(0);
    public static final ChildNumber ONE = new ChildNumber(1);
    public static final ChildNumber ZERO_HARDENED = new ChildNumber(0, true);

    /** Integer i as per BIP 32 spec, including the MSB denoting derivation type (0 = public, 1 = private) **/
    private final int i;

    public ChildNumber(int childNumber, boolean isHardened) {
        if (hasHardenedBit(childNumber))
            throw new IllegalArgumentException("Most significant bit is reserved and shouldn't be set: " + childNumber);
        i = isHardened ? (childNumber | HARDENED_BIT) : childNumber;
    }

    public ChildNumber(int i) {
        this.i = i;
    }

    /** Returns the uint32 encoded form of the path element, including the most significant bit. */
    public int getI() {
        return i;
    }

    /** Returns the uint32 encoded form of the path element, including the most significant bit. */
    public int i() { return i; }

    public boolean isHardened() {
        return hasHardenedBit(i);
    }

    private static boolean hasHardenedBit(int a) {
        return (a & HARDENED_BIT) != 0;
    }

    /** Returns the child number without the hardening bit set (i.e. index in that part of the tree). */
    public int num() {
        return i & (~HARDENED_BIT);
    }

    @Override
    public String toString() {
        return String.format(Locale.US, "%d%s", num(), isHardened() ? "H" : "");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return i == ((ChildNumber)o).i;
    }

    @Override
    public int hashCode() {
        return i;
    }

    @Override
    public int compareTo(ChildNumber other) {
        // note that in this implementation compareTo() is not consistent with equals()
        return Ints.compare(this.num(), other.num());
    }
}
