/**
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

package com.google.bitcoin.core;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Represents a monetary Bitcoin value. This class is immutable.
 */
public final class Coin implements Comparable<Coin>, Serializable {

    public static final Coin ZERO = new Coin(BigInteger.ZERO);
    public static final Coin ONE = new Coin(BigInteger.ONE);
    public static final Coin TEN = new Coin(BigInteger.TEN);

    private final BigInteger value;

    public Coin(final BigInteger value) {
        this.value = value;
    }

    public Coin(final String value, final int radix) {
        this(new BigInteger(value, radix));
    }

    public Coin(final byte[] value) {
        this(new BigInteger(value));
    }

    public static Coin valueOf(final long value) {
        return new Coin(BigInteger.valueOf(value));
    }

    public Coin add(final Coin value) {
        return new Coin(this.value.add(value.value));
    }

    public Coin subtract(final Coin value) {
        return new Coin(this.value.subtract(value.value));
    }

    public Coin multiply(final Coin value) {
        return new Coin(this.value.multiply(value.value));
    }

    public Coin multiply(final long value) {
        return multiply(Coin.valueOf(value));
    }

    public Coin divide(final Coin value) {
        return new Coin(this.value.divide(value.value));
    }

    public Coin[] divideAndRemainder(final Coin value) {
        final BigInteger[] result = this.value.divideAndRemainder(value.value);
        return new Coin[] { new Coin(result[0]), new Coin(result[1]) };
    }

    public Coin shiftLeft(final int n) {
        return new Coin(this.value.shiftLeft(n));
    }

    public Coin shiftRight(final int n) {
        return new Coin(this.value.shiftRight(n));
    }

    public int signum() {
        return this.value.signum();
    }

    public Coin negate() {
        return new Coin(this.value.negate());
    }

    public byte[] toByteArray() {
        return this.value.toByteArray();
    }

    public long longValue() {
        return this.value.longValue();
    }

    public double doubleValue() {
        return this.value.doubleValue();
    }

    public BigInteger toBigInteger() {
        return value;
    }

    @Override
    public String toString() {
        return value.toString();
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this)
            return true;
        if (o == null || o.getClass() != getClass())
            return false;
        final Coin other = (Coin) o;
        if (!this.value.equals(other.value))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }

    @Override
    public int compareTo(final Coin other) {
        return this.value.compareTo(other.value);
    }
}
