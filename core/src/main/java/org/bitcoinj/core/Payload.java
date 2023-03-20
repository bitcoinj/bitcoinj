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

package org.bitcoinj.core;

import org.bitcoinj.base.internal.ByteUtils;

import java.util.Arrays;
import java.util.Objects;

/**
 * Wrapper for the payload of P2P messages.
 */
public class Payload {
    /**
     * Wrap given payload bytes with an offset of 0.
     * @param bytes payload bytes
     * @return wrapped payload
     */
    public static Payload of(byte[] bytes) {
        return new Payload(bytes, 0);
    }

    /**
     * Wrap given payload bytes with a given offset.
     * @param bytes payload bytes
     * @param offset offset into the payload bytes
     * @return wrapped payload
     */
    public static Payload of(byte[] bytes, int offset) {
        return new Payload(bytes, offset);
    }

    /**
     * Wrap payload, given as a hex string.
     * @param hex payload bytes as hex string
     * @return wrapped payload
     */
    public static Payload ofHex(String hex) {
        return of(ByteUtils.parseHex(hex));
    }

    // The raw message payload bytes themselves.
    private final byte[] bytes;
    // The offset is how many bytes into the provided byte array this message payload starts at.
    private final int offset;

    private Payload(byte[] bytes, int offset) {
        this.bytes = bytes;
        this.offset = offset;
    }

    /**
     * Gets the raw payload bytes, including those before the offset.
     * @return payload bytes
     */
    public byte[] bytes() {
        return bytes;
    }

    /**
     * Gets the offset into the payload bytes.
     * @return offset
     */
    public int offset() {
        return offset;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Payload other = (Payload) o;
        return Arrays.equals(this.bytes, other.bytes) &&
                this.offset == other.offset;
    }

    @Override
    public int hashCode() {
        return Objects.hash(bytes, offset);
    }

    @Override
    public String toString() {
        return ByteUtils.formatHex(bytes);
    }
}
