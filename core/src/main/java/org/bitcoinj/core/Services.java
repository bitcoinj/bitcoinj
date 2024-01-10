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

import org.bitcoinj.base.internal.InternalUtils;

import java.nio.Buffer;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * Wrapper for services bitfield used in various messages of the Bitcoin protocol. Each bit represents a node service,
 * e.g. {@link #NODE_NETWORK} if the node serves the full blockchain.
 * <p>
 * Instances of this class are immutable and should be treated as Java
 * <a href="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/doc-files/ValueBased.html#Value-basedClasses">value-based</a>.
 */
public class Services {
    /** A service bit that denotes whether the peer has a full copy of the block chain or not. */
    public static final int NODE_NETWORK = 1 << 0;
    /** A service bit that denotes whether the peer supports BIP37 bloom filters or not. The service bit is defined in BIP111. */
    public static final int NODE_BLOOM = 1 << 2;
    /** Indicates that a node can be asked for blocks and transactions including witness data. */
    public static final int NODE_WITNESS = 1 << 3;
    /** Indicates the node will service basic block filter requests (BIP157, BIP158). */
    public static final int NODE_COMPACT_FILTERS = 1 << 6;
    /** A service bit that denotes whether the peer has at least the last two days worth of blockchain (BIP159). */
    public static final int NODE_NETWORK_LIMITED = 1 << 10;
    /** Indicates the node supports BIP324 transport. */
    public static final int NODE_P2P_V2 = 1 << 11;
    /** A service bit used by Bitcoin-ABC to announce Bitcoin Cash nodes. */
    public static final int NODE_BITCOIN_CASH = 1 << 5;

    /** Number of bytes of this bitfield. */
    public static final int BYTES = 8;

    private final long bits;

    /**
     * Wrap 64 bits, each representing a node service.
     *
     * @param bits bits to wrap
     * @return wrapped service bits
     */
    public static Services of(long bits) {
        return new Services(bits);
    }

    /**
     * Constructs a services bitfield representing "no node services".
     *
     * @return wrapped service bits
     */
    public static Services none() {
        return new Services(0);
    }

    /**
     * Construct a services bitfield by reading from the given buffer.
     *
     * @param buf buffer to read from
     * @return wrapped service bits
     * @throws BufferUnderflowException if the read services bitfield extends beyond the remaining bytes of the buffer
     */
    public static Services read(ByteBuffer buf) throws BufferUnderflowException {
        return new Services(buf.order(ByteOrder.LITTLE_ENDIAN).getLong());
    }

    private Services(long bits) {
        this.bits = bits;
    }

    /**
     * Gets the 64 bits of this bitfield, each representing a node service.
     *
     * @return the service bits
     */
    public long bits() {
        return bits;
    }

    /**
     * Checks if this bitfield signals any node services at all.
     *
     * @return true if at least one service is signaled, false otherwise
     */
    public boolean hasAny() {
        return bits != 0;
    }

    /**
     * Checks if given specific node services are signaled by this bitfield.
     *
     * @param bitmask bitmask representing the services to be checked for
     * @return true if the given services are all signaled, false otherwise
     */
    public boolean has(long bitmask) {
        return (bits & bitmask) == bitmask;
    }

    /**
     * Checks if at least one of the given node services is signaled by this bitfield.
     *
     * @param bitmask bitmask representing the services to be checked for
     * @return true if at least one of the given services is signaled, false otherwise
     */
    public boolean anyOf(long bitmask) {
        return (bits & bitmask) != 0;
    }

    /**
     * Write the node service bits into the given buffer.
     *
     * @param buf buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the service bits don't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        buf.order(ByteOrder.LITTLE_ENDIAN).putLong(bits);
        return buf;
    }

    /**
     * Allocates a byte array and writes the node service bits into it.
     *
     * @return byte array containing the service bits
     */
    public byte[] serialize() {
        return write(ByteBuffer.allocate(BYTES)).array();
    }

    public String toString() {
        long bits = this.bits;
        List<String> strings = new LinkedList<>();
        if ((bits & NODE_NETWORK) == NODE_NETWORK) {
            strings.add("NETWORK");
            bits &= ~NODE_NETWORK;
        }
        if ((bits & NODE_BLOOM) == NODE_BLOOM) {
            strings.add("BLOOM");
            bits &= ~NODE_BLOOM;
        }
        if ((bits & NODE_WITNESS) == NODE_WITNESS) {
            strings.add("WITNESS");
            bits &= ~NODE_WITNESS;
        }
        if ((bits & NODE_COMPACT_FILTERS) == NODE_COMPACT_FILTERS) {
            strings.add("COMPACT_FILTERS");
            bits &= ~NODE_COMPACT_FILTERS;
        }
        if ((bits & NODE_NETWORK_LIMITED) == NODE_NETWORK_LIMITED) {
            strings.add("NETWORK_LIMITED");
            bits &= ~NODE_NETWORK_LIMITED;
        }
        if ((bits & NODE_P2P_V2) == NODE_P2P_V2) {
            strings.add("P2P_V2");
            bits &= ~NODE_P2P_V2;
        }
        if (bits != 0)
            strings.add("remaining: " + Long.toBinaryString(bits));
        return InternalUtils.joiner(", ").join(strings);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return this.bits == ((Services) o).bits;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.bits);
    }
}
