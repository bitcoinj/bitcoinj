/*
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

package org.bitcoinj.core;

import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Wraps a {@link Block} object with extra data that can be derived from the block chain but is slow or inconvenient to
 * calculate. By storing it alongside the block header we reduce the amount of work required significantly.
 * Recalculation is slow because the fields are cumulative - to find the chainWork you have to iterate over every
 * block in the chain back to the genesis block, which involves lots of seeking/loading etc. So we just keep a
 * running total: it's a disk space vs cpu/io tradeoff.<p>
 *
 * StoredBlocks are put inside a {@link BlockStore} which saves them to memory or disk.
 */
public class StoredBlock {

    // A BigInteger representing the total amount of work done so far on this chain. As of June 22, 2024, it takes 12
    // unsigned bytes to store this value, so developers should use the V2 format.
    private static final int CHAIN_WORK_BYTES_V1 = 12;
    // A BigInteger representing the total amount of work done so far on this chain.
    private static final int CHAIN_WORK_BYTES_V2 = 32;
    // Height is an int.
    private static final int HEIGHT_BYTES = 4;
    // Used for padding.
    private static final byte[] EMPTY_BYTES = new byte[CHAIN_WORK_BYTES_V2]; // fit larger format
    /** Number of bytes serialized by {@link #serializeCompact(ByteBuffer)} */
    public static final int COMPACT_SERIALIZED_SIZE = Block.HEADER_SIZE + CHAIN_WORK_BYTES_V1 + HEIGHT_BYTES;
    /** Number of bytes serialized by {@link #serializeCompactV2(ByteBuffer)} */
    public static final int COMPACT_SERIALIZED_SIZE_V2 = Block.HEADER_SIZE + CHAIN_WORK_BYTES_V2 + HEIGHT_BYTES;

    private final Block header;
    private final BigInteger chainWork;
    private final int height;

    /**
     * Create a StoredBlock from a (header-only) {@link Block}, chain work value, and block height
     *
     * @param header A Block object with only a header (no transactions should be included)
     * @param chainWork Calculated chainWork for this block
     * @param height block height for this block
     */
    public StoredBlock(Block header, BigInteger chainWork, int height) {
        this.header = header;
        this.chainWork = chainWork;
        this.height = height;
    }

    /**
     * The block header this object wraps. The referenced block object must not have any transactions in it.
     */
    public Block getHeader() {
        return header;
    }

    /**
     * The total sum of work done in this block, and all the blocks below it in the chain. Work is a measure of how
     * many tries are needed to solve a block. If the target is set to cover 10% of the total hash value space,
     * then the work represented by a block is 10.
     */
    public BigInteger getChainWork() {
        return chainWork;
    }

    /**
     * Position in the chain for this block. The genesis block has a height of zero.
     */
    public int getHeight() {
        return height;
    }

    /** Returns true if this objects chainWork is higher than the others. */
    public boolean moreWorkThan(StoredBlock other) {
        return chainWork.compareTo(other.chainWork) > 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StoredBlock other = (StoredBlock) o;
        return header.equals(other.header) && chainWork.equals(other.chainWork) && height == other.height;
    }

    @Override
    public int hashCode() {
        return Objects.hash(header, chainWork, height);
    }

    /**
     * Creates a new StoredBlock, calculating the additional fields by adding to the values in this block.
     */
    public StoredBlock build(Block block) throws VerificationException {
        // Stored blocks track total work done in this chain, because the canonical chain is the one that represents
        // the largest amount of work done not the tallest.
        BigInteger chainWork = this.chainWork.add(block.getWork());
        int height = this.height + 1;
        return new StoredBlock(block, chainWork, height);
    }

    /**
     * Given a block store, looks up the previous block in this chain. Convenience method for doing
     * {@code store.get(this.getHeader().getPrevBlockHash())}.
     *
     * @return the previous block in the chain or null if it was not found in the store.
     */
    public StoredBlock getPrev(BlockStore store) throws BlockStoreException {
        return store.get(getHeader().getPrevBlockHash());
    }

    /**
     * Serializes the stored block to a custom packed format. Used internally.
     * As of June 22, 2024, it takes 12 unsigned bytes to store the chain work value,
     * so developers should use {@link #serializeCompactV2(ByteBuffer)}.
     *
     * @param buffer buffer to write to
     */
    public void serializeCompact(ByteBuffer buffer) {
        byte[] chainWorkBytes = ByteUtils.bigIntegerToBytes(getChainWork(), CHAIN_WORK_BYTES_V1);
        if (chainWorkBytes.length < CHAIN_WORK_BYTES_V1) {
            // Pad to the right size.
            buffer.put(EMPTY_BYTES, 0, CHAIN_WORK_BYTES_V1 - chainWorkBytes.length);
        }
        buffer.put(chainWorkBytes);
        buffer.putInt(getHeight());
        byte[] bytes = getHeader().serialize();
        buffer.put(bytes, 0, Block.HEADER_SIZE);  // Trim the trailing 00 byte (zero transactions).
    }

    /**
     * Serializes the stored block to a custom packed format. Used internally.
     *
     * @param buffer buffer to write to
     */
    public void serializeCompactV2(ByteBuffer buffer) {
        byte[] chainWorkBytes = ByteUtils.bigIntegerToBytes(getChainWork(), CHAIN_WORK_BYTES_V2);
        if (chainWorkBytes.length < CHAIN_WORK_BYTES_V2) {
            // Pad to the right size.
            buffer.put(EMPTY_BYTES, 0, CHAIN_WORK_BYTES_V2 - chainWorkBytes.length);
        }
        buffer.put(chainWorkBytes);
        buffer.putInt(getHeight());
        byte[] bytes = getHeader().serialize();
        buffer.put(bytes, 0, Block.HEADER_SIZE);  // Trim the trailing 00 byte (zero transactions).
    }

    /**
     * Deserializes the stored block from a custom packed format. Used internally.
     * As of June 22, 2024, it takes 12 unsigned bytes to store the chain work value,
     * so developers should use {@link #deserializeCompactV2(ByteBuffer)}.
     *
     * @param buffer data to deserialize
     * @return deserialized stored block
     */
    public static StoredBlock deserializeCompact(ByteBuffer buffer) throws ProtocolException {
        byte[] chainWorkBytes = new byte[StoredBlock.CHAIN_WORK_BYTES_V1];
        buffer.get(chainWorkBytes);
        BigInteger chainWork = ByteUtils.bytesToBigInteger(chainWorkBytes);
        int height = buffer.getInt();  // +4 bytes
        byte[] header = new byte[Block.HEADER_SIZE + 1];    // Extra byte for the 00 transactions length.
        buffer.get(header, 0, Block.HEADER_SIZE);
        return new StoredBlock(Block.read(ByteBuffer.wrap(header)), chainWork, height);
    }

    /**
     * Deserializes the stored block from a custom packed format. Used internally.
     *
     * @param buffer data to deserialize
     * @return deserialized stored block
     */
    public static StoredBlock deserializeCompactV2(ByteBuffer buffer) throws ProtocolException {
        byte[] chainWorkBytes = new byte[StoredBlock.CHAIN_WORK_BYTES_V2];
        buffer.get(chainWorkBytes);
        BigInteger chainWork = ByteUtils.bytesToBigInteger(chainWorkBytes);
        int height = buffer.getInt();  // +4 bytes
        byte[] header = new byte[Block.HEADER_SIZE + 1];    // Extra byte for the 00 transactions length.
        buffer.get(header, 0, Block.HEADER_SIZE);
        return new StoredBlock(Block.read(ByteBuffer.wrap(header)), chainWork, height);
    }

    /** @deprecated use {@link #deserializeCompact(ByteBuffer)} */
    @Deprecated
    public static StoredBlock deserializeCompact(MessageSerializer serializer, ByteBuffer buffer) throws ProtocolException {
        return deserializeCompact(buffer);
    }

    @Override
    public String toString() {
        return String.format(Locale.US, "Block %s at height %d: %s",
                getHeader().getHashAsString(), getHeight(), getHeader().toString());
    }
}
