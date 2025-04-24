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

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.Buffers;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * <p>A FilteredBlock is used to relay a block with its transactions filtered using a {@link BloomFilter}. It consists
 * of the block header and a {@link PartialMerkleTree} which contains the transactions which matched the filter.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class FilteredBlock implements Message {
    private final Block header;

    private final PartialMerkleTree merkleTree;
    private List<Sha256Hash> cachedTransactionHashes = null;
    
    // A set of transactions whose hashes are a subset of getTransactionHashes()
    // These were relayed as a part of the filteredblock getdata, ie likely weren't previously received as loose transactions
    private final Map<Sha256Hash, Transaction> associatedTransactions = new HashMap<>();

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static FilteredBlock read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        byte[] headerBytes = Buffers.readBytes(payload, Block.HEADER_SIZE);
        Block header = Block.read(ByteBuffer.wrap(headerBytes));
        PartialMerkleTree merkleTree = PartialMerkleTree.read(payload);
        return new FilteredBlock(header, merkleTree);
    }

    public FilteredBlock(Block header, PartialMerkleTree pmt) {
        super();
        this.header = header;
        this.merkleTree = pmt;
    }

    @Override
    public int messageSize() {
        return Block.HEADER_SIZE +
                merkleTree.messageSize();
    }

    @Override
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        if (header.isHeaderOnly())
            header.write(buf);
        else
            header.asHeader().write(buf);
        merkleTree.write(buf);
        return buf;
    }

    /**
     * Gets a list of leaf hashes which are contained in the partial merkle tree in this filtered block
     *
     * @throws ProtocolException If the partial merkle block is invalid or the merkle root of the partial merkle block doesn't match the block header
     */
    public List<Sha256Hash> getTransactionHashes() throws VerificationException {
        if (cachedTransactionHashes != null)
            return Collections.unmodifiableList(cachedTransactionHashes);
        List<Sha256Hash> hashesMatched = new LinkedList<>();
        if (header.getMerkleRoot().equals(merkleTree.getTxnHashAndMerkleRoot(hashesMatched))) {
            cachedTransactionHashes = hashesMatched;
            return Collections.unmodifiableList(cachedTransactionHashes);
        } else
            throw new VerificationException("Merkle root of block header does not match merkle root of partial merkle tree.");
    }
    
    /**
     * Gets a copy of the block header
     */
    public Block getBlockHeader() {
        return header.asHeader();
    }
    
    /** Gets the hash of the block represented in this Filtered Block */
    public Sha256Hash getHash() {
        return header.getHash();
    }
    
    /**
     * Provide this FilteredBlock with a transaction which is in its Merkle tree.
     * @return false if the tx is not relevant to this FilteredBlock
     */
    public boolean provideTransaction(Transaction tx) throws VerificationException {
        Sha256Hash hash = tx.getTxId();
        if (getTransactionHashes().contains(hash)) {
            associatedTransactions.put(hash, tx);
            return true;
        }
        return false;
    }

    /** Returns the {@link PartialMerkleTree} object that provides the mathematical proof of transaction inclusion in the block. */
    public PartialMerkleTree getPartialMerkleTree() {
        return merkleTree;
    }

    /** Gets the set of transactions which were provided using provideTransaction() which match in getTransactionHashes() */
    public Map<Sha256Hash, Transaction> getAssociatedTransactions() {
        return Collections.unmodifiableMap(associatedTransactions);
    }

    /** Number of transactions in this block, before it was filtered */
    public int getTransactionCount() {
        return merkleTree.getTransactionCount();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FilteredBlock other = (FilteredBlock) o;
        return associatedTransactions.equals(other.associatedTransactions)
            && header.equals(other.header) && merkleTree.equals(other.merkleTree);
    }

    @Override
    public int hashCode() {
        return Objects.hash(associatedTransactions, header, merkleTree);
    }

    @Override
    public String toString() {
        return "FilteredBlock{merkleTree=" + merkleTree + ", header=" + header + '}';
    }
}
