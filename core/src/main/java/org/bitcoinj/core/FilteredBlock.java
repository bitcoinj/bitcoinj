/*
 * Copyright 2012 Matt Corallo
 * Copyright 2015 Andreas Schildbach
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

import java.io.IOException;
import java.io.OutputStream;
import java.util.*;

/**
 * <p>A FilteredBlock is used to relay a block with its transactions filtered using a {@link BloomFilter}. It consists
 * of the block header and a {@link PartialMerkleTree} which contains the transactions which matched the filter.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class FilteredBlock extends Message {
    private Block header;

    private PartialMerkleTree merkleTree;
    private List<Sha256Hash> cachedTransactionHashes = null;
    
    // A set of transactions whose hashes are a subset of getTransactionHashes()
    // These were relayed as a part of the filteredblock getdata, ie likely weren't previously received as loose transactions
    private Map<Sha256Hash, Transaction> associatedTransactions = new HashMap<>();
    
    public FilteredBlock(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }

    public FilteredBlock(NetworkParameters params, Block header, PartialMerkleTree pmt) {
        super(params);
        this.header = header;
        this.merkleTree = pmt;
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (header.getTransactions() == null)
            header.bitcoinSerializeToStream(stream);
        else
            header.cloneAsHeader().bitcoinSerializeToStream(stream);
        merkleTree.bitcoinSerializeToStream(stream);
    }

    @Override
    protected void parse() throws ProtocolException {
        byte[] headerBytes = new byte[Block.HEADER_SIZE];
        System.arraycopy(payload, 0, headerBytes, 0, Block.HEADER_SIZE);
        header = params.getDefaultSerializer().makeBlock(headerBytes);
        
        merkleTree = new PartialMerkleTree(params, payload, Block.HEADER_SIZE);
        
        length = Block.HEADER_SIZE + merkleTree.getMessageSize();
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
        return header.cloneAsHeader();
    }
    
    /** Gets the hash of the block represented in this Filtered Block */
    @Override
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
