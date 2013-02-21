/**
 * Copyright 2012 Matt Corallo
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

import java.io.IOException;
import java.io.OutputStream;
import java.util.*;

/**
 * <p>A FilteredBlock is used to relay a block with its transactions filtered using a {@link BloomFilter}. It consists
 * of the block header and a {@link PartialMerkleTree} which contains the transactions which matched the filter.</p>
 */
public class FilteredBlock extends Message {
    /** The protocol version at which Bloom filtering started to be supported. */
    public static final int MIN_PROTOCOL_VERSION = 70000;
    private Block header;

    // The PartialMerkleTree of transactions
    private PartialMerkleTree merkleTree;
    private Set<Sha256Hash> cachedTransactionHashes = null;
    
    // A set of transactions who's hashes are a subset of getTransactionHashes()
    // These were relayed as a part of the filteredblock getdata, ie likely weren't previously received as loose transactions
    private List<Transaction> associatedTransactions = new LinkedList<Transaction>();
    
    public FilteredBlock(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }
    
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        throw new RuntimeException("Not implemented");
    }

    @Override
    void parse() throws ProtocolException {
        byte[] headerBytes = new byte[Block.HEADER_SIZE];
        System.arraycopy(bytes, 0, headerBytes, 0, Block.HEADER_SIZE);
        header = new Block(params, headerBytes);
        
        merkleTree = new PartialMerkleTree(params, bytes, Block.HEADER_SIZE);
        
        length = Block.HEADER_SIZE + merkleTree.getMessageSize();
    }
    
    @Override
    protected void parseLite() throws ProtocolException {

    }
    
    /**
     * Gets a list of leaf hashes which are contained in the partial merkle tree in this filtered block
     * 
     * @throws ProtocolException If the partial merkle block is invalid or the merkle root of the partial merkle block doesnt match the block header
     */
    public Set<Sha256Hash> getTransactionHashes() throws VerificationException {
        if (cachedTransactionHashes != null)
            return Collections.unmodifiableSet(cachedTransactionHashes);
        Set<Sha256Hash> hashesMatched = new HashSet<Sha256Hash>();
        if (header.getMerkleRoot().equals(merkleTree.getTxnHashAndMerkleRoot(hashesMatched))) {
            cachedTransactionHashes = hashesMatched;
            return Collections.unmodifiableSet(cachedTransactionHashes);
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
    public Sha256Hash getHash() {
        return header.getHash();
    }
    
    /**
     * Provide this FilteredBlock with a transaction which is in its merkle tree
     * @returns false if the tx is not relevant to this FilteredBlock
     */
    public boolean provideTransaction(Transaction tx) throws VerificationException {
        if (getTransactionHashes().contains(tx.getHash())) {
            associatedTransactions.add(tx);
            return true;
        } else
            return false;
    }
    
    /** Gets the set of transactions which were provided using provideTransaction() which match in getTransactionHashes() */
    public List<Transaction> getAssociatedTransactions() {
        return Collections.unmodifiableList(associatedTransactions);
    }
}
