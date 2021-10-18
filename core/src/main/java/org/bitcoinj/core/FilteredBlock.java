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
    
    // A set of transactions whose hashes are a subset of getTransactionHashes()
    // These were relayed as a part of the filteredblock getdata, ie likely weren't previously received as loose transactions
    private Map<Sha256Hash, Transaction> associatedTransactions = new HashMap<>();
    
    public FilteredBlock(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
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
    
    /** Gets the hash of the block represented in this Filtered Block */
    @Override
    public Sha256Hash getHash() {
        return header.getHash();
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
