/**
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;
import static org.bitcoinj.core.Message.UNKNOWN_LENGTH;

/**
 * <p>A FilteredBlock is used to relay a block with its transactions filtered using a {@link BloomFilter}. It consists
 * of the block header and a {@link PartialMerkleTree} which contains the transactions which matched the filter.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class FilteredBlock extends AbstractBlock {

    private PartialMerkleTree merkleTree;
    private List<Sha256Hash> cachedTransactionHashes = null;
    
    // A set of transactions whose hashes are a subset of getTransactionHashes()
    // These were relayed as a part of the filteredblock getdata, ie likely weren't previously received as loose transactions
    private Map<Sha256Hash, Transaction> associatedTransactions = new HashMap<Sha256Hash, Transaction>();
    
    public FilteredBlock(NetworkParameters params, byte[] payloadBytes, int offset, MessageSerializer serializer, int length) throws ProtocolException {
        super(params, payloadBytes, offset, serializer, length);
    }

    public FilteredBlock(NetworkParameters params, final Block block, PartialMerkleTree pmt) {
        super(params, block.getVersion(), block.getPrevBlockHash(), block.getMerkleRoot(),
                block.getTimeSeconds(), block.getDifficultyTarget(), block.getNonce());
        this.merkleTree = pmt;
    }

    @Override
    public byte[] bitcoinSerialize() {
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? HEADER_SIZE * 2: length);
        try {
            writeHeader(stream);
            merkleTree.bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        super.bitcoinSerializeToStream(stream);
        merkleTree.bitcoinSerializeToStream(stream);
    }

    @Override
    protected void parse() throws ProtocolException {
        super.parse();
        parseTransactions();

        length = cursor - offset;
        optimalEncodingMessageSize = length;
    }

    /**
     * Parse the merkle tree containing the filtered transaction's details.
     * Extension point for cases where the filtered block contains non-standard
     * header information.
     */
    protected void parseTransactions() throws ProtocolException {
        merkleTree = new PartialMerkleTree(params, payload, cursor);
        cursor += merkleTree.getMessageSize();
    }
    
    /**
     * Gets a list of leaf hashes which are contained in the partial merkle tree in this filtered block
     * 
     * @throws ProtocolException If the partial merkle block is invalid or the merkle root of the partial merkle block doesnt match the block header
     */
    public List<Sha256Hash> getTransactionHashes() throws VerificationException {
        if (cachedTransactionHashes != null)
            return Collections.unmodifiableList(cachedTransactionHashes);
        List<Sha256Hash> hashesMatched = new LinkedList<Sha256Hash>();
        if (getMerkleRoot().equals(merkleTree.getTxnHashAndMerkleRoot(hashesMatched))) {
            cachedTransactionHashes = hashesMatched;
            return Collections.unmodifiableList(cachedTransactionHashes);
        } else
            throw new VerificationException("Merkle root of block header does not match merkle root of partial merkle tree.");
    }
    
    /**
     * Provide this FilteredBlock with a transaction which is in its Merkle tree.
     * @return false if the tx is not relevant to this FilteredBlock
     */
    public boolean provideTransaction(Transaction tx) throws VerificationException {
        Sha256Hash hash = tx.getHash();
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

    // Hash code provided on just the block header is good enough, but equals
    // must be precise
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FilteredBlock other = (FilteredBlock) o;
        return associatedTransactions.equals(other.associatedTransactions)
            && super.equals(other) && merkleTree.equals(other.merkleTree);
    }

    @Override
    protected final void appendToStringBuilder(final StringBuilder s) {
        s.append("FilteredBlock{merkleTree=")
            .append(merkleTree)
            .append(", header=");
        super.appendToStringBuilder(s);
        s.append("}");
    }
}
