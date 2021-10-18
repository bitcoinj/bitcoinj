/*
 * Copyright 2012 The Bitcoin Developers
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static org.bitcoinj.core.Utils.*;

/**
 * <p>A data structure that contains proofs of block inclusion for one or more transactions, in an efficient manner.</p>
 *
 * <p>The encoding works as follows: we traverse the tree in depth-first order, storing a bit for each traversed node,
 * signifying whether the node is the parent of at least one matched leaf txid (or a matched txid itself). In case we
 * are at the leaf level, or this bit is 0, its merkle node hash is stored, and its children are not explored further.
 * Otherwise, no hash is stored, but we recurse into both (or the only) child branch. During decoding, the same
 * depth-first traversal is performed, consuming bits and hashes as they were written during encoding.</p>
 *
 * <p>The serialization is fixed and provides a hard guarantee about the encoded size,
 * {@code SIZE <= 10 + ceil(32.25*N)} where N represents the number of leaf nodes of the partial tree. N itself
 * is bounded by:</p>
 *
 * <p>
 * N &lt;= total_transactions<br>
 * N &lt;= 1 + matched_transactions*tree_height
 * </p>
 *
 * <p>The serialization format:</p>
 * <pre>
 *  - uint32     total_transactions (4 bytes)
 *  - varint     number of hashes   (1-3 bytes)
 *  - uint256[]  hashes in depth-first order (&lt;= 32*N bytes)
 *  - varint     number of bytes of flag bits (1-3 bytes)
 *  - byte[]     flag bits, packed per 8 in a byte, least significant bit first (&lt;= 2*N-1 bits)
 * </pre>
 * <p>The size constraints follow from this.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class PartialMerkleTree extends Message {
    // the total number of transactions in the block
    private int transactionCount;

    // node-is-parent-of-matched-txid bits
    private byte[] matchedChildBits;

    // txids and internal hashes
    private List<Sha256Hash> hashes;
    
    public PartialMerkleTree(NetworkParameters params, byte[] payloadBytes, int offset) throws ProtocolException {
        super(params, payloadBytes, offset);
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(transactionCount, stream);

        stream.write(new VarInt(hashes.size()).encode());
        for (Sha256Hash hash : hashes)
            stream.write(hash.getReversedBytes());

        stream.write(new VarInt(matchedChildBits.length).encode());
        stream.write(matchedChildBits);
    }

    @Override
    protected void parse() throws ProtocolException {
        transactionCount = (int)readUint32();

        int nHashes = readVarInt().intValue();
        hashes = new ArrayList<>(Math.min(nHashes, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (int i = 0; i < nHashes; i++)
            hashes.add(readHash());

        int nFlagBytes = readVarInt().intValue();
        matchedChildBits = readBytes(nFlagBytes);

        length = cursor - offset;
    }

    public int getTransactionCount() {
        return transactionCount;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PartialMerkleTree other = (PartialMerkleTree) o;
        return transactionCount == other.transactionCount && hashes.equals(other.hashes)
            && Arrays.equals(matchedChildBits, other.matchedChildBits);
    }

    @Override
    public int hashCode() {
        return Objects.hash(transactionCount, hashes, Arrays.hashCode(matchedChildBits));
    }

    @Override
    public String toString() {
        return "PartialMerkleTree{" +
                "transactionCount=" + transactionCount +
                ", matchedChildBits=" + Arrays.toString(matchedChildBits) +
                ", hashes=" + hashes +
                '}';
    }
}
