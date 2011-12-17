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

package com.google.bitcoin.core;

import com.google.bitcoin.store.BlockStoreException;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>A <tt>TransactionConfidence</tt> object tracks data you can use to make a confidence decision about a transaction.
 * It also contains some pre-canned rules for common scenarios: if you aren't really sure what level of confidence
 * you need, these should prove useful.</p>
 *
 * <p>Confidence in a transaction can come in multiple ways:</p>
 *
 * <ul>
 * <li>Because you created it yourself and only you have the necessary keys.</li>
 * <li>Receiving it from a fully validating peer you know is trustworthy, for instance, because it's run by yourself.</li>
 * <li>Receiving it from a peer on the network you randomly chose. If your network connection is not being
 *     intercepted, you have a pretty good chance of connecting to a node that is following the rules.</li>
 * <li>Receiving it from multiple peers on the network. If your network connection is not being intercepted,
 *     hearing about a transaction from multiple peers indicates the network has accepted the transaction and
 *     thus miners likely have too (miners have the final say in whether a transaction becomes valid or not).</li>
 * <li>Seeing the transaction appear appear in a block on the main chain. Your confidence increases as the transaction
 *     becomes further buried under work. Work can be measured either in blocks (roughly, units of time), or
 *     amount of work done.</li>
 * </ul>
 *
 * <p>Alternatively, you may know beyond doubt that the transaction is "dead", that is, one or more of its inputs have
 * been double spent and will never confirm.</p>
 *
 * <p>TransactionConfidence is purely a data structure, it doesn't try and keep itself up to date. To have fresh
 * confidence data, you need to ensure the owning {@link Transaction} is being updated by something, like
 * a {@link Wallet}.</p>
 */
public class TransactionConfidence implements Serializable {
    private static final long serialVersionUID = 4577920141400556444L;

    /**
     * The peers that have announced the transaction to us. Network nodes don't have stable identities, so we use
     * IP address as an approximation. It's obviously vulnerable to being gamed if we allow arbitrary people to connect
     * to us, so only peers we explicitly connected to should go here.
     */
    private Set<PeerAddress> broadcastBy;
    
    public static final int NOT_SEEN_IN_CHAIN = -1;
    public static final int NOT_IN_BEST_CHAIN = -2;

    private int appearedAtChainHeight = NOT_SEEN_IN_CHAIN;
    
    public TransactionConfidence() {
        // Assume a default number of peers for our set.
        broadcastBy = Collections.synchronizedSet(new HashSet<PeerAddress>(10));
    }

    /**
     * The chain height at which the transaction appeared, or {@link TransactionConfidence#NOT_IN_BEST_CHAIN} or
     * {@link TransactionConfidence@NOT_IN_BEST_CHAIN}.
     */
    public synchronized int getAppearedAtChainHeight() {
        return appearedAtChainHeight;
    }

    /**
     * The chain height at which the transaction appeared, or {@link TransactionConfidence#NOT_IN_BEST_CHAIN} or
     * {@link TransactionConfidence@NOT_IN_BEST_CHAIN}.
     */
    public synchronized void setAppearedAtChainHeight(int appearedAtChainHeight) {
        if (appearedAtChainHeight < NOT_IN_BEST_CHAIN)
            throw new IllegalArgumentException("appearedAtChainHeight out of range");
        this.appearedAtChainHeight = appearedAtChainHeight;
    }

    /**
     * Called by a {@link Peer} when a transaction is pending and announced by a peer. The more peers announce the
     * transaction, the more peers have validated it (assuming your internet connection is not being intercepted).
     * @param address IP address of the peer, used as a proxy for identity.
     */
    public void markBroadcastBy(PeerAddress address) {
        broadcastBy.add(address);
    }

    /**
     * @return how many peers have been passed to {@link TransactionConfidence#markBroadcastBy}.
     */
    public int numBroadcastPeers() {
        return broadcastBy.size();
    }

    /**
     * @return A synchronized set of {@link PeerAddress}es that announced the transaction.
     */
    public Set<PeerAddress> getBroadcastBy() {
        return broadcastBy;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Seen by ");
        builder.append(numBroadcastPeers());
        builder.append(" peers. ");
        int height = getAppearedAtChainHeight();
        switch (height) {
            case NOT_IN_BEST_CHAIN: builder.append("Not currently in best chain."); break;
            case NOT_SEEN_IN_CHAIN: builder.append("Not seen in any block yet."); break;
            default: builder.append("Appeared in best chain at height "); builder.append(height); break;
        }
        return builder.toString();
    }

    /**
     * Depth in the chain is an approximation of how much time has elapsed since the transaction has been confirmed. On
     * average there is supposed to be a new block every 10 minutes, but the actual rate may vary. The reference
     * (Satoshi) implementation considers a transaction impractical to reverse after 6 blocks, but as of EOY 2011 network
     * security is high enough that often only one block is considered enough even for high value transactions. For low
     * value transactions like songs, or other cheap items, no blocks at all may be necessary.<p>
     *     
     * If the transaction appears in the top block, the depth is one. The result may be < 0 if the transaction isn't
     * in the best chain or wasn't seen in any blocks at all.
     *
     * @param chain a {@link BlockChain} instance.
     * @return depth, or {@link TransactionConfidence#NOT_IN_BEST_CHAIN} or {@link TransactionConfidence#NOT_SEEN_IN_CHAIN}
     */
    public int getDepthInBlocks(BlockChain chain) {
        int height = getAppearedAtChainHeight();
        switch (height) {
            case NOT_IN_BEST_CHAIN: return NOT_IN_BEST_CHAIN;
            case NOT_SEEN_IN_CHAIN: return NOT_SEEN_IN_CHAIN;
            default: return chain.getBestChainHeight() - height + 1;
        }
    }

    /**
     * Returns the estimated amount of work (number of hashes performed) on this transaction. Work done is a measure of
     * security that is related to depth in blocks, but more predictable: the network will always attempt to produce six
     * blocks per hour by adjusting the difficulty target. So to know how much real computation effort is needed to
     * reverse a transaction, counting blocks is not enough.
     *
     * @param chain
     * @return estimated number of hashes needed to reverse the transaction. Zero if not seen in any block yet.
     */
    public BigInteger getWorkDone(BlockChain chain) throws BlockStoreException {
        BigInteger work = BigInteger.ZERO;
        int depth = getDepthInBlocks(chain);
        if (depth == NOT_IN_BEST_CHAIN || depth == NOT_SEEN_IN_CHAIN)
            return BigInteger.ZERO;
        StoredBlock block = chain.getChainHead();
        for (; depth > 0; depth--) {
            work = work.add(block.getChainWork());
            block = block.getPrev(chain.blockStore);
        }
        return work;
    }
}
