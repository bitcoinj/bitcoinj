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
 * <p>Alternatively, you may know that the transaction is "dead", that is, one or more of its inputs have
 * been double spent and will never confirm unless there is another re-org.</p>
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

    /** Describes the state of the transaction in general terms. Properties can be read to learn specifics. */
    public enum ConfidenceType {
        /** If BUILDING, then the transaction is included in the best chain and your confidence in it is increasing. */
        BUILDING,

        /**
         * If NOT_SEEN_IN_CHAIN, then the transaction is pending and should be included shortly. You can estimate how
         * likely the transaction is to be included by connecting to a bunch of nodes then measuring how many announce
         * it, using {@link com.google.bitcoin.core.TransactionConfidence#numBroadcastPeers()}. Or if you saw it from
         * a trusted peer, you can assume it's valid and will get mined sooner or later as well.
         */
        NOT_SEEN_IN_CHAIN,

        /**
         * If NOT_IN_BEST_CHAIN, then the transaction has been included in a block, but that block is on a fork. A
         * transaction can change from BUILDING to NOT_IN_BEST_CHAIN and vice versa if a reorganization takes place,
         * due to a split in the consensus.
         */
        NOT_IN_BEST_CHAIN,

        /**
         * If OVERRIDDEN_BY_DOUBLE_SPEND, then it means the transaction won't confirm unless there is another re-org,
         * because some other transaction is spending one of its inputs. Such transactions should be alerted to the user
         * so they can take action, eg, suspending shipment of goods if they are a merchant.
         */
        OVERRIDDEN_BY_DOUBLE_SPEND,

        /**
         * If a transaction hasn't been broadcast yet, or there's no record of it, its confidence is UNKNOWN.
         */
        UNKNOWN
    };

    private ConfidenceType confidenceType = ConfidenceType.UNKNOWN;
    private int appearedAtChainHeight = -1;
    private Transaction overridingTransaction;
    
    public TransactionConfidence() {
        // Assume a default number of peers for our set.
        broadcastBy = Collections.synchronizedSet(new HashSet<PeerAddress>(10));
    }

    /**
     * @return The chain height at which the transaction appeared if confidence type is BUILDING.
     * @throws IllegalStateException if the confidence type is not BUILDING.
     */
    public synchronized int getAppearedAtChainHeight() {
        if (getConfidenceType() != ConfidenceType.BUILDING)
            throw new IllegalStateException("Confidence type is " + getConfidenceType() + ", not BUILDING");
        return appearedAtChainHeight;
    }

    /**
     * The chain height at which the transaction appeared, if it has been seen in the best chain. Automatically sets
     * the current type to {@link ConfidenceType#BUILDING}.
     */
    public synchronized void setAppearedAtChainHeight(int appearedAtChainHeight) {
        if (appearedAtChainHeight < 0)
            throw new IllegalArgumentException("appearedAtChainHeight out of range");
        this.appearedAtChainHeight = appearedAtChainHeight;
        setConfidenceType(ConfidenceType.BUILDING);
    }

    /**
     * @return A general statement of the level of confidence you can have in this transaction.
     */
    public ConfidenceType getConfidenceType() {
        return confidenceType;
    }

    /**
     * Called by other objects in the system, like a {@link Wallet}, when new information about the confidence of a 
     * transaction becomes available.
     */
    public void setConfidenceType(ConfidenceType confidenceType) {
        this.confidenceType = confidenceType;
    }


    /**
     * Called by a {@link Peer} when a transaction is pending and announced by a peer. The more peers announce the
     * transaction, the more peers have validated it (assuming your internet connection is not being intercepted).
     * If confidence is currently unknown, sets it to {@link ConfidenceType#NOT_SEEN_IN_CHAIN}.
     *
     * @param address IP address of the peer, used as a proxy for identity.
     */
    public void markBroadcastBy(PeerAddress address) {
        if (getConfidenceType() == ConfidenceType.UNKNOWN)
            setConfidenceType(ConfidenceType.NOT_SEEN_IN_CHAIN);
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
        if (numBroadcastPeers() > 0) {
            builder.append("Seen by ");
            builder.append(numBroadcastPeers());
            builder.append(" peers. ");
        }
        switch (getConfidenceType()) {
            case UNKNOWN:
                builder.append("Unknown confidence level.");
                break;
            case OVERRIDDEN_BY_DOUBLE_SPEND:
                builder.append("Dead: overridden by double spend and will not confirm.");
                break;
            case NOT_IN_BEST_CHAIN: 
                builder.append("Seen in side chain but not best chain.");
                break;
            case NOT_SEEN_IN_CHAIN:
                builder.append("Not seen in chain.");
                break;
            case BUILDING: 
                builder.append("Appeared in best chain at height "); 
                builder.append(getAppearedAtChainHeight());
                builder.append(".");
                break;
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
     * If the transaction appears in the top block, the depth is one. If the transaction does not appear in the best
     * chain yet, throws IllegalStateException, so use {@link com.google.bitcoin.core.TransactionConfidence#getConfidenceType()}
     * to check first.
     *
     * @param chain a {@link BlockChain} instance.
     * @throws IllegalStateException if confidence type != BUILDING.
     * @return depth
     */
    public int getDepthInBlocks(BlockChain chain) {
        if (getConfidenceType() != ConfidenceType.BUILDING) {
            throw new IllegalStateException("Confidence type is not BUILDING");
        }
        int height = getAppearedAtChainHeight();
        return chain.getBestChainHeight() - height + 1;
    }

    /**
     * Returns the estimated amount of work (number of hashes performed) on this transaction. Work done is a measure of
     * security that is related to depth in blocks, but more predictable: the network will always attempt to produce six
     * blocks per hour by adjusting the difficulty target. So to know how much real computation effort is needed to
     * reverse a transaction, counting blocks is not enough.
     *
     * @param chain
     * @throws IllegalStateException if confidence type is not BUILDING
     * @return estimated number of hashes needed to reverse the transaction.
     */
    public BigInteger getWorkDone(BlockChain chain) throws BlockStoreException {
        if (getConfidenceType() != ConfidenceType.BUILDING)
            throw new IllegalStateException("Confidence type is " + getConfidenceType() + ", not BUILDING");
        BigInteger work = BigInteger.ZERO;
        int depth = getDepthInBlocks(chain);
        StoredBlock block = chain.getChainHead();
        for (; depth > 0; depth--) {
            work = work.add(block.getChainWork());
            block = block.getPrev(chain.blockStore);
        }
        return work;
    }

    /**
     * If this transaction has been overridden by a double spend (is dead), this call returns the overriding transaction.
     * @return the transaction that double spent this one
     * @throws IllegalStateException if confidence type is not OVERRIDDEN_BY_DOUBLE_SPEND.
     */
    public Transaction getOverridingTransaction() {
        if (getConfidenceType() != ConfidenceType.OVERRIDDEN_BY_DOUBLE_SPEND)
            throw new IllegalStateException("Confidence type is " + getConfidenceType() +
                                            ", not OVERRIDDEN_BY_DOUBLE_SPEND");
        return overridingTransaction;
    }

    /**
     * Called when the transaction becomes newly dead, that is, we learn that one of its inputs has already been spent
     * in such a way that the double-spending transaction takes precence over this one. It will not become valid now
     * unless there is a re-org. Automatically sets the confidence type to OVERRIDDEN_BY_DOUBLE_SPEND.
     */
    public void setOverridingTransaction(Transaction overridingTransaction) {
        setConfidenceType(ConfidenceType.OVERRIDDEN_BY_DOUBLE_SPEND);
        this.overridingTransaction = overridingTransaction;
    }    
}
