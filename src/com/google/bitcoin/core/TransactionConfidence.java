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

import java.io.Serializable;
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
}
