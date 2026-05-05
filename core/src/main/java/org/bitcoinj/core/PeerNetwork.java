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

/**
 * Represents the "live" state of a Bitcoin P2P Network. Typically, the network state tracked in this object
 * comes from a {@link PeerGroup}, but this object is independent and there are posisble configurations where
 * it may get its data from other sources.
 * <p>
 * Currently this only contains a {@link TxConfidenceTable} instance, but other "live" data from the P2P network
 * may be migrated here in the future.
 */
public class PeerNetwork {
    private final TxConfidenceTable txConfidenceTable;

    /**
     * Constructor.
     */
    public PeerNetwork() {
        this.txConfidenceTable = new TxConfidenceTable();
    }

    /**
     * Get the {@link TxConfidenceTable}
     * @return The confidence table for this P2P network/chain
     */
    public TxConfidenceTable txConfidenceTable() {
        return txConfidenceTable;
    }
}
