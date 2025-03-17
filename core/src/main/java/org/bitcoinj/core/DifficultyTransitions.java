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

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

/**
 * Interface for the logic for difficulty transitions.
 */
public interface DifficultyTransitions {
    /**
     * Return difficulty transition logic for a {@link BitcoinNetwork} enum
     *
     * @param network the network
     * @return the difficulty transition logic for the given string ID
     */
    static StandardDifficultyTransitions of(BitcoinNetwork network) {
        switch (network) {
            case TESTNET:
                return new Testnet3DifficultyTransitions(network);
            default:
                return new StandardDifficultyTransitions(network);
        }
    }

    boolean isDifficultyTransitionPoint(int previousHeight);

    void checkDifficultyTransitions(StoredBlock storedPrev, Block nextBlock,
                                    BlockStore blockStore) throws VerificationException, BlockStoreException;
}
