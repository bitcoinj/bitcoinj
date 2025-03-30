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
import org.bitcoinj.base.Difficulty;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import java.time.Duration;

import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Implements the logic for difficulty transitions. These are the standard rules, in place e.g. on mainnet. Some
 * testnets base their logic on the standard rules and extend them with exceptions.
 */
public class StandardDifficultyTransitions implements DifficultyTransitions {
    protected final NetworkParameters params;

    protected StandardDifficultyTransitions(BitcoinNetwork network) {
        this.params = NetworkParameters.of(network);
    }

    /**
     * Checks if we are at a difficulty transition point.
     * @param previousHeight The height of the previous stored block
     * @return If this is a difficulty transition point
     */
    public final boolean isDifficultyTransitionPoint(final int previousHeight) {
        return ((previousHeight + 1) % params.getInterval()) == 0;
    }

    /**
     * Throws an exception if the block's difficulty is not correct.
     *
     * @param storedPrev previous stored block
     * @param nextBlock proposed block
     * @param blockStore active BlockStore
     * @throws VerificationException if the block's difficulty is not correct.
     * @throws BlockStoreException if an error occurred accessing the BlockStore
     */
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
                                           final BlockStore blockStore) throws VerificationException, BlockStoreException {
        final Block prev = storedPrev.getHeader();

        // Is this supposed to be a difficulty transition point?
        if (!isDifficultyTransitionPoint(storedPrev.getHeight())) {

            // No ... so check the difficulty didn't actually change.
            if (!nextBlock.difficultyTarget().equals(prev.difficultyTarget()))
                throw new VerificationException("Unexpected change in difficulty at height " + storedPrev.getHeight() +
                        ": " + nextBlock.difficultyTarget() + " vs " +
                        prev.difficultyTarget());
            return;
        }

        // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
        // two weeks after the initial block chain download.
        Sha256Hash hash = prev.getHash();
        StoredBlock cursor = null;
        final int interval = params.getInterval();
        for (int i = 0; i < interval; i++) {
            cursor = blockStore.get(hash);
            if (cursor == null) {
                // This should never happen. If it does, it means we are following an incorrect or busted chain.
                throw new VerificationException(
                        "Difficulty transition point but we did not find a way back to the last transition point. Not found: " + hash);
            }
            hash = cursor.getHeader().getPrevBlockHash();
        }
        checkState(cursor != null && isDifficultyTransitionPoint(cursor.getHeight() - 1), () ->
                "didn't arrive at a transition point");

        Block blockIntervalAgo = cursor.getHeader();
        int timespan = (int) (prev.time().getEpochSecond() - blockIntervalAgo.time().getEpochSecond());
        // Limit the adjustment step.
        final int targetTimespan = params.getTargetTimespan();
        if (timespan < targetTimespan / 4)
            timespan = targetTimespan / 4;
        if (timespan > targetTimespan * 4)
            timespan = targetTimespan * 4;

        Difficulty newTarget = prev.difficultyTarget().adjust(
                Duration.ofSeconds(timespan), Duration.ofSeconds(targetTimespan), params.maxTarget());

        Difficulty receivedTarget = nextBlock.difficultyTarget();
        if (!newTarget.equals(receivedTarget))
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    newTarget + " vs " + receivedTarget);
    }
}
