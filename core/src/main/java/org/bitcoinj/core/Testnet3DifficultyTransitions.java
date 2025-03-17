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
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import java.time.Instant;

/**
 * Contains the testnet3-specific logic for difficulty transitions.
 */
public class Testnet3DifficultyTransitions extends StandardDifficultyTransitions {
    protected Testnet3DifficultyTransitions(BitcoinNetwork network) {
        super(network);
    }

    /** Spacing for the 20-minute difficulty exception. */
    private static final int TESTNET_DIFFICULTY_EXCEPTION_SPACING = NetworkParameters.TARGET_SPACING * 2;
    // February 16th 2012
    private static final Instant testnetDiffDate = Instant.ofEpochMilli(1329264000000L);

    @Override
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
                                           final BlockStore blockStore) throws VerificationException, BlockStoreException {
        if (!isDifficultyTransitionPoint(storedPrev.getHeight()) && nextBlock.time().isAfter(testnetDiffDate)) {
            // After 15th February 2012 the rules on the testnet change to avoid people running up the difficulty
            // and then leaving, making it too hard to mine a block. On non-difficulty transition points, easy
            // blocks are allowed if there has been a span of 20 minutes without one.
            long timeDelta = nextBlock.time().getEpochSecond() - storedPrev.getHeader().time().getEpochSecond();
            boolean isMinDiffBlock = nextBlock.difficultyTarget().equals(params.maxTarget());
            if (timeDelta < 0 && isMinDiffBlock) {
                // There is an integer underflow bug in Bitcoin Core that means mindiff blocks are accepted when time
                // goes backwards. Thus, skip any further checks.
                return;
            } else if (timeDelta > TESTNET_DIFFICULTY_EXCEPTION_SPACING){
                // 20 minute exception
                checkDifficultyTarget(nextBlock, params.maxTarget());
            } else {
                // If no special rule applies, expect the last non-mindiff difficulty.
                checkDifficultyTarget(nextBlock, backwardsSkipMindiffBlocks(storedPrev, blockStore).difficultyTarget());
            }
        } else {
            super.checkDifficultyTransitions(storedPrev, nextBlock, blockStore);
        }
    }

    private void checkDifficultyTarget(Block nextBlock, Difficulty expectedTarget) {
        Difficulty newTarget = nextBlock.difficultyTarget();
        if (!newTarget.equals(expectedTarget))
            throw new VerificationException("Testnet block transition that is not allowed: " +
                    expectedTarget + " vs " +
                    newTarget);
    }

    private Block backwardsSkipMindiffBlocks(StoredBlock prev, BlockStore blockStore) throws BlockStoreException {
        // Walk backwards until we find a block that doesn't have the easiest proof of work.
        int interval = params.getInterval();
        Difficulty maxTarget = params.maxTarget();
        while (!prev.getHeader().equals(params.getGenesisBlock()) &&
                prev.getHeight() % interval != 0 &&
                prev.getHeader().difficultyTarget().equals(maxTarget))
            prev = prev.getPrev(blockStore);
        return prev.getHeader();
    }
}
