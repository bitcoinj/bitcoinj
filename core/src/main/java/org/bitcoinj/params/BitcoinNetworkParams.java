/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.params;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Difficulty;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.BitcoinSerializer;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.Temporal;
import java.time.temporal.TemporalUnit;

import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Parameters for Bitcoin-like networks.
 */
public abstract class BitcoinNetworkParams extends NetworkParameters {
    /**
     * Block reward halving interval (number of blocks)
     */
    public static final int REWARD_HALVING_INTERVAL = 210_000;

    private static final Logger log = LoggerFactory.getLogger(BitcoinNetworkParams.class);

    /** lazy-initialized by the first call to {@link NetworkParameters#getGenesisBlock()} */
    protected Block genesisBlock;

    /**
     * No-args constructor
     */
    public BitcoinNetworkParams(BitcoinNetwork network) {
        super(network);
        interval = INTERVAL;
        subsidyDecreaseBlockCount = REWARD_HALVING_INTERVAL;
    }

    /**
     * Return network parameters for a network id
     * @param id the network id
     * @return the network parameters for the given string ID or NULL if not recognized
     */
    @Nullable
    public static BitcoinNetworkParams fromID(String id) {
        return BitcoinNetwork.fromIdString(id)
                .map(BitcoinNetworkParams::of)
                .orElse(null);
    }

    /**
     * Return network parameters for a {@link BitcoinNetwork} enum
     * @param network the network
     * @return the network parameters for the given string ID
     * @throws IllegalArgumentException if unknown network
     */
    public static BitcoinNetworkParams of(BitcoinNetwork network) {
        switch (network) {
            case MAINNET:
                return MainNetParams.get();
            case TESTNET:
                return TestNet3Params.get();
            case SIGNET:
                return SigNetParams.get();
            case REGTEST:
                return RegTestParams.get();
            default:
                throw new IllegalArgumentException("Unknown network");
        }
    }

    /**
     * Checks if we are at a reward halving point.
     * @param previousHeight The height of the previous stored block
     * @return If this is a reward halving point
     */
    public final boolean isRewardHalvingPoint(final int previousHeight) {
        return ((previousHeight + 1) % REWARD_HALVING_INTERVAL) == 0;
    }

    /**
     * <p>A utility method that calculates how much new Bitcoin would be created by the block at the given height.
     * The inflation of Bitcoin is predictable and drops roughly every 4 years (210,000 blocks). At the dawn of
     * the system it was 50 coins per block, in late 2012 it went to 25 coins per block, and so on. The size of
     * a coinbase transaction is inflation plus fees.</p>
     *
     * <p>The half-life is controlled by {@link NetworkParameters#getSubsidyDecreaseBlockCount()}.</p>
     *
     * @param height the height of the block to calculate inflation for
     * @return block reward (inflation) for specified block
     */
    public Coin getBlockInflation(int height) {
        return Coin.FIFTY_COINS.shiftRight(height / getSubsidyDecreaseBlockCount());
    }

    /**
     * Checks if we are at a difficulty transition point.
     * @param previousHeight The height of the previous stored block
     * @return If this is a difficulty transition point
     */
    public final boolean isDifficultyTransitionPoint(final int previousHeight) {
        return ((previousHeight + 1) % this.getInterval()) == 0;
    }

    @Override
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
        final int interval = this.getInterval();
        for (int i = 0; i < interval; i++) {
            cursor = blockStore.get(hash);
            if (cursor == null) {
                // This should never happen. If it does, it means we are following an incorrect or busted chain.
                throw new VerificationException(
                        "Difficulty transition point but we did not find a way back to the last transition point. Not found: " + hash);
            }
            hash = cursor.getHeader().prevHash();
        }
        checkState(cursor != null && isDifficultyTransitionPoint(cursor.getHeight() - 1), () ->
                "didn't arrive at a transition point");

        Block blockIntervalAgo = cursor.getHeader();
        int timespan = (int) (prev.time().getEpochSecond() - blockIntervalAgo.time().getEpochSecond());
        // Limit the adjustment step.
        final int targetTimespan = this.getTargetTimespan();
        if (timespan < targetTimespan / 4)
            timespan = targetTimespan / 4;
        if (timespan > targetTimespan * 4)
            timespan = targetTimespan * 4;

        Difficulty newTarget = prev.difficultyTarget().adjust(
                Duration.ofSeconds(timespan), Duration.ofSeconds(targetTimespan), this.maxTarget);

        Difficulty receivedTarget = nextBlock.difficultyTarget();
        if (!newTarget.equals(receivedTarget))
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    newTarget + " vs " + receivedTarget);
    }

    @Override
    public BitcoinSerializer getSerializer() {
        return new BitcoinSerializer(network);
    }
}
