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
import org.bitcoinj.base.Network;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.BitcoinSerializer;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.DifficultyTransitions;
import org.bitcoinj.core.NetworkParameters;

import org.jspecify.annotations.Nullable;

/**
 * Parameters for Bitcoin-like networks.
 */
public abstract class BitcoinNetworkParams extends NetworkParameters {
    /**
     * Block reward halving interval (number of blocks)
     */
    public static final int REWARD_HALVING_INTERVAL = 210_000;

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
     * @deprecated use {@link BitcoinNetwork#fromIdString(String)} or {@link BitcoinNetworkParams#of(BitcoinNetwork)}
     */
    @Deprecated
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
     * Return the {@link BitcoinNetwork} type representing the same Bitcoin-like network that this
     * {@link BitcoinNetworkParams} represents. For almost all purposes, using {@link BitcoinNetwork} is preferable
     * to using {@link BitcoinNetworkParams}. Note that this override narrows the return type from the more general
     * {@link Network}.
     *
     * @return Network enum for this network
     */
    @Override
    public BitcoinNetwork network() {
        return (BitcoinNetwork) network;
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

    /** @deprecated use {@link DifficultyTransitions#isDifficultyTransitionPoint(int)} */
    @Deprecated
    public final boolean isDifficultyTransitionPoint(final int previousHeight) {
        return DifficultyTransitions.of((BitcoinNetwork) network).isDifficultyTransitionPoint(previousHeight);
    }

    @Override
    public BitcoinSerializer getSerializer() {
        return new BitcoinSerializer(network);
    }
}
