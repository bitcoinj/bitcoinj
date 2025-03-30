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

import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.Stopwatch;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.bitcoinj.base.Coin.FIFTY_COINS;
import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Helpers for creating chains of blocks. All these methods are intended for test use only.
 */
@VisibleForTesting
public class TestBlocks {
    private static final byte[] EMPTY_BYTES = new byte[32];
    private static final byte[] pubkeyForTesting = new ECKey().getPubKey();

    private static final Logger log = LoggerFactory.getLogger(TestBlocks.class);

    /**
     * Returns an unsolved block that builds on top of the previous one.
     *
     * @param prev    previous block to build next block on
     * @param to      if not null, 50 coins are sent to the address
     * @param version version of the block to create
     * @param time    time of the block to create
     * @param height  block height if known, or -1 otherwise
     * @return created block
     */
    public static Block createNextBlock(Block prev, @Nullable Address to, long version, Instant time, int height) {
        return createNextBlock(prev, to, version, null, time, pubkeyForTesting, FIFTY_COINS, height);
    }

    /**
     * Returns an unsolved block that builds on top of the previous one.
     * In this variant you can specify a public key (pubkey) for use in generating coinbase blocks.
     *
     * @param prev          previous block to build next block on
     * @param to            if not null, 50 coins are sent to the address
     * @param version       version of the block to create
     * @param prevOut       previous output to spend by the "50 coins transaction"
     * @param time          time of the block to create
     * @param pubKey        for the coinbase
     * @param coinbaseValue for the coinbase
     * @param height        block height if known, or -1 otherwise
     * @return created block
     */
    static Block createNextBlock(Block prev, @Nullable Address to, long version, @Nullable TransactionOutPoint prevOut, Instant time,
                          byte[] pubKey, Coin coinbaseValue, int height) {
        Block b = new Block(version);
        b.setDifficultyTarget(prev.difficultyTarget());
        addCoinbaseTransaction(b, pubKey, coinbaseValue, height);

        if (to != null) {
            // Add a transaction paying 50 coins to the "to" address.
            Transaction t = new Transaction();
            t.addOutput(new TransactionOutput(t, FIFTY_COINS, to));
            // The input does not really need to be a valid signature, as long as it has the right general form.
            TransactionInput input;
            if (prevOut == null) {
                prevOut = new TransactionOutPoint(0, nextTestOutPointHash());
            }
            input = new TransactionInput(t, Script.createInputScript(EMPTY_BYTES, EMPTY_BYTES), prevOut);
            t.addInput(input);
            b.addTransaction(t);
        }

        b.setPrevBlockHash(prev.getHash());
        // Don't let timestamp go backwards
        Instant bitcoinTime = time.truncatedTo(ChronoUnit.SECONDS);
        if (prev.time().compareTo(bitcoinTime) >= 0)
            b.setTime(prev.time().plusSeconds(1));
        else
            b.setTime(bitcoinTime);
        if (b.getVersion() != version) {
            throw new RuntimeException();
        }
        return b;
    }

    // Importantly the outpoint hash cannot be zero as that's how we detect a coinbase transaction in isolation
    // but it must be unique to avoid 'different' transactions looking the same.
    private static Sha256Hash nextTestOutPointHash() {
        byte[] counter = new byte[32];
        counter[0] = (byte) txCounter;
        counter[1] = (byte) (txCounter++ >> 8);
        return Sha256Hash.wrap(counter);
    }

    /**
     * @param prev    previous block to build next block on
     * @param to      if not null, 50 coins are sent to the address
     * @param prevOut previous output to spend by the "50 coins transaction"
     * @return created block
     */
    public static Block createNextBlock(Block prev, @Nullable Address to, TransactionOutPoint prevOut) {
        return createNextBlock(prev, to, Block.BLOCK_VERSION_GENESIS, prevOut, prev.time().plusSeconds(5), pubkeyForTesting,
                FIFTY_COINS, Block.BLOCK_HEIGHT_UNKNOWN);
    }

    /**
     * @param prev          previous block to build next block on
     * @param to            if not null, 50 coins are sent to the address
     * @param coinbaseValue for the coinbase
     * @return created block
     */
    public static Block createNextBlock(Block prev, @Nullable Address to, Coin coinbaseValue) {
        return createNextBlock(prev, to, Block.BLOCK_VERSION_GENESIS, null, prev.time().plusSeconds(5), pubkeyForTesting,
                coinbaseValue, Block.BLOCK_HEIGHT_UNKNOWN);
    }

    /**
     * @param prev previous block to build next block on
     * @param to   if not null, 50 coins are sent to the address
     * @return created block
     */
    public static Block createNextBlock(Block prev, @Nullable Address to) {
        return createNextBlock(prev, to, FIFTY_COINS);
    }

    /**
     * @param prev          previous block to build next block on
     * @param version       version of the block to create
     * @param pubKey        for the coinbase
     * @param coinbaseValue for the coinbase
     * @param height        block height if known, or -1 otherwise
     * @return created block
     */
    public static Block createNextBlockWithCoinbase(Block prev, long version, byte[] pubKey, Coin coinbaseValue, int height) {
        return createNextBlock(prev, null, version, (TransactionOutPoint) null, TimeUtils.currentTime(), pubKey,
                coinbaseValue, height);
    }

    /**
     * Create a block sending 50BTC as a coinbase transaction to the public key specified.
     *
     * @param prev    previous block to build next block on
     * @param version version of the block to create
     * @param pubKey  for the coinbase
     * @param height  block height if known, or -1 otherwise
     * @return created block
     */
    static Block createNextBlockWithCoinbase(Block prev, long version, byte[] pubKey, int height) {
        return createNextBlock(prev, null, version, (TransactionOutPoint) null, TimeUtils.currentTime(), pubKey,
                FIFTY_COINS, height);
    }

    /**
     * Finds a value of nonce that makes the blocks hash lower than the difficulty target. This is called mining, but
     * solving with the CPU is far too slow to do real mining with. It exists only for unit testing purposes.
     * <p>
     * This can loop forever if a solution cannot be found solely by incrementing nonce. It doesn't change
     * extraNonce.
     *
     * @param block block to solve
     */
    public static void solve(Block block) {
        Duration warningThreshold = Duration.ofSeconds(5);
        Stopwatch watch = Stopwatch.start();
        while (true) {
            try {
                // Is our proof of work valid yet?
                if (block.difficultyTarget().isMetByWork(block.getHash()))
                    return;
                // No, so increment the nonce and try again.
                block.setNonce(block.getNonce() + 1);

                if (watch.isRunning() && watch.elapsed().compareTo(warningThreshold) > 0) {
                    watch.stop();
                    log.warn("trying to solve block for longer than {} seconds", warningThreshold.getSeconds());
                }
            } catch (VerificationException e) {
                throw new RuntimeException(e); // Cannot happen.
            }
        }
    }

    // Used to make transactions unique.
    private static int txCounter;

    /**
     * Adds a coinbase transaction to the given block.
     *
     * @param block  block to add coinbase transaction to
     * @param height block height, if known, or -1 otherwise.
     */
    static void addCoinbaseTransaction(Block block, byte[] pubKeyTo, Coin value, final int height) {
        checkState(block.transactions.isEmpty(), () -> "block must not contain transactions");
        // cache will be invalidated when the coinbase is added below
        block.transactions.clear();
        Transaction coinbase = new Transaction();
        final ScriptBuilder inputBuilder = new ScriptBuilder();

        if (height >= Block.BLOCK_HEIGHT_GENESIS) {
            inputBuilder.number(height);
        }
        inputBuilder.data(new byte[]{(byte) txCounter, (byte) (txCounter++ >> 8)});

        // A real coinbase transaction has some stuff in the scriptSig like the extraNonce and difficulty. The
        // transactions are distinguished by every TX output going to a different key.
        //
        // Here we will do things a bit differently so a new address isn't needed every time. We'll put a simple
        // counter in the scriptSig so every transaction has a different hash.
        coinbase.addInput(TransactionInput.coinbaseInput(coinbase,
                inputBuilder.build().program()));
        coinbase.addOutput(new TransactionOutput(coinbase, value,
                ScriptBuilder.createP2PKOutputScript(ECKey.fromPublicOnly(pubKeyTo)).program()));
        block.addTransaction(coinbase);
    }
}
