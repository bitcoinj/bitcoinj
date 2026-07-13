/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import java.math.BigInteger;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for Bitcoin testnet4, the network defined in BIP-94. It replaces testnet3 with a
 * fresh genesis block (a new coinbase message and output, hence a different merkle root and hash)
 * and adjusted proof-of-work rules that mitigate the testnet3 "block storm" and time-warp issues.
 *
 * The {@link #checkDifficultyTransitions} logic implements the BIP-94 rules and is validated
 * against real testnet4 headers (see TestNet4ParamsTest). Note: a later, still-unsettled Bitcoin
 * Core proposal would disable the minimum-difficulty exception past a fixed testnet4 height
 * (bitcoin/bitcoin#34420, superseded by #35081); it is intentionally NOT implemented here and
 * should be revisited once the target Bitcoin Core version finalizes it.
 */
public class TestNet4Params extends AbstractBitcoinNetParams {
    public static final int TESTNET_MAJORITY_WINDOW = 100;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 75;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 51;

    // testnet4 timewarp mitigation: first block of a difficulty period must not be timestamped
    // more than this many seconds before the previous block.
    private static final long MAX_TIMEWARP_SECONDS = 600L;

    // Mid-period, a block may use the minimum-difficulty exception only if it was mined more than
    // this many seconds after the previous block (the testnet "20 minute rule").
    private static final long MIN_DIFFICULTY_EXCEPTION_GAP_SECONDS = NetworkParameters.TARGET_SPACING * 2L;

    // Full coinbase input script of the testnet4 genesis block:
    //   push(0x1d00ffff) push(4) push("03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e")
    private static final byte[] GENESIS_COINBASE_SCRIPT_SIG = Utils.HEX.decode(
        "04ffff001d01044c4c30332f4d61792f323032342030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065");

    // testnet4 genesis output is a push of 33 zero bytes followed by OP_CHECKSIG.
    private static final byte[] GENESIS_OUTPUT_PUBKEY = new byte[33];

    public TestNet4Params() {
        super();
        id = ID_TESTNET4;
        // testnet4 network magic (differs from testnet3's 0x0b110907).
        packetMagic = 0x1c163f28;
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        port = 48333;
        // Address prefixes and HRP are shared with testnet3.
        addressHeader = 111;
        p2shHeader = 196;
        dumpedPrivateKeyHeader = 239;
        segwitAddressHrp = "tb";

        // Rebuild the genesis block with the testnet4 coinbase (different from the shared
        // "The Times 03/Jan/2009 ..." coinbase produced by NetworkParameters#createGenesis).
        genesisBlock = buildGenesisBlock(this, GENESIS_COINBASE_SCRIPT_SIG, GENESIS_OUTPUT_PUBKEY);
        genesisBlock.setTime(1714777860L);
        genesisBlock.setDifficultyTarget(0x1d00ffffL);
        genesisBlock.setNonce(393743547L);

        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 210000;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
            "Unexpected testnet4 genesis hash: " + genesisHash);
        alertSigningKey = Utils.HEX.decode("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");

        dnsSeeds = new String[] {
                "seed.testnet4.bitcoin.sprovoost.nl", // Sjors Provoost
                "seed.testnet4.wiz.biz",              // Jason Maurice
        };
        addrSeeds = null;
        bip32HeaderP2PKHpub = 0x043587cf; // The 4 byte header that serializes in base58 to "tpub".
        bip32HeaderP2PKHpriv = 0x04358394; // The 4 byte header that serializes in base58 to "tprv"
        bip32HeaderP2WPKHpub = 0x045f1cf6; // The 4 byte header that serializes in base58 to "vpub".
        bip32HeaderP2WPKHpriv = 0x045f18bc; // The 4 byte header that serializes in base58 to "vprv"

        majorityEnforceBlockUpgrade = TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TESTNET_MAJORITY_WINDOW;
    }

    private static TestNet4Params instance;
    public static synchronized TestNet4Params get() {
        if (instance == null) {
            instance = new TestNet4Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET;
    }

    @Override
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
        final BlockStore blockStore) throws VerificationException, BlockStoreException {

        boolean isFirstBlockOfNewPeriod = isDifficultyTransitionPoint(storedPrev.getHeight());
        if (isFirstBlockOfNewPeriod) {
            checkRetargetDifficulty(storedPrev, nextBlock, blockStore);
        } else {
            checkMidPeriodDifficulty(storedPrev, nextBlock, blockStore);
        }
    }

    /**
     * Mid-period rule (shared with testnet3): a block mined promptly (within the 20-minute window)
     * must carry the last real, non-minimum difficulty; a block mined after a longer gap (or with a
     * backwards timestamp) may use the minimum-difficulty exception, so no constraint is enforced.
     */
    private void checkMidPeriodDifficulty(final StoredBlock storedPrev, final Block nextBlock,
        final BlockStore blockStore) throws VerificationException, BlockStoreException {

        Block previousHeader = storedPrev.getHeader();
        long secondsSincePreviousBlock = nextBlock.getTimeSeconds() - previousHeader.getTimeSeconds();

        boolean minedWithinDifficultyWindow =
            secondsSincePreviousBlock >= 0 && secondsSincePreviousBlock <= MIN_DIFFICULTY_EXCEPTION_GAP_SECONDS;
        if (!minedWithinDifficultyWindow) {
            return;
        }

        StoredBlock lastRealDifficultyBlock = findLastNonMinimumDifficultyBlock(storedPrev, blockStore);
        BigInteger requiredTarget = lastRealDifficultyBlock.getHeader().getDifficultyTargetAsInteger();
        BigInteger declaredTarget = nextBlock.getDifficultyTargetAsInteger();

        boolean declaredTargetMatchesRequired = declaredTarget.equals(requiredTarget);
        if (!declaredTargetMatchesRequired) {
            throw new VerificationException("Testnet4 block transition that is not allowed: " +
                Long.toHexString(lastRealDifficultyBlock.getHeader().getDifficultyTarget()) + " vs " +
                Long.toHexString(nextBlock.getDifficultyTarget()));
        }
    }

    /**
     * Retarget rule (BIP-94), applied to the first block of a new period. It differs from testnet3 in
     * two ways: it enforces the time-warp floor, and it anchors the calculation to the FIRST block of
     * the closing period (guaranteed real difficulty) instead of the last block.
     */
    private void checkRetargetDifficulty(final StoredBlock storedPrev, final Block nextBlock,
        final BlockStore blockStore) throws VerificationException, BlockStoreException {

        Block previousHeader = storedPrev.getHeader();

        boolean violatesTimewarpFloor =
            nextBlock.getTimeSeconds() < previousHeader.getTimeSeconds() - MAX_TIMEWARP_SECONDS;
        if (violatesTimewarpFloor) {
            throw new VerificationException("Testnet4 time-warp violation at difficulty transition: block time " +
                nextBlock.getTimeSeconds() + " is more than " + MAX_TIMEWARP_SECONDS +
                "s before previous block time " + previousHeader.getTimeSeconds());
        }

        Block firstBlockOfPeriod = findFirstBlockOfPeriod(previousHeader, blockStore);
        int periodTimespanSeconds =
            clampToAllowedTimespan((int) (previousHeader.getTimeSeconds() - firstBlockOfPeriod.getTimeSeconds()));

        BigInteger newTarget = Utils.decodeCompactBits(firstBlockOfPeriod.getDifficultyTarget())
            .multiply(BigInteger.valueOf(periodTimespanSeconds))
            .divide(BigInteger.valueOf(getTargetTimespan()));

        boolean targetBelowMinimumDifficulty = newTarget.compareTo(getMaxTarget()) > 0;
        if (targetBelowMinimumDifficulty) {
            newTarget = getMaxTarget();
        }

        long declaredTargetCompact = nextBlock.getDifficultyTarget();
        long expectedTargetCompact = reduceToDeclaredPrecision(newTarget, declaredTargetCompact);

        boolean declaredTargetMatchesExpected = expectedTargetCompact == declaredTargetCompact;
        if (!declaredTargetMatchesExpected) {
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                Long.toHexString(expectedTargetCompact) + " vs " + Long.toHexString(declaredTargetCompact));
        }
    }

    /**
     * Walks backwards from {@code from}, skipping consecutive minimum-difficulty blocks, and returns the
     * first block carrying a real difficulty (also stopping at the genesis block or a period boundary).
     */
    private StoredBlock findLastNonMinimumDifficultyBlock(final StoredBlock from, final BlockStore blockStore)
        throws BlockStoreException {

        StoredBlock cursor = from;
        while (isSkippableMinimumDifficultyBlock(cursor)) {
            cursor = cursor.getPrev(blockStore);
        }
        return cursor;
    }

    private boolean isSkippableMinimumDifficultyBlock(final StoredBlock block) {
        boolean isGenesis = block.getHeader().equals(getGenesisBlock());
        boolean isPeriodBoundary = block.getHeight() % getInterval() == 0;
        boolean isMinimumDifficulty = block.getHeader().getDifficultyTargetAsInteger().equals(getMaxTarget());
        return !isGenesis && !isPeriodBoundary && isMinimumDifficulty;
    }

    /**
     * Walks back one full period from the last block of a period to its first block, asserting that the
     * traversal lands on a difficulty-transition boundary.
     */
    private Block findFirstBlockOfPeriod(final Block lastBlockOfPeriod, final BlockStore blockStore)
        throws VerificationException, BlockStoreException {

        Sha256Hash hash = lastBlockOfPeriod.getHash();
        StoredBlock cursor = null;
        int interval = getInterval();
        for (int stepsBack = 0; stepsBack < interval; stepsBack++) {
            cursor = blockStore.get(hash);
            if (cursor == null) {
                throw new VerificationException(
                    "Difficulty transition point but we did not find a way back to the last transition point. Not found: " + hash);
            }
            hash = cursor.getHeader().getPrevBlockHash();
        }
        checkState(cursor != null && isDifficultyTransitionPoint(cursor.getHeight() - 1),
            "Didn't arrive at a transition point.");
        return cursor.getHeader();
    }

    /** Clamps the measured timespan to [targetTimespan/4, targetTimespan*4], per the standard retarget rules. */
    private int clampToAllowedTimespan(final int timespanSeconds) {
        int minimumTimespan = getTargetTimespan() / 4;
        int maximumTimespan = getTargetTimespan() * 4;
        if (timespanSeconds < minimumTimespan) {
            return minimumTimespan;
        }
        if (timespanSeconds > maximumTimespan) {
            return maximumTimespan;
        }
        return timespanSeconds;
    }

    /**
     * Reduces a freshly-computed target to the precision of the declared compact bits and re-encodes it, so
     * the two can be compared exactly (the calculation is higher-precision than the compact-bits format).
     */
    private static long reduceToDeclaredPrecision(final BigInteger target, final long declaredTargetCompact) {
        int accuracyBytes = (int) (declaredTargetCompact >>> 24) - 3;
        BigInteger precisionMask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        return Utils.encodeCompactBits(target.and(precisionMask));
    }
}
