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

package org.monacoinj.params;

import java.math.BigInteger;
import java.util.Date;

import org.monacoinj.core.Block;
import org.monacoinj.core.NetworkParameters;
import org.monacoinj.core.StoredBlock;
import org.monacoinj.core.Utils;
import org.monacoinj.core.VerificationException;
import org.monacoinj.store.BlockStore;
import org.monacoinj.store.BlockStoreException;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Monacoin that has relaxed rules suitable for development
 * and testing of applications and new Monacoin versions.
 */
public class TestNet4Params extends AbstractMonacoinNetParams {
    public TestNet4Params() {
        super();
        id = ID_TESTNET;
        // Genesis hash is 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
        packetMagic = 0xfcc1b7dc;
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1e0fffffL);
        port = 19403;
        addressHeader = 111;
        p2shHeader = 196;
        p2shHeaderAlt = 117;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        dumpedPrivateKeyHeader = 239;
        genesisBlock.setTime(1388479759L);
        genesisBlock.setDifficultyTarget(0x1e0fffffL);
        genesisBlock.setNonce(600389L);
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 1051200;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("a0d810b45c92ac12e8c5b312a680caafba52216e5d9649b9dd86f7ad6550a43f"));
        alertSigningKey = Utils.HEX.decode("04887665070e79d20f722857e58ec8f402733f710135521a0b63441419bf5665ba4623bed13fca0cb2338682ab2a54ad13ce07fbc81c3c2f0912a4eb8521dd3cfb");

        dnsSeeds = new String[] {
                "test-dnsseed.monacoin.org",
                "electrumx1.testnet.monacoin.nl",
                "electrumx1.testnet.monacoin.ninja",
        };
        addrSeeds = null;
        bip32HeaderPub = 0x043587CF;
        bip32HeaderPriv = 0x04358394;

        majorityEnforceBlockUpgrade = 51;
        majorityRejectBlockOutdated = 75;
        majorityWindow = 100;
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

    // February 16th 2012 TODO Mona
    private static final Date testnetDiffDate = new Date(1329264000000L);

    @Override
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
        final BlockStore blockStore) throws VerificationException, BlockStoreException {
        if (!isDifficultyTransitionPoint(storedPrev.getHeight()) && nextBlock.getTime().after(testnetDiffDate)) {
            Block prev = storedPrev.getHeader();

            // After 15th February 2012 the rules on the testnet change to avoid people running up the difficulty
            // and then leaving, making it too hard to mine a block. On non-difficulty transition points, easy
            // blocks are allowed if there has been a span of 20 minutes without one.
            final long timeDelta = nextBlock.getTimeSeconds() - prev.getTimeSeconds();
            // There is an integer underflow bug in monacoin-qt that means mindiff blocks are accepted when time
            // goes backwards.
            if (timeDelta >= 0 && timeDelta <= NetworkParameters.TARGET_SPACING * 2) {
        	// Walk backwards until we find a block that doesn't have the easiest proof of work, then check
        	// that difficulty is equal to that one.
        	StoredBlock cursor = storedPrev;
        	while (!cursor.getHeader().equals(getGenesisBlock()) &&
                       cursor.getHeight() % getInterval() != 0 &&
                       cursor.getHeader().getDifficultyTargetAsInteger().equals(getMaxTarget()))
                    cursor = cursor.getPrev(blockStore);
        	BigInteger cursorTarget = cursor.getHeader().getDifficultyTargetAsInteger();
        	BigInteger newTarget = nextBlock.getDifficultyTargetAsInteger();
        	if (!cursorTarget.equals(newTarget))
                    throw new VerificationException("Testnet block transition that is not allowed: " +
                	Long.toHexString(cursor.getHeader().getDifficultyTarget()) + " vs " +
                	Long.toHexString(nextBlock.getDifficultyTarget()));
            }
        } else {
            super.checkDifficultyTransitions(storedPrev, nextBlock, blockStore);
        }
    }
}
