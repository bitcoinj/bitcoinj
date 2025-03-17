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

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Difficulty;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Sha256Hash;

import java.time.Instant;

import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class TestNet3Params extends BitcoinNetworkParams {
    public static final int TESTNET_MAJORITY_WINDOW = 100;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 75;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 51;
    private static final Instant GENESIS_TIME = Instant.ofEpochSecond(1296688602);
    private static final long GENESIS_NONCE = 414098458;
    private static final Sha256Hash GENESIS_HASH = Sha256Hash.wrap("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943");

    public TestNet3Params() {
        super(BitcoinNetwork.TESTNET);

        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Difficulty.STANDARD_MAX_DIFFICULTY_TARGET;

        port = 18333;
        packetMagic = 0x0b110907;
        dumpedPrivateKeyHeader = 239;
        spendableCoinbaseDepth = 100;
        bip32HeaderP2PKHpub = 0x043587cf; // The 4 byte header that serializes in base58 to "tpub".
        bip32HeaderP2PKHpriv = 0x04358394; // The 4 byte header that serializes in base58 to "tprv"
        bip32HeaderP2WPKHpub = 0x045f1cf6; // The 4 byte header that serializes in base58 to "vpub".
        bip32HeaderP2WPKHpriv = 0x045f18bc; // The 4 byte header that serializes in base58 to "vprv"

        majorityEnforceBlockUpgrade = TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TESTNET_MAJORITY_WINDOW;

        dnsSeeds = new String[] {
                "testnet-seed.bitcoin.jonasschnelli.ch", // Jonas Schnelli
                "seed.tbtc.petertodd.net",               // Peter Todd
                "seed.testnet.bitcoin.sprovoost.nl",     // Sjors Provoost
                "testnet-seed.bluematt.me",              // Matt Corallo
                "seed.testnet.achownodes.xyz",           // Ava Chow
        };
        addrSeeds = null;

    }

    private static TestNet3Params instance;
    public static synchronized TestNet3Params get() {
        if (instance == null) {
            instance = new TestNet3Params();
        }
        return instance;
    }

    @Override
    public Block getGenesisBlock() {
        synchronized (GENESIS_HASH) {
            if (genesisBlock == null) {
                genesisBlock = Block.createGenesis(GENESIS_TIME, Difficulty.STANDARD_MAX_DIFFICULTY_TARGET,
                        GENESIS_NONCE);
                checkState(genesisBlock.getHash().equals(GENESIS_HASH), () ->
                        "invalid genesis hash");
            }
        }
        return genesisBlock;
    }
}
