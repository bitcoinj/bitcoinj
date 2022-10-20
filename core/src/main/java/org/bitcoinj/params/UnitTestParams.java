/*
 * Copyright 2013 Google Inc.
 * Copyright 2019 Andreas Schildbach
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
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Utils;

/**
 * Network parameters used by the bitcoinj unit tests (and potentially your own). This lets you solve a block using
 * {@link Block#solve()} by setting difficulty to the easiest possible.
 */
public class UnitTestParams extends BitcoinNetworkParams {
    public static final int UNITNET_MAJORITY_WINDOW = 8;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 6;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 4;

    public UnitTestParams() {
        // Unit Test Params are BY DEFINITION on the Bitcoin TEST network (i.e. not REGTEST or SIGNET)
        // This means that tests that run against UnitTestParams expect TEST network behavior.
        super(BitcoinNetwork.TESTNET);

        targetTimespan = 200000000;  // 6 years. Just a very big number.
        maxTarget = ByteUtils.decodeCompactBits(Block.EASIEST_DIFFICULTY_TARGET);
        interval = 10;
        subsidyDecreaseBlockCount = 100;

        port = 18333;
        packetMagic = 0x0b110907;
        dumpedPrivateKeyHeader = 239;
        addressHeader = 111;
        p2shHeader = 196;
        segwitAddressHrp = "tb";
        spendableCoinbaseDepth = 5;
        bip32HeaderP2PKHpub = 0x043587cf; // The 4 byte header that serializes in base58 to "tpub".
        bip32HeaderP2PKHpriv = 0x04358394; // The 4 byte header that serializes in base58 to "tprv"
        bip32HeaderP2WPKHpub = 0x045f1cf6; // The 4 byte header that serializes in base58 to "vpub".
        bip32HeaderP2WPKHpriv = 0x045f18bc; // The 4 byte header that serializes in base58 to "vprv"

        majorityEnforceBlockUpgrade = 3;
        majorityRejectBlockOutdated = 4;
        majorityWindow = 7;

        dnsSeeds = null;
        addrSeeds = null;
    }

    private static UnitTestParams instance;
    public static synchronized UnitTestParams get() {
        if (instance == null) {
            instance = new UnitTestParams();
        }
        return instance;
    }

    @Override
    public Block getGenesisBlock() {
        synchronized (this) {
            if (genesisBlock == null) {
                genesisBlock = Block.createGenesis(this);
                genesisBlock.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
                genesisBlock.setTime(Utils.currentTimeSeconds());
                genesisBlock.solve();
            }
        }
        return genesisBlock;
    }
}
