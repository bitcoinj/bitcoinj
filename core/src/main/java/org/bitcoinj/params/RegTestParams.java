/*
 * Copyright 2013 Google Inc.
 * Copyright 2018 Andreas Schildbach
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
import org.bitcoinj.base.Sha256Hash;

import static com.google.common.base.Preconditions.checkState;

/**
 * Network parameters for the regression test mode of bitcoind in which all blocks are trivially solvable.
 */
public class RegTestParams extends AbstractBitcoinNetParams {
    private static final long GENESIS_TIME = 1296688602;
    private static final long GENESIS_NONCE = 2;
    private static final Sha256Hash GENESIS_HASH = Sha256Hash.wrap("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");

    public RegTestParams() {
        super(BitcoinNetwork.REGTEST);
        id = BitcoinNetwork.ID_REGTEST;
        
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = ByteUtils.decodeCompactBits(Block.EASIEST_DIFFICULTY_TARGET);
        // Difficulty adjustments are disabled for regtest.
        // By setting the block interval for difficulty adjustments to Integer.MAX_VALUE we make sure difficulty never
        // changes.
        interval = Integer.MAX_VALUE;
        subsidyDecreaseBlockCount = 150;

        port = 18444;
        packetMagic = 0xfabfb5daL;
        dumpedPrivateKeyHeader = 239;
        addressHeader = 111;
        p2shHeader = 196;
        segwitAddressHrp = "bcrt";
        spendableCoinbaseDepth = 100;
        bip32HeaderP2PKHpub = 0x043587cf; // The 4 byte header that serializes in base58 to "tpub".
        bip32HeaderP2PKHpriv = 0x04358394; // The 4 byte header that serializes in base58 to "tprv"
        bip32HeaderP2WPKHpub = 0x045f1cf6; // The 4 byte header that serializes in base58 to "vpub".
        bip32HeaderP2WPKHpriv = 0x045f18bc; // The 4 byte header that serializes in base58 to "vprv"

        majorityEnforceBlockUpgrade = MainNetParams.MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MainNetParams.MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MainNetParams.MAINNET_MAJORITY_WINDOW;

        dnsSeeds = null;
        addrSeeds = null;
    }

    @Override
    public boolean allowEmptyPeerChain() {
        return true;
    }

    private static RegTestParams instance;
    public static synchronized RegTestParams get() {
        if (instance == null) {
            instance = new RegTestParams();
        }
        return instance;
    }

    @Override
    public Block getGenesisBlock() {
        synchronized (GENESIS_HASH) {
            if (genesisBlock == null) {
                genesisBlock = Block.createGenesis(this);
                genesisBlock.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
                genesisBlock.setTime(GENESIS_TIME);
                genesisBlock.setNonce(GENESIS_NONCE);
                checkState(genesisBlock.getHash().equals(GENESIS_HASH), "Invalid genesis hash");
            }
        }
        return genesisBlock;
    }
}
