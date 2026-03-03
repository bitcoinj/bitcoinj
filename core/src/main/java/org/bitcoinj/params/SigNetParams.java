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

package org.bitcoinj.params;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Difficulty;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Sha256Hash;

import java.time.Instant;

import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * <p>Parameters for the signet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.</p>
 * <p>See <a href="https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki">BIP325</a>
 */
public class SigNetParams extends BitcoinNetworkParams {
    public static final int TESTNET_MAJORITY_WINDOW = 100;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 75;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 51;
    private static final Difficulty GENESIS_DIFFICULTY = Difficulty.ofCompact(0x1e0377ae);
    private static final Instant GENESIS_TIME = Instant.ofEpochSecond(1598918400);
    private static final long GENESIS_NONCE = 52613770;
    private static final Sha256Hash GENESIS_HASH = Sha256Hash.wrap("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6");

    public SigNetParams() {
        super(BitcoinNetwork.SIGNET);

        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Difficulty.EASIEST_DIFFICULTY_TARGET;

        port = 38333;
        packetMagic = 0x0a03cf40;
        dumpedPrivateKeyHeader = 239;
        spendableCoinbaseDepth = 100;
        bip32HeaderP2PKHpub = 0x043587cf; // The 4 byte header that serializes in base58 to "tpub".
        bip32HeaderP2PKHpriv = 0x04358394; // The 4 byte header that serializes in base58 to "tprv"
        bip32HeaderP2WPKHpub = bip32HeaderP2PKHpub;
        bip32HeaderP2WPKHpriv = bip32HeaderP2PKHpriv;

        majorityEnforceBlockUpgrade = TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TESTNET_MAJORITY_WINDOW;

        dnsSeeds = new String[] {
                "seed.signet.bitcoin.sprovoost.nl", // Sjors Provoost
                "seed.signet.achownodes.xyz",       // Ava Chow
        };
        addrSeeds = null;
    }

    private static SigNetParams instance;
    public static synchronized SigNetParams get() {
        if (instance == null) {
            instance = new SigNetParams();
        }
        return instance;
    }

    @Override
    public Block getGenesisBlock() {
        synchronized (GENESIS_HASH) {
            if (genesisBlock == null) {
                genesisBlock = Block.createGenesis(GENESIS_TIME, GENESIS_DIFFICULTY, GENESIS_NONCE, GENESIS_MESSAGE,
                        GENESIS_OUTPUT_PUBKEY);
                checkState(genesisBlock.getMerkleRoot().equals(GENESIS_MERKLE_ROOT), () ->
                        "invalid merkle root in block: " + ByteUtils.formatHex(genesisBlock.serialize()));
                checkState(genesisBlock.getHash().equals(GENESIS_HASH), () ->
                        "invalid genesis hash");
            }
        }
        return genesisBlock;
    }
}
