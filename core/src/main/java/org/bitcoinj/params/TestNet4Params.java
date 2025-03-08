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
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.Block;

import java.time.Instant;

import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Parameters for the testnet 4, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class TestNet4Params extends TestNetParams {
    private static final Instant GENESIS_TIME = Instant.ofEpochSecond(1714777860);
    private static final long GENESIS_NONCE = 393743547;
    private static final String GENESIS_MESSAGE =
            "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
    private static final byte[] GENESIS_OUTPUT_PUBKEY = new byte[33];
    private static final Sha256Hash GENESIS_HASH =
            Sha256Hash.wrap("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043");
    private static final Sha256Hash GENESIS_MERKLE_ROOT =
            Sha256Hash.wrap("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e");

    public TestNet4Params() {
        super(BitcoinNetwork.TESTNET4);

        port = 48333;
        packetMagic = 0x1c163f28;

        dnsSeeds = new String[] {
                "seed.testnet4.bitcoin.sprovoost.nl",  // Sjors Provoost
                "seed.testnet4.wiz.biz",               // Jason Maurice
        };
        addrSeeds = null;
    }

    private static TestNet4Params instance;
    public static synchronized TestNet4Params get() {
        if (instance == null) {
            instance = new TestNet4Params();
        }
        return instance;
    }

    @Override
    public Block getGenesisBlock() {
        synchronized (GENESIS_HASH) {
            if (genesisBlock == null) {
                genesisBlock = Block.createGenesis(GENESIS_TIME, Difficulty.STANDARD_MAX_DIFFICULTY_TARGET,
                        GENESIS_NONCE, GENESIS_MESSAGE, GENESIS_OUTPUT_PUBKEY);
                checkState(genesisBlock.getMerkleRoot().equals(GENESIS_MERKLE_ROOT), () ->
                        "invalid merkle root in block: " + ByteUtils.formatHex(genesisBlock.serialize()));
                checkState(genesisBlock.getHash().equals(GENESIS_HASH), () ->
                        "invalid genesis hash");
            }
        }
        return genesisBlock;
    }
}
