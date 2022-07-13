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
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Sha256Hash;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class MainNetParams extends AbstractBitcoinNetParams {
    public static final int MAINNET_MAJORITY_WINDOW = 1000;
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 950;
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 750;
    private static final long GENESIS_TIME = 1231006505;
    private static final long GENESIS_NONCE = 2083236893;
    private static final Sha256Hash GENESIS_HASH = Sha256Hash.wrap("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

    public MainNetParams() {
        super(BitcoinNetwork.MAINNET);
        id = BitcoinNetwork.ID_MAINNET;

        targetTimespan = TARGET_TIMESPAN;
        maxTarget = ByteUtils.decodeCompactBits(Block.STANDARD_MAX_DIFFICULTY_TARGET);

        port = 8333;
        packetMagic = 0xf9beb4d9L;
        dumpedPrivateKeyHeader = 128;
        addressHeader = 0;
        p2shHeader = 5;
        segwitAddressHrp = "bc";
        spendableCoinbaseDepth = 100;
        bip32HeaderP2PKHpub = 0x0488b21e; // The 4 byte header that serializes in base58 to "xpub".
        bip32HeaderP2PKHpriv = 0x0488ade4; // The 4 byte header that serializes in base58 to "xprv"
        bip32HeaderP2WPKHpub = 0x04b24746; // The 4 byte header that serializes in base58 to "zpub".
        bip32HeaderP2WPKHpriv = 0x04b2430c; // The 4 byte header that serializes in base58 to "zprv"

        majorityEnforceBlockUpgrade = MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MAINNET_MAJORITY_WINDOW;

        // This contains (at a minimum) the blocks which are not BIP30 compliant. BIP30 changed how duplicate
        // transactions are handled. Duplicated transactions could occur in the case where a coinbase had the same
        // extraNonce and the same outputs but appeared at different heights, and greatly complicated re-org handling.
        // Having these here simplifies block connection logic considerably.
        checkpoints.put(91722, Sha256Hash.wrap("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"));
        checkpoints.put(91812, Sha256Hash.wrap("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"));
        checkpoints.put(91842, Sha256Hash.wrap("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"));
        checkpoints.put(91880, Sha256Hash.wrap("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
        checkpoints.put(200000, Sha256Hash.wrap("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"));

        dnsSeeds = new String[] {
                "seed.bitcoin.sipa.be",         // Pieter Wuille
                "dnsseed.bluematt.me",          // Matt Corallo
                "dnsseed.bitcoin.dashjr.org",   // Luke Dashjr
                "seed.bitcoinstats.com",        // Chris Decker
                "seed.bitcoin.jonasschnelli.ch",// Jonas Schnelli
                "seed.btc.petertodd.org",       // Peter Todd
                "seed.bitcoin.sprovoost.nl",    // Sjors Provoost
                "dnsseed.emzy.de",              // Stephan Oeste
                "seed.bitcoin.wiz.biz",         // Jason Maurice
        };

        // These are in big-endian format, which is what the SeedPeers code expects.
        // Updated Apr. 11th 2019
        addrSeeds = new int[] {
                // seed.bitcoin.sipa.be
                0x117c7e18, 0x12641955, 0x1870652e, 0x1dfec3b9, 0x4a330834, 0x5b53382d, 0x77abaca3, 0x09e3d36c,
                0xa0a4e1d4, 0xa275d9c7, 0xa280bc4b, 0xa50d1b76, 0x0a5f84cb, 0xa86cd5bd, 0xb3f427ba, 0xc6fc4cd0,
                0xc73c19b9, 0xd905d85f, 0xd919f9ad, 0xda3fc312, 0xdc4ca5b9, 0xe38ef05b, 0xedce8e57, 0xf68ad23e,
                0xfb3b9c59,
                // dnsseed.bluematt.me
                0x1061d85f, 0x2d5325b0, 0x3505ef91, 0x4c42b14c, 0x623cce72, 0x067e4428, 0x6b47e32e, 0x6e47e32e,
                0x87aed35f, 0x96fe3234, 0xac81419f, 0xb6f9bb25, 0xc9ddb4b9, 0xcbd8aca3, 0xd55c09b0, 0xd5640618,
                0xdaa9144e, 0xdfb99088, 0xe0339650, 0xeb8221af, 0xfcbfd75b,
                // dnsseed.bitcoin.dashjr.org
                0x028ea62e, 0x2cf968be, 0x2d9cf023, 0x3bedb812, 0x40373745, 0x40aa9850, 0x42504a28, 0x50b8f655,
                0x5a86e548, 0x6d79f459, 0x70681b41, 0x74a8cf1f, 0x779233d4, 0x8b2380b2, 0x9dcc342f, 0xa331b5ad,
                0xa95b4c90, 0xb05ff750, 0x0bfde3d4, 0x0c15c136, 0xd3912552, 0xd56ce69d, 0xd8af5454, 0xfce48068,
                // seed.bitcoinstats.com
                0x10c23a35, 0x1168b223, 0x11ae871f, 0x14ddce34, 0x018ce3d5, 0x1b242934, 0x20bcf754, 0x33954d33,
                0x355609b0, 0x39fd202f, 0x4df35e2f, 0x4f23f22b, 0x5707f862, 0x8602bdce, 0x8e09703e, 0x90009ede,
                0x9ffb125b, 0xa33c4c90, 0xa9c4ec57, 0xaa2d5097, 0xae52fb94, 0x00ed2636, 0xedf5649f, 0x0f41a6bc,
                0xfe03cf22,
                // seed.bitcoin.jonasschnelli.ch
                0x23159dd8, 0x368fea55, 0x50bd4031, 0x5395de6c, 0x05c6902f, 0x60c09350, 0x66d6d168, 0x70d90337,
                0x7a549ac3, 0x9012d552, 0x94a60f33, 0xa490ff36, 0xb030d552, 0xb0729450, 0xb12b4c4a, 0x0b7e7e60,
                0xc4f84b2f, 0xc533f42f, 0xc8f60ec2, 0xc9d1bab9, 0xd329cb74, 0xe4b26ab4, 0xe70e5db0, 0xec072034,
                // seed.btc.petertodd.org
                0x10ac1242, 0x131c4a79, 0x1477da47, 0x2899ec63, 0x45660451, 0x4b1b0050, 0x6931d0c2, 0x070ed85f,
                0x806a9950, 0x80b0d522, 0x810d2bc1, 0x829d3b8b, 0x848bdfb0, 0x87a5e52e, 0x9664bb25, 0xa021a6df,
                0x0a5f8548, 0x0a66c752, 0xaaf5b64f, 0xabba464a, 0xc5df4165, 0xe8c5efd5, 0xfa08d01f,
                // seed.bitcoin.sprovoost.nl
                0x14420418, 0x1efdd990, 0x32ded23a, 0x364e1e54, 0x3981d262, 0x39ae6ed3, 0x5143a699, 0x68f861cb,
                0x6f229e23, 0x6fe45d8e, 0x77db09b0, 0x7a1cd85f, 0x8dd03b8b, 0x92aec9c3, 0xa2debb23, 0xa47dee50,
                0xb3566bb4, 0xcb1845b9, 0xcd51c253, 0xd541574d, 0xe0cba936, 0xfb2c26d0,
                // dnsseed.emzy.de
                0x16e0d7b9, 0x1719c2b9, 0x1edfd04a, 0x287eff2d, 0x28f54e3e, 0x3574c1bc, 0x36f1b4cf, 0x3932571b,
                0x3d6f9bbc, 0x4458aa3a, 0x4dd2cf52, 0x05483e97, 0x559caed5, 0x59496251, 0x66d432c6, 0x7501f7c7,
                0x7775599f, 0x8e0ea28b, 0x8f3d0d9d, 0x902695de, 0xa6ada27b, 0xbb00875b, 0xbc26c979, 0xd1a2c58a,
                0xf6d33b8b, 0xf9d95947,
        };
    }

    private static MainNetParams instance;
    public static synchronized MainNetParams get() {
        if (instance == null) {
            instance = new MainNetParams();
        }
        return instance;
    }

    @Override
    public Block getGenesisBlock() {
        synchronized (GENESIS_HASH) {
            if (genesisBlock == null) {
                genesisBlock = Block.createGenesis(this);
                genesisBlock.setDifficultyTarget(Block.STANDARD_MAX_DIFFICULTY_TARGET);
                genesisBlock.setTime(GENESIS_TIME);
                genesisBlock.setNonce(GENESIS_NONCE);
                checkState(genesisBlock.getHash().equals(GENESIS_HASH), "Invalid genesis hash");
            }
        }
        return genesisBlock;
    }
}
