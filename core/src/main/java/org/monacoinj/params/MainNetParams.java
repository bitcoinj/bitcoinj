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

package org.monacoinj.params;

import org.monacoinj.core.*;
import org.monacoinj.net.discovery.*;

import java.net.*;

import static com.google.common.base.Preconditions.*;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class MainNetParams extends AbstractMonacoinNetParams {
    public static final int MAINNET_MAJORITY_WINDOW = 1000;
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 950;
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 750;

    public MainNetParams() {
        super();
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1e0fffffL);
        dumpedPrivateKeyHeader = 176;
        dumpedPrivateKeyHeaderAlt = 178; // TODO Mona still monacoin-qt 0.10.x
        addressHeader = 50;
        p2shHeader = 55;
        p2shHeaderAlt = 5; // TODO Mona
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        port = 9401;
        packetMagic = 0xfbc0b6dbL;
        bip32HeaderPub = 0x0488B21E; //The 4 byte header that serializes in base58 to "xpub".
        bip32HeaderPriv = 0x0488ADE4; //The 4 byte header that serializes in base58 to "xprv"

        majorityEnforceBlockUpgrade = MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MAINNET_MAJORITY_WINDOW;

        genesisBlock.setDifficultyTarget(0x1e0ffff0L);
        genesisBlock.setTime(1388479472L);
        genesisBlock.setNonce(1234534L);
        id = ID_MAINNET;
        subsidyDecreaseBlockCount = 1051200;
        spendableCoinbaseDepth = 100;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("ff9f1c0116d19de7c9963845e129f9ed1bfc0b376eb54fd7afa42e0d418c8bb6"),
                genesisHash);

        // This contains (at a minimum) the blocks which are not BIP30 compliant. BIP30 changed how duplicate
        // transactions are handled. Duplicated transactions could occur in the case where a coinbase had the same
        // extraNonce and the same outputs but appeared at different heights, and greatly complicated re-org handling.
        // Having these here simplifies block connection logic considerably.
        // Monacoin's default is "True"(BIP30)
        checkpoints.put(1500, Sha256Hash.wrap("9f42d51d18d0a8914a00664c433a0ca4be3eed02f9374d790bffbd3d3053d41d"));
        checkpoints.put(4000, Sha256Hash.wrap("2c60edac7d9f44d90d1e218af2a8085e78b735185c5bf42f9fe9dbd0e604c97b"));
        checkpoints.put(8000, Sha256Hash.wrap("61d4d053b1a4c6deb4c7e806cedd876f25b51da6c51b209109579c7b9892e5c2"));
        checkpoints.put(16000, Sha256Hash.wrap("3c4a8887bb3ae0599abfefe765f7c911fbfe98b3f23d7f70b05bf49cf62ebdaf"));
        checkpoints.put(32000, Sha256Hash.wrap("c0703986c1c6a9052478db5e52432e5a1e55d6b6362b85f0ffdbb61ce3311b77"));
        checkpoints.put(58700, Sha256Hash.wrap("a9c5d9878864b77ba52b068787b83ce2fcf526c5899f40af51c9d441eeb4c84d"));
        checkpoints.put(80000, Sha256Hash.wrap("c99b83da7328b58251d16f4646da222b0280f180bd208efa5e3256c9eb6ea2be"));
        checkpoints.put(115000, Sha256Hash.wrap("75e642c003e5bd748b679472e981b7b2f81f344b3f197029f84470256cef33e4"));
        checkpoints.put(189250, Sha256Hash.wrap("1bea3d5c25a8097eef2e70ece4beb6c502b895fe00056552948309beb3497c99"));
        checkpoints.put(300000, Sha256Hash.wrap("11095515590421444ba29396d9122c234baced79be8b32604acc37cf094558ab"));
        checkpoints.put(444000, Sha256Hash.wrap("3ed05516cdce4db93b135189592c7e2b37d768f99a1819a1d2ea3a8e5b8439a8"));
        checkpoints.put(450000, Sha256Hash.wrap("353f5b7f9440e1d830bd1c265c69fb0e7c7988e343b2202a704406d04a8cd02e"));
        checkpoints.put(904000, Sha256Hash.wrap("3c4a8887bb3ae0599abfefe765f7c911fbfe98b3f23d7f70b05bf49cf62ebdaf"));
        checkpoints.put(1045000, Sha256Hash.wrap("562593372b8cee7d2eac325ef8874532d93cc031a75a00cec0086d2d943f40dc"));

        dnsSeeds = new String[] {
                "dnsseed.monacoin.org",
                "monacoin.org",
                "electrumx.tamami-foundation.org",
        };
        //httpSeeds = new HttpDiscovery.Details[] {
        //        // Andreas Schildbach
        //        new HttpDiscovery.Details(
        //                ECKey.fromPublicOnly(Utils.HEX.decode("0238746c59d46d5408bf8b1d0af5740fe1a6e1703fcb56b2953f0b965c740d256f")),
        //                URI.create("http://httpseed.monacoin.schildbach.de/peers")
        //        )
        //};

        addrSeeds = null // TODO Mona
    }

    private static MainNetParams instance;
    public static synchronized MainNetParams get() {
        if (instance == null) {
            instance = new MainNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_MAINNET;
    }
}
