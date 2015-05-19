/*
 * Copyright 2013 Google Inc.
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

import org.bitcoinj.core.CoinDefinition;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.net.discovery.HttpDiscovery;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class MainNetParams extends NetworkParameters {
    public MainNetParams() {
        super();
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = CoinDefinition.proofOfWorkLimit; //main.cpp bnProofOfWorkLimit (~uint256(0) >> 20); // UnionCoin: starting difficulty is 1 / 2^12
        dumpedPrivateKeyHeader = CoinDefinition.dumpedPrivateKeyHeader + CoinDefinition.AddressHeader;
        addressHeader = CoinDefinition.AddressHeader;
        p2shHeader = CoinDefinition.p2shHeader;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        port = CoinDefinition.Port;
        packetMagic = CoinDefinition.PacketMagic;
        bip32HeaderPub = 0x0488B21E; //The 4 byte header that serializes in base58 to "xpub".
        bip32HeaderPriv = 0x0488ADE4; //The 4 byte header that serializes in base58 to "xprv"

        genesisBlock.setDifficultyTarget(CoinDefinition.genesisBlockDifficultyTarget);
        genesisBlock.setTime(CoinDefinition.genesisBlockTime);
        genesisBlock.setNonce(CoinDefinition.genesisBlockNonce);
        id = ID_MAINNET;

        spendableCoinbaseDepth = CoinDefinition.spendableCoinbaseDepth;
        String genesisHash = genesisBlock.getHashAsString();
        String merkleRoot = genesisBlock.getMerkleRoot().toString();
        checkState(merkleRoot.equals(CoinDefinition.genesisMerkleRoot),
                merkleRoot);
        checkState(genesisHash.equals(CoinDefinition.genesisHash),
                genesisHash);

        CoinDefinition.initCheckpoints(checkpoints);

        dnsSeeds = CoinDefinition.dnsSeeds;
        httpSeeds = new HttpDiscovery.Details[]{};
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
