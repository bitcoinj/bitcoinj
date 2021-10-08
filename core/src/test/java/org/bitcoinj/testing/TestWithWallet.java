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

package org.bitcoinj.testing;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStore;
import org.junit.BeforeClass;


// TODO: This needs to be somewhat rewritten - the "sendMoneyToWallet" methods aren't sending via the block chain object

/**
 * A utility class that you can derive from in your unit tests. TestWithWallet sets up an empty wallet,
 * an in-memory block store and a block chain object. It also provides helper methods for filling the wallet
 * with money in whatever ways you wish. Note that for simplicity with amounts, this class sets the default
 * fee per kilobyte to zero in setUp.
 */
public class TestWithWallet {
    protected static NetworkParameters UNITTEST;
    protected static NetworkParameters MAINNET;

    protected ECKey myKey;
    protected Address myAddress;

    protected BlockStore blockStore;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Utils.resetMocking();
        UNITTEST = UnitTestParams.get();
        MAINNET = MainNetParams.get();
    }

    public void setUp() throws Exception {
        //BriefLogFormatter.init();
        //myKey = wallet.freshReceiveKey();
        //myAddress = wallet.freshReceiveAddress(Script.ScriptType.P2PKH);
        //blockStore = new MemoryBlockStore(UNITTEST);
        //chain = new BlockChain(UNITTEST, wallet, blockStore);
    }

    public void tearDown() throws Exception {
    }
}
