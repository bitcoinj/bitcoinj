/*
 * Copyright 2016 Robin Owens
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
package org.bitcoinj.examples;

import java.net.InetAddress;
import org.bitcoinj.core.FullPrunedBlockChain;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.FullPrunedBlockStore;
import org.bitcoinj.store.LevelDbFullPrunedBlockStore;

public class LevelDb {
    public static void main(String[] args) throws Exception {
        /*
         * This is just a test runner that will download blockchain till block
         * 390000 then exit.
         */
        FullPrunedBlockStore store = new LevelDbFullPrunedBlockStore(
                MainNetParams.get(), args[0], 1000, 100 * 1024 * 1024l,
                10 * 1024 * 1024, 100000, true, 390000);

        FullPrunedBlockChain vChain = new FullPrunedBlockChain(
                MainNetParams.get(), store);
        vChain.setRunScripts(false);

        PeerGroup vPeerGroup = new PeerGroup(MainNetParams.get(), vChain);
        vPeerGroup.setUseLocalhostPeerWhenPossible(true);
        vPeerGroup.addAddress(InetAddress.getLocalHost());

        vPeerGroup.start();
        vPeerGroup.downloadBlockChain();

    }

}
