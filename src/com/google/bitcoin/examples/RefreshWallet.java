/*
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.examples;

import com.google.bitcoin.core.*;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.MemoryBlockStore;

import java.io.File;
import java.math.BigInteger;
import java.net.InetAddress;

/**
 * RefreshWallet loads a wallet, then processes the block chain to update the transaction pools within it.
 */
public class RefreshWallet {
    public static void main(String[] args) throws Exception {
        File file = new File(args[0]);
        Wallet wallet = Wallet.loadFromFile(file);
        System.out.println(wallet.toString());

        // Set up the components and link them together.
        final NetworkParameters params = NetworkParameters.testNet();
        BlockStore blockStore = new MemoryBlockStore(params);
        BlockChain chain = new BlockChain(params, wallet, blockStore);

        final PeerGroup peerGroup = new PeerGroup(params, chain);
        peerGroup.addAddress(new PeerAddress(InetAddress.getLocalHost()));
        peerGroup.start();

        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet w, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                System.out.println("\nReceived tx " + tx.getHashAsString());
                System.out.println(tx.toString());
            }
        });

        // Now download and process the block chain.
        peerGroup.downloadBlockChain();
        peerGroup.stop();
        wallet.saveToFile(file);
        System.out.println("\nDone!\n");
        System.out.println(wallet.toString());
    }
}
