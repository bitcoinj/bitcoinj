/**
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
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.store.MemoryBlockStore;

import java.math.BigInteger;
import java.net.InetAddress;

/**
 * This example shows how to solve the challenge Hal posted here:<p>
 *
 * <a href="http://www.bitcoin.org/smf/index.php?topic=3638.0">http://www.bitcoin.org/smf/index.php?topic=3638
 * .0</a><p>
 *
 * in which a private key with some coins associated with it is published. The goal is to import the private key,
 * claim the coins and then send them to a different address.
 */
public class PrivateKeys {
    public static void main(String[] args) throws Exception {
        // TODO: Assumes main network not testnet. Make it selectable.
        NetworkParameters params = MainNetParams.get();
        try {
            // Decode the private key from Satoshis Base58 variant. If 51 characters long then it's from Bitcoins
            // dumpprivkey command and includes a version byte and checksum. Otherwise assume it's a raw key.
            ECKey key;
            if (args[0].length() == 51) {
                DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(params, args[0]);
                key = dumpedPrivateKey.getKey();
            } else {
                BigInteger privKey = Base58.decodeToBigInteger(args[0]);
                key = new ECKey(privKey);
            }
            System.out.println("Address from private key is: " + key.toAddress(params).toString());
            // And the address ...
            Address destination = new Address(params, args[1]);

            // Import the private key to a fresh wallet.
            Wallet wallet = new Wallet(params);
            wallet.addKey(key);

            // Find the transactions that involve those coins.
            final MemoryBlockStore blockStore = new MemoryBlockStore(params);
            BlockChain chain = new BlockChain(params, wallet, blockStore);

            final PeerGroup peerGroup = new PeerGroup(params, chain);
            peerGroup.addAddress(new PeerAddress(InetAddress.getLocalHost()));
            peerGroup.start();
            peerGroup.downloadBlockChain();
            peerGroup.stop();

            // And take them!
            System.out.println("Claiming " + Utils.bitcoinValueToFriendlyString(wallet.getBalance()) + " coins");
            wallet.sendCoins(peerGroup, destination, wallet.getBalance());
            // Wait a few seconds to let the packets flush out to the network (ugly).
            Thread.sleep(5000);
            System.exit(0);
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("First arg should be private key in Base58 format. Second argument should be address " +
                    "to send to.");
            return;
        }
    }
}
