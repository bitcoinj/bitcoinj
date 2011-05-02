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

import java.math.BigInteger;
import java.net.InetAddress;

/**
 * This example shows how to solve the challenge Hal posted here:<p>
 *
 *   <a href="http://www.bitcoin.org/smf/index.php?topic=3638.0">http://www.bitcoin.org/smf/index.php?topic=3638
 *   .0</a><p>
 *
 * in which a private key with some coins associated with it is published. The goal is to import the private key,
 * claim the coins and then send them to a different address.
 */
public class PrivateKeys {
    public static void main(String[] args) throws Exception {
        NetworkParameters params = NetworkParameters.prodNet();
        try {
            // Decode the private key from Satoshis Base58 variant.
            BigInteger privKey = Base58.decodeToBigInteger(args[0]);
            ECKey key = new ECKey(privKey);
            System.out.println("Address from private key is: " + key.toAddress(params).toString());
            // And the address ...
            Address destination = new Address(params, args[1]);

            // Import the private key to a fresh wallet.
            Wallet wallet = new Wallet(params);
            wallet.addKey(key);

            // Find the transactions that involve those coins.
            NetworkConnection conn = new NetworkConnection(InetAddress.getLocalHost(), params, 0, 60000);
            BlockChain chain = new BlockChain(params, wallet, new MemoryBlockStore(params));
            Peer peer = new Peer(params, conn, chain);
            peer.start();
            peer.startBlockChainDownload().await();

            // And take them!
            System.out.println("Claiming " + Utils.bitcoinValueToFriendlyString(wallet.getBalance()) + " coins");
            wallet.sendCoins(peer, destination, wallet.getBalance());
            // Wait a few seconds to let the packets flush out to the network (ugly).
            Thread.sleep(5000);
            peer.disconnect();
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("First arg should be private key in Base58 format. Second argument should be address " +
                    "to send to.");
            return;
        }
    }
}
