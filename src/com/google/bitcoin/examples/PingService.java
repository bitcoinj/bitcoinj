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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;

/**
 * PingService demonstrates basic usage of the library. It sits on the network and when it receives coins, simply
 * sends them right back to the previous owner, determined rather arbitrarily by the address of the first input.
 */
public class PingService {
    public static void main(String[] args) throws Exception {
        final NetworkParameters params = NetworkParameters.prodNet();

        // Try to read the wallet from storage, create a new one if not possible.
        Wallet wallet;
        final File walletFile = new File("pingservice.wallet");
        try {
            wallet = Wallet.loadFromFile(walletFile);
        } catch (IOException e) {
            wallet = new Wallet(params);
            wallet.keychain.add(new ECKey());
            wallet.saveToFile(walletFile);
        }
        // Fetch the first key in the wallet (should be the only key).
        ECKey key = wallet.keychain.get(0);

        // Connect to the localhost node.
        System.out.println("Please wait, connecting and downloading block chain. This may take a while.");
        System.out.println("Send coins to: " + key.toAddress(params).toString());

        NetworkConnection conn = new NetworkConnection(InetAddress.getLocalHost(), params);
        BlockChain chain = new BlockChain(params, wallet);
        final Peer peer = new Peer(params, conn, chain);
        peer.start();
        peer.startBlockChainDownload().await();

        // We want to know when the balance changes.
        wallet.addEventListener(new WalletEventListener() {
            public void onCoinsReceived(Wallet w, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                // Running on a peer thread.

                // It's impossible to pick one specific identity that you receive coins from in BitCoin as there
                // could be inputs from many addresses. So instead we just pick the first and assume they were all
                // owned by the same person.
                try {
                    TransactionInput input = tx.getInputs().get(0);
                    Address from = input.getFromAddress();
                    BigInteger value = tx.getValueSentToMe(w);
                    System.out.println("Received " + Utils.bitcoinValueToFriendlyString(value) + " from " + from.toString());
                    // Now send the coins back!
                    Transaction sendTx = w.sendCoins(peer, from, value);
                    assert sendTx != null;  // We should never try to send more coins than we have!
                    System.out.println("Sent coins back! Transaction hash is " + sendTx.getHashAsString());
                    w.saveToFile(walletFile);
                } catch (ScriptException e) {
                    // If we didn't understand the scriptSig, just crash.
                    e.printStackTrace();
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
        });

        System.out.println("Waiting for coins to arrive. Press Ctrl-C to quit.");
        // The peer thread keeps us alive until something kills the process.
    }
}
