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
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BoundedOverheadBlockStore;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;

/**
 * <p>
 * PingService demonstrates basic usage of the library. It sits on the network and when it receives coins, simply
 * sends them right back to the previous owner, determined rather arbitrarily by the address of the first input.
 * </p>
 *
 * <p>
 * If running on TestNet (slow but better than using real coins on prodnet) do the following:
 * <ol>
 * <li>Backup your current wallet.dat in case of unforeseen problems</li>
 * <li>Start your bitcoin client in test mode <code>bitcoin -testnet</code>. This will create a new sub-directory called testnet and should not interfere with normal wallets or operations.</li>
 * <li>(Optional) Choose a fresh address</li>
 * <li>(Optional) Visit the Testnet faucet (https://testnet.freebitcoins.appspot.com/) to load your client with test coins</li>
 * <li>Run <code>PingService -testnet</code></li>
 * <li>Wait for the block chain to download</li>
 * <li>Send some coins from your bitcoin client to the address provided in the PingService console</li>
 * <li>Leave it running until you get the coins back again</li>
 * </ol>
 * </p>
 *
 * <p>The testnet can be slow or flaky as it's a shared resource. You can use the <a href="http://sourceforge
 * .net/projects/bitcoin/files/Bitcoin/testnet-in-a-box/">testnet in a box</a> to do everything purely locally.</p>
 */
public class PingService {
    public static void main(String[] args) throws Exception {
        boolean testNet = args.length > 0 && args[0].equalsIgnoreCase("testnet");
        final NetworkParameters params = testNet ? NetworkParameters.testNet() : NetworkParameters.prodNet();
        String filePrefix = testNet ? "pingservice-testnet" : "pingservice-prodnet";

        // Try to read the wallet from storage, create a new one if not possible.
        Wallet wallet;
        final File walletFile = new File(filePrefix + ".wallet");
        try {
            wallet = Wallet.loadFromFile(walletFile);
        } catch (IOException e) {
            wallet = new Wallet(params);
            wallet.keychain.add(new ECKey());
            wallet.saveToFile(walletFile);
        }
        // Fetch the first key in the wallet (should be the only key).
        ECKey key = wallet.keychain.get(0);

        System.out.println(wallet);

        // Load the block chain, if there is one stored locally.
        System.out.println("Reading block store from disk");
        BlockStore blockStore = new BoundedOverheadBlockStore(params, new File(filePrefix + ".blockchain"));

        // Connect to the localhost node. One minute timeout since we won't try any other peers
        System.out.println("Connecting ...");
        BlockChain chain = new BlockChain(params, wallet, blockStore);
        
        final PeerGroup peerGroup = new PeerGroup(blockStore, params, chain);
        peerGroup.addAddress(new PeerAddress(InetAddress.getLocalHost()));
        peerGroup.start();

        // We want to know when the balance changes.
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet w, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                // Running on a peer thread.
                assert !newBalance.equals(BigInteger.ZERO);
                // It's impossible to pick one specific identity that you receive coins from in BitCoin as there
                // could be inputs from many addresses. So instead we just pick the first and assume they were all
                // owned by the same person.
                try {
                    TransactionInput input = tx.getInputs().get(0);
                    Address from = input.getFromAddress();
                    BigInteger value = tx.getValueSentToMe(w);
                    System.out.println("Received " + Utils.bitcoinValueToFriendlyString(value) + " from " + from.toString());
                    // Now send the coins back!
                    Transaction sendTx = w.sendCoins(peerGroup, from, value);
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

        peerGroup.downloadBlockChain();
        System.out.println("Send coins to: " + key.toAddress(params).toString());
        System.out.println("Waiting for coins to arrive. Press Ctrl-C to quit.");
        // The PeerGroup thread keeps us alive until something kills the process.
    }
}
