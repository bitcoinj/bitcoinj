/*
 * Copyright by the original author or authors.
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

package org.monacoinj.examples;

import org.monacoinj.core.*;
import org.monacoinj.kits.WalletAppKit;
import org.monacoinj.params.TestNet4Params;
import org.monacoinj.script.Script;
import org.monacoinj.wallet.Wallet;
import org.monacoinj.wallet.listeners.KeyChainEventListener;
import org.monacoinj.wallet.listeners.ScriptsChangeEventListener;
import org.monacoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.monacoinj.wallet.listeners.WalletCoinsSentEventListener;

import java.io.File;
import java.util.List;

import org.monacoinj.core.listeners.TransactionConfidenceEventListener;

/**
 * The following example shows how to use the by monacoinj provided WalletAppKit.
 * The WalletAppKit class wraps the boilerplate (Peers, BlockChain, BlockStorage, Wallet) needed to set up a new SPV monacoinj app.
 * 
 * In this example we also define a WalletEventListener class with implementors that are called when the wallet changes (for example sending/receiving money)
 */
public class Kit {

    public static void main(String[] args) {

        // First we configure the network we want to use.
        // The available options are:
        // - MainNetParams
        // - TestNet4Params
        // - RegTestParams
        // While developing your application you probably want to use the Regtest mode and run your local monacoin network. Run monacoind with the -regtest flag
        // To test you app with a real network you can use the testnet. The testnet is an alternative monacoin network that follows the same rules as main network. Coins are worth nothing and you can get coins for example from http://faucet.xeno-genesis.com/
        // 
        // For more information have a look at: https://monacoinj.github.io/testing and https://monacoin.org/en/developer-examples#testing-applications
        NetworkParameters params = TestNet4Params.get();

        // Now we initialize a new WalletAppKit. The kit handles all the boilerplate for us and is the easiest way to get everything up and running.
        // Have a look at the WalletAppKit documentation and its source to understand what's happening behind the scenes: https://github.com/monacoinj/monacoinj/blob/master/core/src/main/java/org/monacoinj/kits/WalletAppKit.java
        WalletAppKit kit = new WalletAppKit(params, new File("."), "walletappkit-example");

        // In case you want to connect with your local monacoind tell the kit to connect to localhost.
        // You must do that in reg test mode.
        //kit.connectToLocalHost();

        // Now we start the kit and sync the blockchain.
        // monacoinj is working a lot with the Google Guava libraries. The WalletAppKit extends the AbstractIdleService. Have a look at the introduction to Guava services: https://github.com/google/guava/wiki/ServiceExplained
        kit.startAsync();
        kit.awaitRunning();

        kit.wallet().addCoinsReceivedEventListener(new WalletCoinsReceivedEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                System.out.println("-----> coins resceived: " + tx.getHashAsString());
                System.out.println("received: " + tx.getValue(wallet));
            }
        });

        kit.wallet().addCoinsSentEventListener(new WalletCoinsSentEventListener() {
            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                System.out.println("coins sent");
            }
        });

        kit.wallet().addKeyChainEventListener(new KeyChainEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> keys) {
                System.out.println("new key added");
            }
        });

        kit.wallet().addScriptsChangeEventListener(new ScriptsChangeEventListener() {
            @Override
            public void onScriptsChanged(Wallet wallet, List<Script> scripts, boolean isAddingScripts) {
                System.out.println("new script added");
            }
        });

        kit.wallet().addTransactionConfidenceEventListener(new TransactionConfidenceEventListener() {
            @Override
            public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
                System.out.println("-----> confidence changed: " + tx.getHashAsString());
                TransactionConfidence confidence = tx.getConfidence();
                System.out.println("new block depth: " + confidence.getDepthInBlocks());
            }
        });

        // Ready to run. The kit syncs the blockchain and our wallet event listener gets notified when something happens.
        // To test everything we create and print a fresh receiving address. Send some coins to that address and see if everything works.
        System.out.println("send money to: " + kit.wallet().freshReceiveAddress().toString());

        // Make sure to properly shut down all the running services when you manually want to stop the kit. The WalletAppKit registers a runtime ShutdownHook so we actually do not need to worry about that when our application is stopping.
        //System.out.println("shutting down again");
        //kit.stopAsync();
        //kit.awaitTerminated();
    }

}
