package com.google.bitcoin.examples;

import java.io.File;

import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.params.TestNet3Params;

public class Kit {

    public static void main(String[] args) {

        // configuring the network we want to use. 
        // MainNetParams - for the live/main network
        // TestNet3Params - for using the test network. An alternative bitcoin network, following the same rules as the live network but coins are worth nothing. Get coins from: http://faucet.xeno-genesis.com/
        // RegTestParams - for testing with your local bitcoin network. Run the bitcoid in regtest mode
        // for more information have a look at: 
        //   - https://bitcoinj.github.io/testing  
        //   - https://bitcoin.org/en/developer-examples#testing-applications
        NetworkParameters params = TestNet3Params.get();

        // initialize a new WalletAppKit. The WalletAppKit sets up the peers, blockchain, blockstorage and the wallet for you. 
        // it is the easiest way to get everything up and running. 
        // have a look at the source of the WalletAppKit to see what's happening behind the scenes: https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/com/google/bitcoin/kits/WalletAppKit.java
        final WalletAppKit kit = new WalletAppKit(params, new File("."), "walletappkit-example");

        //kit.connectToLocalHost(); // you want to connect to localhost when running behind a bitcoind (probably in regtest mode)

        // start everything up. sync the blockchain
        // bitcoinj is working a lot with the google guava libraries. Here the Guava Service. have a look at the intorduction: https://code.google.com/p/guava-libraries/wiki/ServiceExplained
        kit.startAsync();
        // we wait until everything is done. 
        kit.awaitRunning();

        // the best way to to observe wallet events (like when coins are received) is to implement your own WalletListener
        // have a look at the interface: https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/com/google/bitcoin/core/WalletEventListener.java
        // https://bitcoinj.github.io/javadoc/0.11/com/google/bitcoin/core/AbstractWalletEventListener.html
        WalletListener wListener = new WalletListener();
        // register the event listener. From now on the WalletListener code will run.  
        kit.wallet().addEventListener(wListener);

        // print a new receiving address. 
        // have a look a the documentation of the wallet class: 
        // send money to this address to test your code. 
        System.out.println("send money to: " + kit.wallet().freshReceiveAddress().toString());

        // shutting down
        System.out.println("shutting down again");
        kit.stopAsync();
        kit.awaitTerminated();
    }

}
