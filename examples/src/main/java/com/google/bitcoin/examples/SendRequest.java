package com.google.bitcoin.examples;

import java.io.File;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.Coin;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.params.TestNet3Params;

public class SendRequest {

    public static void main(String[] args) throws Exception {
        // we reuse the code from the WalletAppKit example. have a look there for explanation
        NetworkParameters params = TestNet3Params.get();
        WalletAppKit kit = new WalletAppKit(params, new File("."), "sendrequest-example");
        kit.startAsync();
        kit.awaitRunning();

        // you can get testnet coins from: http://faucet.xeno-genesis.com/
        System.out.println("send money to: " + kit.wallet().currentReceiveAddress().toString());

        // the coin class represents a bitcoin value
        // we use the parseCoin method to simple a readable string as value 
        Coin value = Coin.parseCoin("0.09");

        // to which address should we send the money to?
        // create a new Address object from the address hash
        Address to = new Address(params, "mhPoR8WQ3vNnYw2tgpRVBViZHkkydan31G");

        // there are different ways to create and publish a SendRequest. this is probably the easiest. 
        // have a look at the SendRequest class: https://bitcoinj.github.io/javadoc/0.11/com/google/bitcoin/core/Wallet.SendRequest.html

        // this might raise an Insufficent money error when you do not have enough coins to spend in your wallet. 
        // to test send money to the address that we print in line 19. You can use the http://faucet.xeno-genesis.com/ to get testnet coins. 
        Wallet.SendResult result = kit.wallet().sendCoins(kit.peerGroup(), to, value);

        System.out.println("coins sent " + result.tx.getHashAsString());

        // shutting down 
        kit.stopAsync();
        kit.awaitTerminated();
    }

}
