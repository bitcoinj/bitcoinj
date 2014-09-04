package com.google.bitcoin.examples;

import java.util.List;

import com.google.bitcoin.core.Coin;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionConfidence;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.core.WalletEventListener;
import com.google.bitcoin.script.Script;

// have a look at the Kit.java example to see a usage of this EventListener
public class WalletListener implements WalletEventListener {

    @Override
    public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
        System.out.println("-----> coins resceived: " + tx.getHashAsString());
        System.out.println("received: " + tx.getValue(wallet));
    }

    @Override
    public void onTransactionConfidenceChanged(Wallet wallet, Transaction tx) {
        System.out.println("-----> confidence changed: " + tx.getHashAsString());
        TransactionConfidence confidence = tx.getConfidence();
        System.out.println("new block depth: " + confidence.getDepthInBlocks());
    }

    @Override
    public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
        System.out.println("coins sent");
    }

    @Override
    public void onReorganize(Wallet wallet) {
    }

    @Override
    public void onWalletChanged(Wallet wallet) {
    }

    @Override
    public void onKeysAdded(List<ECKey> keys) {
        System.out.println("new key added");
    }

    @Override
    public void onScriptsAdded(Wallet wallet, List<Script> scripts) {
        System.out.println("new script added");
    }
}
