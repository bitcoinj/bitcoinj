package org.bitcoinj.wallettool;

import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.wallet.Wallet;

import java.util.concurrent.CountDownLatch;

public class wallet_tx extends EnumWait {
    void wait2(CountDownLatch latch, Wallet wallet, PeerGroup peerGroup, WalletTool.Condition condition)
    {
        wallet.addCoinsReceivedEventListener((demoWallet, tx, prevBalance, newBalance) -> {
            // Runs in a peer thread.
            System.out.println(tx.getTxId());
            latch.countDown();  // Wake up main thread.
        });
        wallet.addCoinsSentEventListener((demoWallet, tx, prevBalance, newBalance) -> {
            // Runs in a peer thread.
            System.out.println(tx.getTxId());
            latch.countDown();  // Wake up main thread.
        });

    }
}
