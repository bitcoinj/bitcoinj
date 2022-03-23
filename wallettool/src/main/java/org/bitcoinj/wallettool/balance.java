package org.bitcoinj.wallettool;

import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.wallet.Wallet;

import java.util.concurrent.CountDownLatch;

public class balance extends EnumWait
{
    void wait2(CountDownLatch latch, Wallet wallet, PeerGroup peerGroup, WalletTool.Condition condition)
    {
        if (condition.matchBitcoins(wallet.getBalance(Wallet.BalanceType.ESTIMATED))) {
            latch.countDown();
        }
        final WalletTool.WalletEventListener listener = new WalletTool.WalletEventListener(latch);
        wallet.addCoinsReceivedEventListener(listener);
        wallet.addCoinsSentEventListener(listener);
        wallet.addChangeEventListener(listener);
        wallet.addReorganizeEventListener(listener);

    }
}
