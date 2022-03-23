package org.bitcoinj.wallettool;

import org.bitcoinj.core.PeerGroup;

import java.util.concurrent.CountDownLatch;
import org.bitcoinj.wallet.Wallet;

public abstract class EnumWait {

    abstract void wait2(CountDownLatch latch, Wallet wallet, PeerGroup peerGroup, WalletTool.Condition condition);

}

