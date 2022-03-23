package org.bitcoinj.wallettool;

import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.wallet.Wallet;

import java.util.concurrent.CountDownLatch;

public class block  extends EnumWait {

    void wait2(CountDownLatch latch, Wallet wallet, PeerGroup peerGroup, WalletTool.Condition condition){
        peerGroup.addBlocksDownloadedEventListener((peer, block, filteredBlock, blocksLeft) -> {
            // Check if we already ran. This can happen if a block being received triggers download of more
            // blocks, or if we receive another block whilst the peer group is shutting down.
            if (latch.getCount() == 0) return;
            latch.countDown();
        });

    }

}
