// Copyright 2011 Google Inc. All Rights Reserved.

package com.google.bitcoin.examples;

import com.google.bitcoin.core.Peer;
import com.google.bitcoin.core.PeerEventListener;

import java.util.concurrent.Semaphore;

class DownloadListener implements PeerEventListener {
    private int originalBlocksLeft = -1;
    private int lastPercent = -1;
    Semaphore done = new Semaphore(0);
    
    @Override
    public void onBlocksDownloaded(Peer peer, int blocksLeft) {
        if (blocksLeft == 0) {
            System.out.println("Done downloading block chain");
            done.release();
        }
        
        if (blocksLeft <= 0)
            return;

        if (originalBlocksLeft < 0) {
            System.out.println("Downloading block chain of size " + blocksLeft + ". " +
                    (lastPercent > 1000 ? "This may take a while." : ""));
            originalBlocksLeft = blocksLeft;
        }
        
        double pct = 100.0 - (100.0 * (blocksLeft / (double) originalBlocksLeft));
        if ((int)pct != lastPercent) {
            System.out.println(String.format("Chain download %d%% done", (int) pct));
            lastPercent = (int)pct;
        }
    }
    
    public void await() throws InterruptedException {
        done.acquire();
    }
}