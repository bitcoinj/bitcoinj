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