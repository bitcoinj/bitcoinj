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

package com.google.bitcoin.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DateFormat;
import java.util.Date;
import java.util.concurrent.Semaphore;

// TODO: Rename this to DownloadProgressTracker or something more appropriate.

/**
 * <p>An implementation of {@link AbstractPeerEventListener} that listens to chain download events and tracks progress
 * as a percentage. The default implementation prints progress to stdout, but you can subclass it and override the
 * progress method to update a GUI instead.</p>
 */
public class DownloadListener extends AbstractPeerEventListener {
    private static final Logger log = LoggerFactory.getLogger(DownloadListener.class);
    private int originalBlocksLeft = -1;
    private int lastPercent = 0;
    private Semaphore done = new Semaphore(0);
    private boolean caughtUp = false;

    @Override
    public void onChainDownloadStarted(Peer peer, int blocksLeft) {
        startDownload(blocksLeft);
        // Only mark this the first time, because this method can be called more than once during a chain download
        // if we switch peers during it.
        if (originalBlocksLeft == -1)
            originalBlocksLeft = blocksLeft;
        else
            log.info("Chain download switched to {}", peer);
        if (blocksLeft == 0) {
            doneDownload();
            done.release();
        }
    }

    @Override
    public void onBlocksDownloaded(Peer peer, Block block, int blocksLeft) {
        if (caughtUp)
            return;

        if (blocksLeft == 0) {
            caughtUp = true;
            doneDownload();
            done.release();
        }

        if (blocksLeft < 0 || originalBlocksLeft <= 0)
            return;

        double pct = 100.0 - (100.0 * (blocksLeft / (double) originalBlocksLeft));
        if ((int) pct != lastPercent) {
            progress(pct, blocksLeft, new Date(block.getTimeSeconds() * 1000));
            lastPercent = (int) pct;
        }
    }

    /**
     * Called when download progress is made.
     *
     * @param pct  the percentage of chain downloaded, estimated
     * @param date the date of the last block downloaded
     */
    protected void progress(double pct, int blocksSoFar, Date date) {
        log.info(String.format("Chain download %d%% done with %d blocks to go, block date %s", (int) pct,
                blocksSoFar, DateFormat.getDateTimeInstance().format(date)));
    }

    /**
     * Called when download is initiated.
     *
     * @param blocks the number of blocks to download, estimated
     */
    protected void startDownload(int blocks) {
        if (blocks > 0 && originalBlocksLeft == -1)
            log.info("Downloading block chain of size " + blocks + ". " +
                    (blocks > 1000 ? "This may take a while." : ""));

    }

    /**
     * Called when we are done downloading the block chain.
     */
    protected void doneDownload() {
    }

    /**
     * Wait for the chain to be downloaded.
     */
    public void await() throws InterruptedException {
        done.acquire();
    }
}
