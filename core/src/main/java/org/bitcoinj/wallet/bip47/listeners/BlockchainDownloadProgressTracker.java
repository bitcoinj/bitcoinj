/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47.listeners;

import org.bitcoinj.core.listeners.DownloadProgressTracker;

/**
 * Created by jimmy on 9/29/17.
 */

public abstract class BlockchainDownloadProgressTracker extends DownloadProgressTracker {
    protected boolean isDownloading = false;
    private String mCoin;

    public BlockchainDownloadProgressTracker(String coin) {
        super();

        mCoin = coin;
    }

    public String getCoin() {
        return mCoin;
    }

    public boolean isDownloading() {
        return isDownloading;
    }

    public abstract int getProgress();
}
