package com.google.bitcoin.wallet;

import com.google.bitcoin.core.Transaction;

/**
 * This coin selector will select any transaction at all, regardless of where it came from or whether it was
 * confirmed yet. However immature coinbases will not be included (would be a protocol violation).
 */
public class AllowUnconfirmedCoinSelector extends DefaultCoinSelector {
    @Override protected boolean shouldSelect(Transaction tx) {
        return true;
    }

    private static AllowUnconfirmedCoinSelector instance;

    /** Returns a global static instance of the selector. */
    public static AllowUnconfirmedCoinSelector get() {
        // This doesn't have to be thread safe as the object has no state, so discarded duplicates are harmless.
        if (instance == null)
            instance = new AllowUnconfirmedCoinSelector();
        return instance;
    }
}
