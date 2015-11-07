package org.bitcoinj.wallet;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;

/**
 * This coin selector will select any transaction at all, regardless of where it came from or whether it was
 * confirmed yet. However immature coinbases will not be included (would be a protocol violation).
 */
public class AllowUnconfirmedCoinSelector extends DefaultCoinSelector {

    public AllowUnconfirmedCoinSelector(NetworkParameters params) {
        super(params);
    }

    @Override protected boolean shouldSelect(Transaction tx) {
        return true;
    }

    private static AllowUnconfirmedCoinSelector instance;

    /** Returns a global static instance of the selector. */
    public static AllowUnconfirmedCoinSelector get(NetworkParameters params) {
        // This doesn't have to be thread safe as the object has no state, so discarded duplicates are harmless.
        if (instance == null)
            instance = new AllowUnconfirmedCoinSelector(params);
        return instance;
    }
}
