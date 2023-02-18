package org.bitcoinj.base.utils;

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Monetary;
import org.bitcoinj.base.Network;

/**
 * Experimental subclass for use cases where we don't know what the network is
 */
public enum UnknownNetwork implements Network {
    DEPRECATED,          // Unknown network resulting from usage of deprecated API
    UNNECESSARY;         // Unknown network in subclass where network info is not needed

    @Override
    public String id() {
        return "deprecated";
    }

    @Override
    public String uriScheme() {
        return "deprecated";
    }

    @Override
    public boolean hasMaxMoney() {
        return false;
    }

    @Override
    public Monetary maxMoney() {
        return Coin.ZERO;
    }

    @Override
    public boolean exceedsMaxMoney(Monetary monetary) {
        return false;
    }
}
