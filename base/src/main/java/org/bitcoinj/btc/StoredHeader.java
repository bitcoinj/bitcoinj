package org.bitcoinj.btc;

import java.math.BigInteger;

// Extra fields for bitcoinj StoredBlock (or equivalent)
// TODO: Do we want this?
// TODO: Refactor bitcoin StoredBlock and BlockStore to use this.
public interface StoredHeader {
    BigInteger chainWork();
    int height();
}
