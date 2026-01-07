package org.bitcoinj.btc;

// This is a "mix-in", either Block or BlockHeader implementations may implement it.
public interface BtcBlockHash {
    // stored, pre-computed hash
    BtcSha256 hash();
}
