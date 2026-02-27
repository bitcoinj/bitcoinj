package org.bitcoinj.btc;

import java.math.BigInteger;

/**
 *
 */
public interface BtcSha256 {
    // Bitcoin serialization fornat (reversed)
    byte[] serialize();
    // Returns a hex string
    String toString();
    BigInteger toBigInteger();
    byte[] toByteArray();
}
