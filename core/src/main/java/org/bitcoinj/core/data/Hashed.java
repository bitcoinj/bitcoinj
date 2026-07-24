package org.bitcoinj.core.data;

import org.bitcoinj.base.Sha256Hash;

/**
  * This is a "mix-in", either Block or BlockHeader implementations may implement it.
 */
public interface Hashed {
    // stored, pre-computed hash
    Sha256Hash hash();
}
