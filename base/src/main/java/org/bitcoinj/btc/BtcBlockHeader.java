package org.bitcoinj.btc;

import java.time.Instant;

/**
 * Implementations SHOULD be immutable.
 * getHash() may be present/precomputed, computed each time or computed lazily.
 * Implement {@code BtcBlockHash#hash()} if the Block hash is precomputed and
 * returnable without computation.
 */
public interface BtcBlockHeader {
    long version();   // TODO: Should this be long or int?
    BtcSha256 prevHash();
    BtcSha256 merkleRoot();
    Instant time();
    long bits();       // TODO: Should this be long, int, or a DifficultyTarget type?
    long nonce();      // TODO: long or int?
    // This _may_ compute or compute-and-memoize the hash, there is no performance guarantee
    BtcSha256 getHash();
}
