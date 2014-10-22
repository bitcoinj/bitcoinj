package org.bitcoinj.wallet;

/**
 * Indicates that an attempt was made to upgrade a random wallet to deterministic, but there were no non-rotating
 * random keys to use as source material for the seed. Add a non-compromised key first!
 */
public class AllRandomKeysRotating  extends RuntimeException {}
