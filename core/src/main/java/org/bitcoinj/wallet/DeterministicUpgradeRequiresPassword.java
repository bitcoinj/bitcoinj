package org.bitcoinj.wallet;

/**
 * Indicates that the pre-HD random wallet is encrypted, so you should try the upgrade again after getting the
 * users password. This is required because HD wallets are upgraded from random using the private key bytes of
 * the oldest non-rotating key, in order to make the upgrade process itself deterministic.
 */
public class DeterministicUpgradeRequiresPassword extends RuntimeException {}
