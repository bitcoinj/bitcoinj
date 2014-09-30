package org.bitcoinj.wallet;

/**
 * Indicates that an attempt was made to use HD wallet features on a wallet that was deserialized from an old,
 * pre-HD random wallet without calling upgradeToDeterministic() beforehand.
 */
public class DeterministicUpgradeRequiredException extends RuntimeException {}
