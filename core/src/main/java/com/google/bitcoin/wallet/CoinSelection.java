package com.google.bitcoin.wallet;

import com.google.bitcoin.core.TransactionOutput;

import java.math.BigInteger;
import java.util.Collection;

/**
 * Represents the results of a
 * {@link com.google.bitcoin.wallet.CoinSelector#select(java.math.BigInteger, java.util.LinkedList)} operation. A
 * coin selection represents a list of spendable transaction outputs that sum together to give valueGathered.
 * Different coin selections could be produced by different coin selectors from the same input set, according
 * to their varying policies.
 */
public class CoinSelection {
    public BigInteger valueGathered;
    public Collection<TransactionOutput> gathered;

    public CoinSelection(BigInteger valueGathered, Collection<TransactionOutput> gathered) {
        this.valueGathered = valueGathered;
        this.gathered = gathered;
    }
}
