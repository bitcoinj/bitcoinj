package org.bitcoinj.wallet;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;

import com.google.common.collect.ImmutableList;

/**
 * This class extends the DeterministicKeyChain allowing the possibility to use a custom account path
 * 
 * @author Giuseppe Magnotta
 *
 */
public class DeterministicKeyChainAccountPath extends DeterministicKeyChain {
	
	// By default initialize with value from superclass

	public DeterministicKeyChainAccountPath(DeterministicKey watchingKey, ImmutableList<ChildNumber> accountPath) {
        super(watchingKey, accountPath);
        
        setAccountPath(accountPath);
    }
	
}
