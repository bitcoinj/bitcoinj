package org.bitcoinj.core.strategies;

import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;

import java.util.List;

public interface BlockLocatorStrategy {
    /**
     * Creates a list of hashes to be used in a block locator
     * @param blockChain the block chain to be updated
     * @return list of hashes
     */
    public List<Sha256Hash> createBlockLocator(AbstractBlockChain blockChain);

    public void setNetworkParameters(NetworkParameters params);

}
