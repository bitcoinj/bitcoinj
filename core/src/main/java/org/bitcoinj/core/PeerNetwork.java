package org.bitcoinj.core;

import org.bitcoinj.base.Network;

/**
 *
 */
public interface PeerNetwork {
    Network network();
    TxConfidenceTable txConfidenceTable();
}
