package org.bitcoinj.btc;

import java.util.List;

public interface BtcBlock extends BtcBlockHeader {
    List<? extends BtcTransaction> transactions();
}
