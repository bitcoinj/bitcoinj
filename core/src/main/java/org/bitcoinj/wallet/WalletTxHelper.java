package org.bitcoinj.wallet;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;

import javax.annotation.Nullable;

public class WalletTxHelper {

    /**
     * <p>Depth in the chain is an approximation of how much time has elapsed since the transaction has been confirmed.
     * On average there is supposed to be a new block every 10 minutes, but the actual rate may vary. Bitcoin Core
     * considers a transaction impractical to reverse after 6 blocks, but as of EOY 2011 network
     * security is high enough that often only one block is considered enough even for high value transactions. For low
     * value transactions like songs, or other cheap items, no blocks at all may be necessary.</p>
     *
     * <p>If the transaction appears in the top block, the depth is one. If it's anything else (pending, dead, unknown)
     * the depth is zero.</p>
     */
    public static int calcDepth(@Nullable Integer appearedAtChainHeight, int lastBlockSeenHeight) {
        if (appearedAtChainHeight == null){
            return 0;
        }
        return lastBlockSeenHeight - appearedAtChainHeight + 1;
    }

    /**
     * A transaction is mature if it is either a building coinbase tx that is as deep or deeper than the required coinbase depth, or a non-coinbase tx.
     */
    public static boolean isMature(NetworkParameters params,
                                   Transaction tx,
                                   @Nullable Integer appearedAtChainHeight,
                                   int lastBlockSeenHeight) {
        if (!tx.isCoinBase())
            return true;

        return calcDepth(appearedAtChainHeight, lastBlockSeenHeight) >= params.getSpendableCoinbaseDepth();
    }

}
