package org.bitcoinj.core.listeners;

import org.bitcoinj.core.*;

import java.util.*;

/**
 * For backwards compatibility only. Implements the block chain listener interfaces. Use the more specific interfaces
 * instead.
 */
@Deprecated
public class AbstractBlockChainListener implements BlockChainListener {
    @Override
    public void notifyNewBestBlock(StoredBlock block) throws VerificationException {
    }

    @Override
    public void reorganize(StoredBlock splitPoint, List<StoredBlock> oldBlocks, List<StoredBlock> newBlocks) throws VerificationException {
    }

    @Override
    public void receiveFromBlock(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType, int relativityOffset) throws VerificationException {
    }

    @Override
    public boolean notifyTransactionIsInBlock(Sha256Hash txHash, StoredBlock block, BlockChain.NewBlockType blockType, int relativityOffset) throws VerificationException {
        return false;
    }
}
