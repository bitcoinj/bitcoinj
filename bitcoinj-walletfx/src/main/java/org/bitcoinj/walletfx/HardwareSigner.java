package org.bitcoinj.walletfx;

import org.bitcoinj.core.Transaction;

/**
 * Work-in-progress interface for hardware signing overlays
 * TODO: Needs mechanism to pass signed transaction on to "Send" function.
 */
public interface HardwareSigner {
    void displaySigningOverlay(Transaction tx, SendMoneyController sendMoneyController);

    String getButtonText();
}
