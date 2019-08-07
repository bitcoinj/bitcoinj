package org.bitcoinj.walletfx;

import org.bitcoinj.wallet.SendRequest;

/**
 * Work-in-progress interface for hardware signing overlays
 * TODO: Needs mechanism to pass signed transaction on to "Send" function.
 */
public interface HardwareSigner {



    void displaySigningOverlay(SendRequest sendRequest, SendMoneyController sendMoneyController);

    String getButtonText();
}
