package com.google.bitcoin.crypto.hd.wallet;

import com.google.bitcoin.core.ECKey;

import java.util.ArrayList;

/**
 * @author Matija Mazi <br/>
 *
 * Used by {@link com.google.bitcoin.core.Wallet} to generate receiving and change keys.
 */
public interface WalletKeyGenerator {
    ECKey nextReceivingKey();

    ECKey nextChangeKey(ArrayList<ECKey> keychain);
}
