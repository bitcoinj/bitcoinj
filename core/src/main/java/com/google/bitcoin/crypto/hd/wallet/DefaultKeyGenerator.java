package com.google.bitcoin.crypto.hd.wallet;

import com.google.bitcoin.core.ECKey;

import java.io.Serializable;
import java.util.ArrayList;

import static com.google.common.base.Preconditions.checkState;

/**
 * @author Matija Mazi <br/>
 *
 * The default WalletKeyGenerator implementation, creating random receiving keys and always returning the second
 * existing keychain key (or first if only one).
 */
public class DefaultKeyGenerator implements WalletKeyGenerator, Serializable {

    @Override
    public ECKey nextReceivingKey() {
        return new ECKey();
    }

    @Override
    public ECKey nextChangeKey(ArrayList<ECKey> keychain) {
        // For now let's just pick the second key in our keychain. In future we might want to do something else to
        // give the user better privacy here, eg in incognito mode.
        // The second key is chosen rather than the first because, by default, a wallet is created with a
        // single key. If the user imports say a blockchain.info backup they typically want change to go
        // to one of the imported keys
        checkState(keychain.size() > 0, "Can't send value without an address to use for receiving change");
        ECKey change = keychain.get(0);

        if (keychain.size() > 1) {
            change = keychain.get(1);
        }
        return change;
    }
}
