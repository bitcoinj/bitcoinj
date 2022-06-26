package org.bitcoinj.base;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.utils.Network;

/**
 * A public or private key that can be used to generate an address. Currently the only
 * implementation of this interface is {@code ECKey} in `core`.
 *
 * Keys should know how to make addresses not address know how to make themselves from keys.
 * If ECKey implements `AddressKey`, this allows us to move LegacyAddress and SegwitAddress to `o.b.base`
 *
 * This approach should actually allow us to generate keys from the EC implementation in Java, I think.
 */
public interface AddressKey {
    Address toAddress(ScriptType scriptType, Network network);

    @Deprecated
    Address toAddress(ScriptType scriptType, NetworkParameters params);
}
