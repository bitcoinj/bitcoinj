package org.bitcoinj.core;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.AddressFactory;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.utils.Network;

import javax.annotation.Nullable;

/**
 *
 */
public class DefaultAddressFactory implements AddressFactory {
    @Override
    public Address fromString(String addressString) {
        return fromString(addressString, (NetworkParameters) null);
    }

    @Override
    public Address fromString(String addressString, Network network) {
        return fromString(addressString, NetworkParameters.of(network));
    }

    @Deprecated
    public Address fromString(String str, @Nullable NetworkParameters params)
            throws AddressFormatException {
        try {
            return LegacyAddress.fromBase58(params, str);
        } catch (AddressFormatException.WrongNetwork x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                return SegwitAddress.fromBech32(params, str);
            } catch (AddressFormatException.WrongNetwork x2) {
                throw x;
            } catch (AddressFormatException x2) {
                throw new AddressFormatException(str);
            }
        }
    }

}
