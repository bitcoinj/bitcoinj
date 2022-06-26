package org.bitcoinj.core;

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.utils.Network;

/**
 * A factory interface for creating addresses
 */
public interface AddressFactory {

    /**
     * Parse a string and return an address if it is valid on any known network
     */
    Address fromString(String addressString) throws AddressFormatException;

    /**
     * Parse a string and return an address if it is valid on the specified network
     */
    Address fromString(String addressString, Network network) throws AddressFormatException;

    default Address fromKey(AddressKey key, ScriptType scriptType, Network network) {
        return key.toAddress(scriptType, network);
    }

}
