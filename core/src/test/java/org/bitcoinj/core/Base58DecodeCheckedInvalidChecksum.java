package org.bitcoinj.core;

import org.junit.Test;

public class Base58DecodeCheckedInvalidChecksum {

    @Test(expected = AddressFormatException.InvalidChecksum.class)
    public void testDecodeChecked_invalidChecksum() {
        Base58.decodeChecked("4stwEBjT6FYyVW");
    }
}
