package org.bitcoinj.net;

import org.bitcoinj.utils.CIDRUtils;

import java.net.InetAddress;

/**
 * Checks an IPv6 InetAddress represents a valid OnionCat address
 * @author danda
 * @author Oscar Guindzberg
 */
public class OnionCatAddressChecker {

    // Note:  this is borrowed/ported from btcd (written in go).

    // btcd has many more rules that are probably important and should be
    // implemented in this class, but for now we only care about onion
    // addresses for onioncat (ipv6) encoding/decoding.

    // onionCatNet defines the IPv6 address block used to support Tor.
    // bitcoind encodes a .onion address as a 16 byte number by decoding the
    // address prior to the .onion (i.e. the key hash) base32 into a ten
    // byte number. It then stores the first 6 bytes of the address as
    // 0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43.
    //
    // This is the same range used by OnionCat, which is part part of the
    // RFC4193 unique local IPv6 range.
    //
    // In summary the format is:
    // { magic 6 bytes, 10 bytes base32 decode of key hash }
    private static CIDRUtils onionCatNet = new CIDRUtils("fd87:d87e:eb43::", 48);

    // isOnionCatTor returns whether or not the passed address is in the IPv6 range
    // used by bitcoin to support Tor (fd87:d87e:eb43::/48).  Note that this range
    // is the same range used by OnionCat, which is part of the RFC4193 unique local
    // IPv6 range.
    public static boolean isOnionCatTor(InetAddress addr) {
        return onionCatNet.isInRange(addr);
    }
}
