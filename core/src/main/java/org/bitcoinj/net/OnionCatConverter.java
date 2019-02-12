package org.bitcoinj.net;

import org.bitcoinj.core.Utils;
import org.bitcoinj.utils.Base32;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;


/**
 * Converts .onion addresses to IPv6 format and viceversa.
 * @author danda
 * @author Oscar Guindzberg
 */
public class OnionCatConverter {

    /** Converts a .onion address to onioncat format
     *
     * @param hostname e.g. explorernuoc63nb.onion
     * @return e.g. fd87:d87e:eb43:25de:b744:916d:1c2f:6da1
     */
    public static byte[] onionHostToIPV6Bytes(String hostname) {
        String needle = ".onion";
        if(hostname.endsWith(needle)) {
            if (hostname.length() != 22) {
                throw new IllegalArgumentException("Invalid hostname: " + hostname);
            }
            hostname = hostname.substring(0, hostname.length() - needle.length());
        } else {
            if (hostname.length() != 16) {
                throw new IllegalArgumentException("Invalid hostname: " + hostname);
            }
        }
        byte[] prefix = new byte[] {(byte)0xfd, (byte)0x87, (byte)0xd8, (byte)0x7e, (byte)0xeb, (byte)0x43};
        byte[] onionaddr = Base32.base32Decode(hostname);
        byte[] ipBytes = new byte[prefix.length + onionaddr.length];
        System.arraycopy(prefix, 0, ipBytes, 0, prefix.length);
        System.arraycopy(onionaddr, 0, ipBytes, prefix.length, onionaddr.length);

        return ipBytes;
    }

    public static InetAddress onionHostToInetAddress(String hostname) throws UnknownHostException {
        return InetAddress.getByAddress(onionHostToIPV6Bytes(hostname));
    }


    /** Converts an IPV6 onioncat encoded address to a .onion address
     * @param bytes e.g. fd87:d87e:eb43:25de:b744:916d:1c2f:6da1
     * @return e.g. explorernuoc63nb.onion
     */
    public static String IPV6BytesToOnionHost(byte[] bytes) {
        if (bytes.length != 16) {
            throw new IllegalArgumentException("Invalid IPv6 address: " + Utils.HEX.encode(bytes));
        }
        String base32 = Base32.base32Encode( Arrays.copyOfRange(bytes, 6, 16) );
        return base32.toLowerCase() + ".onion";
    }
}
