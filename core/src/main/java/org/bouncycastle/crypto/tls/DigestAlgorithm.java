package org.bouncycastle.crypto.tls;

/**
 * RFC 2246
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 *
 * @deprecated use MACAlgorithm constants instead
 */
public class DigestAlgorithm
{
    public static final int NULL = 0;
    public static final int MD5 = 1;
    public static final int SHA = 2;

    /*
     * RFC 5246
     */
    public static final int SHA256 = 3;
    public static final int SHA384 = 4;
    public static final int SHA512 = 5;
}
