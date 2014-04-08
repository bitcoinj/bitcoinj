package org.bouncycastle.crypto.tls;

/**
 * RFC 2246
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class BulkCipherAlgorithm
{
    public static final int _null = 0;
    public static final int rc4 = 1;
    public static final int rc2 = 2;
    public static final int des = 3;
    public static final int _3des = 4;
    public static final int des40 = 5;

    /*
     * RFC 4346
     */
    public static final int aes = 6;
    public static final int idea = 7;
}
