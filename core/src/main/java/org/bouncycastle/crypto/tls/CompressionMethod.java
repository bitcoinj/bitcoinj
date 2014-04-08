package org.bouncycastle.crypto.tls;

/**
 * RFC 2246 6.1
 */
public class CompressionMethod
{
    public static final short _null = 0;

    /**
     * @deprecated use '_null' instead
     */
    public static final short NULL = _null;

    /*
     * RFC 3749 2
     */
    public static final short DEFLATE = 1;

    /*
     * Values from 224 decimal (0xE0) through 255 decimal (0xFF)
     * inclusive are reserved for private use.
     */
}
