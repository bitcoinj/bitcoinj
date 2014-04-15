package org.bouncycastle.crypto.tls;

public class MaxFragmentLength
{
    /*
     * RFC 3546 3.2.
     */
    public static final short pow2_9 = 1;
    public static final short pow2_10 = 2;
    public static final short pow2_11 = 3;
    public static final short pow2_12 = 4;

    public static boolean isValid(short maxFragmentLength)
    {
        return maxFragmentLength >= pow2_9 && maxFragmentLength <= pow2_12;
    }
}
