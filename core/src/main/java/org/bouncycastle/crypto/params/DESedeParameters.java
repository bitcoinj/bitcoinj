package org.bouncycastle.crypto.params;

public class DESedeParameters
    extends DESParameters
{
    /*
     * DES-EDE Key length in bytes.
     */
    static public final int DES_EDE_KEY_LENGTH = 24;

    public DESedeParameters(
        byte[]  key)
    {
        super(key);

        if (isWeakKey(key, 0, key.length))
        {
            throw new IllegalArgumentException("attempt to create weak DESede key");
        }
    }

    /**
     * return true if the passed in key is a DES-EDE weak key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     * @param length number of bytes making up the key
     */
    public static boolean isWeakKey(
        byte[]  key,
        int     offset,
        int     length)
    {
        for (int i = offset; i < length; i += DES_KEY_LENGTH)
        {
            if (DESParameters.isWeakKey(key, i))
            {
                return true;
            }
        }

        return false;
    }

    /**
     * return true if the passed in key is a DES-EDE weak key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     */
    public static boolean isWeakKey(
        byte[]  key,
        int     offset)
    {
        return isWeakKey(key, offset, key.length - offset);
    }
}
