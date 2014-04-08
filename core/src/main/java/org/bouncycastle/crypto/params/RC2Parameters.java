package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class RC2Parameters
    implements CipherParameters
{
    private byte[]  key;
    private int     bits;

    public RC2Parameters(
        byte[]  key)
    {
        this(key, (key.length > 128) ? 1024 : (key.length * 8));
    }

    public RC2Parameters(
        byte[]  key,
        int     bits)
    {
        this.key = new byte[key.length];
        this.bits = bits;

        System.arraycopy(key, 0, this.key, 0, key.length);
    }

    public byte[] getKey()
    {
        return key;
    }

    public int getEffectiveKeyBits()
    {
        return bits;
    }
}
