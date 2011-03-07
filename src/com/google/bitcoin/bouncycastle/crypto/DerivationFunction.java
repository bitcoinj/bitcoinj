package com.google.bitcoin.bouncycastle.crypto;

/**
 * base interface for general purpose byte derivation functions.
 */
public interface DerivationFunction
{
    public void init(DerivationParameters param);

    /**
     * return the message digest used as the basis for the function
     */
    public Digest getDigest();

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException;
}
