package org.bouncycastle.crypto.params;


public class IESWithCipherParameters
    extends IESParameters
{
    private int cipherKeySize;

    /**
     * @param derivation the derivation parameter for the KDF function.
     * @param encoding the encoding parameter for the KDF function.
     * @param macKeySize the size of the MAC key (in bits).
     * @param cipherKeySize the size of the associated Cipher key (in bits).
     */
    public IESWithCipherParameters(
        byte[]  derivation,
        byte[]  encoding,
        int     macKeySize,
        int     cipherKeySize)
    {
        super(derivation, encoding, macKeySize);

        this.cipherKeySize = cipherKeySize;
    }

    public int getCipherKeySize()
    {
        return cipherKeySize;
    }
}
