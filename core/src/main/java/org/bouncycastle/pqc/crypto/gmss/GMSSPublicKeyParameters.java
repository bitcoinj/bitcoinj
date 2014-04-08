package org.bouncycastle.pqc.crypto.gmss;


public class GMSSPublicKeyParameters
    extends GMSSKeyParameters
{
    /**
     * The GMSS public key
     */
    private byte[] gmssPublicKey;

    /**
     * The constructor.
     *
     * @param key              a raw GMSS public key
     * @param gmssParameterSet an instance of GMSSParameterset
     */
    public GMSSPublicKeyParameters(byte[] key, GMSSParameters gmssParameterSet)
    {
        super(false, gmssParameterSet);
        this.gmssPublicKey = key;
    }

    /**
     * Returns the GMSS public key
     *
     * @return The GMSS public key
     */
    public byte[] getPublicKey()
    {
        return gmssPublicKey;
    }
}
