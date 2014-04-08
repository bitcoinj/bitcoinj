package org.bouncycastle.crypto;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * a holding class for public/private parameter pairs.
 */
public class AsymmetricCipherKeyPair
{
    private AsymmetricKeyParameter    publicParam;
    private AsymmetricKeyParameter    privateParam;

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
     */
    public AsymmetricCipherKeyPair(
        AsymmetricKeyParameter    publicParam,
        AsymmetricKeyParameter    privateParam)
    {
        this.publicParam = publicParam;
        this.privateParam = privateParam;
    }

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
     * @deprecated use AsymmetricKeyParameter
     */
    public AsymmetricCipherKeyPair(
        CipherParameters    publicParam,
        CipherParameters    privateParam)
    {
        this.publicParam = (AsymmetricKeyParameter)publicParam;
        this.privateParam = (AsymmetricKeyParameter)privateParam;
    }

    /**
     * return the public key parameters.
     *
     * @return the public key parameters.
     */
    public AsymmetricKeyParameter getPublic()
    {
        return publicParam;
    }

    /**
     * return the private key parameters.
     *
     * @return the private key parameters.
     */
    public AsymmetricKeyParameter getPrivate()
    {
        return privateParam;
    }
}
