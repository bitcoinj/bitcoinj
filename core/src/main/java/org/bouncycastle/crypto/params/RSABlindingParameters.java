package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

import java.math.BigInteger;

public class RSABlindingParameters
    implements CipherParameters
{
    private RSAKeyParameters publicKey;
    private BigInteger       blindingFactor;

    public RSABlindingParameters(
        RSAKeyParameters publicKey,
        BigInteger       blindingFactor)
    {
        if (publicKey instanceof RSAPrivateCrtKeyParameters)
        {
            throw new IllegalArgumentException("RSA parameters should be for a public key");
        }
        
        this.publicKey = publicKey;
        this.blindingFactor = blindingFactor;
    }

    public RSAKeyParameters getPublicKey()
    {
        return publicKey;
    }

    public BigInteger getBlindingFactor()
    {
        return blindingFactor;
    }
}
