package org.bouncycastle.crypto;

/**
 * base interface for general purpose Digest based byte derivation functions.
 */
public interface DigestDerivationFunction
    extends DerivationFunction
{
    /**
     * return the message digest used as the basis for the function
     */
    public Digest getDigest();
}
