package org.bouncycastle.crypto;

/**
 * base interface for general purpose Mac based byte derivation functions.
 */
public interface MacDerivationFunction
    extends DerivationFunction
{
    /**
     * return the MAC used as the basis for the function
     */
    public Mac getMac();
}
