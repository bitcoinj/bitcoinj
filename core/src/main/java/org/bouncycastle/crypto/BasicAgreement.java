package org.bouncycastle.crypto;

import java.math.BigInteger;

/**
 * The basic interface that basic Diffie-Hellman implementations
 * conforms to.
 */
public interface BasicAgreement
{
    /**
     * initialise the agreement engine.
     */
    void init(CipherParameters param);

    /**
     * return the field size for the agreement algorithm in bytes.
     */
    int getFieldSize();

    /**
     * given a public key from a given party calculate the next
     * message in the agreement sequence. 
     */
    BigInteger calculateAgreement(CipherParameters pubKey);
}
