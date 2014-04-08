package org.bouncycastle.crypto.prng;

public interface EntropySource
{
    /**
     * Return whether or not this entropy source is regarded as prediction resistant.
     *
     * @return true if it is, false otherwise.
     */
    boolean isPredictionResistant();

    /**
     * Return a byte array of entropy.
     *
     * @return  entropy bytes.
     */
    byte[] getEntropy();

    /**
     * Return the number of bits of entropy this source can produce.
     *
     * @return size in bits of the return value of getEntropy.
     */
    int entropySize();
}
