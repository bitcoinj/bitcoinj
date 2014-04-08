package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

public class DSAParameterGenerationParameters
{
    public static final int DIGITAL_SIGNATURE_USAGE = 1;
    public static final int KEY_ESTABLISHMENT_USAGE = 2;

    private final int l;
    private final int n;
    private final int usageIndex;
    private final int certainty;
    private final SecureRandom random;

    /**
     * Construct without a usage index, this will do a random construction of G.
     *
     * @param L desired length of prime P in bits (the effective key size).
     * @param N desired length of prime Q in bits.
     * @param certainty certainty level for prime number generation.
     * @param random the source of randomness to use.
     */
    public DSAParameterGenerationParameters(
        int L,
        int N,
        int certainty,
        SecureRandom random)
    {
        this(L, N, certainty, random, -1);
    }

    /**
     * Construct for a specific usage index - this has the effect of using verifiable canonical generation of G.
     *
     * @param L desired length of prime P in bits (the effective key size).
     * @param N desired length of prime Q in bits.
     * @param certainty certainty level for prime number generation.
     * @param random the source of randomness to use.
     * @param usageIndex a valid usage index.
     */
    public DSAParameterGenerationParameters(
        int L,
        int N,
        int certainty,
        SecureRandom random,
        int usageIndex)
    {
        this.l = L;
        this.n = N;
        this.certainty = certainty;
        this.usageIndex = usageIndex;
        this.random = random;
    }

    public int getL()
    {
        return l;
    }

    public int getN()
    {
        return n;
    }

    public int getCertainty()
    {
        return certainty;
    }

    public SecureRandom getRandom()
    {
        return random;
    }

    public int getUsageIndex()
    {
        return usageIndex;
    }
}
