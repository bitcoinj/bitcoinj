package org.bouncycastle.math.ec.endo;

import java.math.BigInteger;

public class GLVTypeBParameters
{
    protected final BigInteger beta;
    protected final BigInteger lambda;
    protected final BigInteger[] v1, v2;
    protected final BigInteger g1, g2;
    protected final int bits;

    public GLVTypeBParameters(BigInteger beta, BigInteger lambda, BigInteger[] v1, BigInteger[] v2, BigInteger g1,
        BigInteger g2, int bits)
    {
        this.beta = beta;
        this.lambda = lambda;
        this.v1 = v1;
        this.v2 = v2;
        this.g1 = g1;
        this.g2 = g2;
        this.bits = bits;
    }

    public BigInteger getBeta()
    {
        return beta;
    }

    public BigInteger getLambda()
    {
        return lambda;
    }

    public BigInteger[] getV1()
    {
        return v1;
    }

    public BigInteger[] getV2()
    {
        return v2;
    }

    public BigInteger getG1()
    {
        return g1;
    }

    public BigInteger getG2()
    {
        return g2;
    }
    
    public int getBits()
    {
        return bits;
    }
}
