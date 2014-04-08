package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;

public class ElGamalParameters
    implements CipherParameters
{
    private BigInteger              g;
    private BigInteger              p;
    private int                     l;

    public ElGamalParameters(
        BigInteger  p,
        BigInteger  g)
    {
        this(p, g, 0);
    }

    public ElGamalParameters(
        BigInteger  p,
        BigInteger  g,
        int         l)
    {
        this.g = g;
        this.p = p;
        this.l = l;
    }

    public BigInteger getP()
    {
        return p;
    }

    /**
     * return the generator - g
     */
    public BigInteger getG()
    {
        return g;
    }

    /**
     * return private value limit - l
     */
    public int getL()
    {
        return l;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof ElGamalParameters))
        {
            return false;
        }

        ElGamalParameters    pm = (ElGamalParameters)obj;

        return pm.getP().equals(p) && pm.getG().equals(g) && pm.getL() == l;
    }
    
    public int hashCode()
    {
        return (getP().hashCode() ^ getG().hashCode()) + l;
    }
}
