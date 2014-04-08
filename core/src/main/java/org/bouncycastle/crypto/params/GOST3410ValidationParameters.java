package org.bouncycastle.crypto.params;

public class GOST3410ValidationParameters
{
    private int x0;
    private int c;
    private long x0L;
    private long cL;


    public GOST3410ValidationParameters(
        int  x0,
        int  c)
    {
        this.x0 = x0;
        this.c = c;
    }

    public GOST3410ValidationParameters(
        long  x0L,
        long  cL)
    {
        this.x0L = x0L;
        this.cL = cL;
    }

    public int getC()
    {
        return c;
    }

    public int getX0()
    {
        return x0;
    }

    public long getCL()
    {
        return cL;
    }

    public long getX0L()
    {
        return x0L;
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof GOST3410ValidationParameters))
        {
            return false;
        }

        GOST3410ValidationParameters  other = (GOST3410ValidationParameters)o;

        if (other.c != this.c)
        {
            return false;
        }

        if (other.x0 != this.x0)
        {
            return false;
        }

        if (other.cL != this.cL)
        {
            return false;
        }

        if (other.x0L != this.x0L)
        {
            return false;
        }

        return true;
    }

    public int hashCode()
    {
        return x0 ^ c ^ (int) x0L ^ (int)(x0L >> 32) ^ (int) cL ^ (int)(cL >> 32);
    }
}
