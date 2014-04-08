package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ElGamalPrivateKeyParameters
    extends ElGamalKeyParameters
{
    private BigInteger      x;

    public ElGamalPrivateKeyParameters(
        BigInteger      x,
        ElGamalParameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof ElGamalPrivateKeyParameters))
        {
            return false;
        }

        ElGamalPrivateKeyParameters  pKey = (ElGamalPrivateKeyParameters)obj;

        if (!pKey.getX().equals(x))
        {
            return false;
        }

        return super.equals(obj);
    }
    
    public int hashCode()
    {
        return getX().hashCode();
    }
}
