package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ElGamalPublicKeyParameters
    extends ElGamalKeyParameters
{
    private BigInteger      y;

    public ElGamalPublicKeyParameters(
        BigInteger      y,
        ElGamalParameters    params)
    {
        super(false, params);

        this.y = y;
    }   

    public BigInteger getY()
    {
        return y;
    }

    public int hashCode()
    {
        return y.hashCode() ^ super.hashCode();
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof ElGamalPublicKeyParameters))
        {
            return false;
        }

        ElGamalPublicKeyParameters   other = (ElGamalPublicKeyParameters)obj;

        return other.getY().equals(y) && super.equals(obj);
    }
}
