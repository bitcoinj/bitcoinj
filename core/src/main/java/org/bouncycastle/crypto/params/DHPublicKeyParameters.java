package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DHPublicKeyParameters
    extends DHKeyParameters
{
    private BigInteger      y;

    public DHPublicKeyParameters(
        BigInteger      y,
        DHParameters    params)
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
        if (!(obj instanceof DHPublicKeyParameters))
        {
            return false;
        }

        DHPublicKeyParameters   other = (DHPublicKeyParameters)obj;

        return other.getY().equals(y) && super.equals(obj);
    }
}
