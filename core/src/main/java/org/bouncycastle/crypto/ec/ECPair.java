package org.bouncycastle.crypto.ec;

import org.bouncycastle.math.ec.ECPoint;

public class ECPair
{
    private final ECPoint x;
    private final ECPoint y;

    public ECPair(ECPoint x, ECPoint y)
    {
        this.x = x;
        this.y = y;
    }

    public ECPoint getX()
    {
        return x;
    }

    public ECPoint getY()
    {
        return y;
    }

    public boolean equals(ECPair other)
    {
        return other.getX().equals(getX()) && other.getY().equals(getY());
    }

    public boolean equals(Object other)
    {
        return other instanceof ECPair ? equals((ECPair)other) : false;
    }

    public int hashCode()
    {
        return x.hashCode() + 37 * y.hashCode();
    }
}
