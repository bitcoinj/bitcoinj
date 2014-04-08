package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class AbstractECMultiplier implements ECMultiplier
{
    public ECPoint multiply(ECPoint p, BigInteger k)
    {
        int sign = k.signum();
        if (sign == 0 || p.isInfinity())
        {
            return p.getCurve().getInfinity();
        }

        ECPoint positive = multiplyPositive(p, k.abs());
        return sign > 0 ? positive : positive.negate();
    }

    protected abstract ECPoint multiplyPositive(ECPoint p, BigInteger k);
}
