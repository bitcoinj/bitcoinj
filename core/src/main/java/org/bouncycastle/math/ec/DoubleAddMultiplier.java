package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class DoubleAddMultiplier extends AbstractECMultiplier
{
    /**
     * Joye's double-add algorithm.
     */
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECPoint[] R = new ECPoint[]{ p.getCurve().getInfinity(), p };

        int n = k.bitLength();
        for (int i = 0; i < n; ++i)
        {
            int b = k.testBit(i) ? 1 : 0;
            int bp = 1 - b;
            R[bp] = R[bp].twicePlus(R[b]);
        }

        return R[0];
    }
}
