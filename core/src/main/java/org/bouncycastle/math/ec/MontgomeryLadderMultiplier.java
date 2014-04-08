package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class MontgomeryLadderMultiplier extends AbstractECMultiplier
{
    /**
     * Montgomery ladder.
     */
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECPoint[] R = new ECPoint[]{ p.getCurve().getInfinity(), p };

        int n = k.bitLength();
        int i = n;
        while (--i >= 0)
        {
            int b = k.testBit(i) ? 1 : 0;
            int bp = 1 - b;
            R[bp] = R[bp].add(R[b]);
            R[b] = R[b].twice();
        }
        return R[0];
    }
}
