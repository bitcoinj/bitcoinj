package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class ZSignedDigitR2LMultiplier extends AbstractECMultiplier
{
    /**
     * 'Zeroless' Signed Digit Right-to-Left.
     */
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECPoint R0 = p.getCurve().getInfinity(), R1 = p;

        int n = k.bitLength();
        int s = k.getLowestSetBit();

        R1 = R1.timesPow2(s);

        int i = s;
        while (++i < n)
        {
            R0 = R0.add(k.testBit(i) ? R1 : R1.negate());
            R1 = R1.twice();
        }

        R0 = R0.add(R1);

        return R0;
    }
}
