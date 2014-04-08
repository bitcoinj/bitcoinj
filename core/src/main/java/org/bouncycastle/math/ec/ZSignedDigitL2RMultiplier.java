package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class ZSignedDigitL2RMultiplier extends AbstractECMultiplier
{
    /**
     * 'Zeroless' Signed Digit Left-to-Right.
     */
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECPoint addP = p.normalize(), subP = addP.negate();

        ECPoint R0 = addP;

        int n = k.bitLength();
        int s = k.getLowestSetBit();

        int i = n;
        while (--i > s)
        {
            R0 = R0.twicePlus(k.testBit(i) ? addP : subP);
        }

        R0 = R0.timesPow2(s);

        return R0;
    }
}
