package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the NAF (Non-Adjacent Form) multiplication algorithm (right-to-left).
 */
public class NafR2LMultiplier extends AbstractECMultiplier
{
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        int[] naf = WNafUtil.generateCompactNaf(k);

        ECPoint R0 = p.getCurve().getInfinity(), R1 = p;

        int zeroes = 0;
        for (int i = 0; i < naf.length; ++i)
        {
            int ni = naf[i];
            int digit = ni >> 16;
            zeroes += ni & 0xFFFF;

            R1 = R1.timesPow2(zeroes);
            R0 = R0.add(digit < 0 ? R1.negate() : R1);

            zeroes = 1;
        }

        return R0;
    }
}
