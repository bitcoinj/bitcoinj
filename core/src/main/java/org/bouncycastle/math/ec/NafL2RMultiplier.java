package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the NAF (Non-Adjacent Form) multiplication algorithm (left-to-right).
 */
public class NafL2RMultiplier extends AbstractECMultiplier
{
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        int[] naf = WNafUtil.generateCompactNaf(k);

        ECPoint addP = p.normalize(), subP = addP.negate();

        ECPoint R = p.getCurve().getInfinity();

        int i = naf.length;
        while (--i >= 0)
        {
            int ni = naf[i];
            int digit = ni >> 16, zeroes = ni & 0xFFFF;

            R = R.twicePlus(digit < 0 ? subP : addP);
            R = R.timesPow2(zeroes);
        }

        return R;
    }
}
