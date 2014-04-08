package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the WNAF (Window Non-Adjacent Form) multiplication
 * algorithm.
 */
public class WNafL2RMultiplier extends AbstractECMultiplier
{
    /**
     * Multiplies <code>this</code> by an integer <code>k</code> using the
     * Window NAF method.
     * @param k The integer by which <code>this</code> is multiplied.
     * @return A new <code>ECPoint</code> which equals <code>this</code>
     * multiplied by <code>k</code>.
     */
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        // Clamp the window width in the range [2, 16]
        int width = Math.max(2, Math.min(16, getWindowSize(k.bitLength())));

        WNafPreCompInfo wnafPreCompInfo = WNafUtil.precompute(p, width, true);
        ECPoint[] preComp = wnafPreCompInfo.getPreComp();
        ECPoint[] preCompNeg = wnafPreCompInfo.getPreCompNeg();

        int[] wnaf = WNafUtil.generateCompactWindowNaf(width, k);

        ECPoint R = p.getCurve().getInfinity();

        int i = wnaf.length;

        /*
         * NOTE: We try to optimize the first window using the precomputed points to substitute an
         * addition for 2 or more doublings.
         */
        if (i > 1)
        {
            int wi = wnaf[--i];
            int digit = wi >> 16, zeroes = wi & 0xFFFF;

            int n = Math.abs(digit);
            ECPoint[] table = digit < 0 ? preCompNeg : preComp;

            // Optimization can only be used for values in the lower half of the table
            if ((n << 2) < (1 << width))
            {
                int highest = LongArray.bitLengths[n];

                // TODO Get addition/doubling cost ratio from curve and compare to 'scale' to see if worth substituting?
                int scale = width - highest;
                int lowBits =  n ^ (1 << (highest - 1));

                int i1 = ((1 << (width - 1)) - 1);
                int i2 = (lowBits << scale) + 1;
                R = table[i1 >>> 1].add(table[i2 >>> 1]);

                zeroes -= scale;

//              System.out.println("Optimized: 2^" + scale + " * " + n + " = " + i1 + " + " + i2);
            }
            else
            {
                R = table[n >>> 1];
            }

            R = R.timesPow2(zeroes);
        }

        while (i > 0)
        {
            int wi = wnaf[--i];
            int digit = wi >> 16, zeroes = wi & 0xFFFF;

            int n = Math.abs(digit);
            ECPoint[] table = digit < 0 ? preCompNeg : preComp;
            ECPoint r = table[n >>> 1];

            R = R.twicePlus(r);
            R = R.timesPow2(zeroes);
        }

        return R;
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @return the window size to use
     */
    protected int getWindowSize(int bits)
    {
        return WNafUtil.getWindowSize(bits);
    }
}
