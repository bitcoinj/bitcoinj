package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class ReferenceMultiplier extends AbstractECMultiplier
{
    /**
     * Simple shift-and-add multiplication. Serves as reference implementation
     * to verify (possibly faster) implementations in
     * {@link org.bouncycastle.math.ec.ECPoint ECPoint}.
     * 
     * @param p The point to multiply.
     * @param k The factor by which to multiply.
     * @return The result of the point multiplication <code>k * p</code>.
     */
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECPoint q = p.getCurve().getInfinity();
        int t = k.bitLength();
        if (t > 0)
        {
            if (k.testBit(0))
            {
                q = p;
            }
            for (int i = 1; i < t; i++)
            {
                p = p.twice();
                if (k.testBit(i))
                {
                    q = q.add(p);
                }
            }
        }
        return q;
    }
}
