package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class FixedPointUtil
{
    public static final String PRECOMP_NAME = "bc_fixed_point";

    public static int getCombSize(ECCurve c)
    {
        BigInteger order = c.getOrder();
        return order == null ? c.getFieldSize() + 1 : order.bitLength(); 
    }

    public static FixedPointPreCompInfo getFixedPointPreCompInfo(PreCompInfo preCompInfo)
    {
        if ((preCompInfo != null) && (preCompInfo instanceof FixedPointPreCompInfo))
        {
            return (FixedPointPreCompInfo)preCompInfo;
        }

        return new FixedPointPreCompInfo();
    }

    public static FixedPointPreCompInfo precompute(ECPoint p, int minWidth)
    {
        ECCurve c = p.getCurve();

        int n = 1 << minWidth;
        FixedPointPreCompInfo info = getFixedPointPreCompInfo(c.getPreCompInfo(p, PRECOMP_NAME));
        ECPoint[] lookupTable = info.getPreComp();

        if (lookupTable == null || lookupTable.length < n)
        {
            int bits = getCombSize(c);
            int d = (bits + minWidth - 1) / minWidth;

            ECPoint[] pow2Table = new ECPoint[minWidth];
            pow2Table[0] = p;
            for (int i = 1; i < minWidth; ++i)
            {
                pow2Table[i] = pow2Table[i - 1].timesPow2(d);
            }
    
            c.normalizeAll(pow2Table);
    
            lookupTable = new ECPoint[n];
            lookupTable[0] = c.getInfinity();
    
            for (int bit = minWidth - 1; bit >= 0; --bit)
            {
                ECPoint pow2 = pow2Table[bit];

                int step = 1 << bit;
                for (int i = step; i < n; i += (step << 1))
                {
                    lookupTable[i] = lookupTable[i - step].add(pow2);
                }
            }

            c.normalizeAll(lookupTable);

            info.setPreComp(lookupTable);
            info.setWidth(minWidth);

            c.setPreCompInfo(p, PRECOMP_NAME, info);
        }

        return info;
    }
}
