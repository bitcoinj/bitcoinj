package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class WNafUtil
{
    public static final String PRECOMP_NAME = "bc_wnaf";

    private static final int[] DEFAULT_WINDOW_SIZE_CUTOFFS = new int[]{ 13, 41, 121, 337, 897, 2305 };

    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final int[] EMPTY_INTS = new int[0];

    public static int[] generateCompactNaf(BigInteger k)
    {
        if ((k.bitLength() >>> 16) != 0)
        {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (k.signum() == 0)
        {
            return EMPTY_INTS;
        }

        BigInteger _3k = k.shiftLeft(1).add(k);

        int bits = _3k.bitLength();
        int[] naf = new int[bits >> 1];

        BigInteger diff = _3k.xor(k);

        int highBit = bits - 1, length = 0, zeroes = 0;
        for (int i = 1; i < highBit; ++i)
        {
            if (!diff.testBit(i))
            {
                ++zeroes;
                continue;
            }

            int digit  = k.testBit(i) ? -1 : 1;
            naf[length++] = (digit << 16) | zeroes;
            zeroes = 1;
            ++i;
        }

        naf[length++] = (1 << 16) | zeroes;

        if (naf.length > length)
        {
            naf = trim(naf, length);
        }

        return naf;
    }

    public static int[] generateCompactWindowNaf(int width, BigInteger k)
    {
        if (width == 2)
        {
            return generateCompactNaf(k);
        }

        if (width < 2 || width > 16)
        {
            throw new IllegalArgumentException("'width' must be in the range [2, 16]");
        }
        if ((k.bitLength() >>> 16) != 0)
        {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (k.signum() == 0)
        {
            return EMPTY_INTS;
        }

        int[] wnaf = new int[k.bitLength() / width + 1];

        // 2^width and a mask and sign bit set accordingly
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;

        boolean carry = false;
        int length = 0, pos = 0;

        while (pos <= k.bitLength())
        {
            if (k.testBit(pos) == carry)
            {
                ++pos;
                continue;
            }

            k = k.shiftRight(pos);

            int digit = k.intValue() & mask;
            if (carry)
            {
                ++digit;
            }

            carry = (digit & sign) != 0;
            if (carry)
            {
                digit -= pow2;
            }

            int zeroes = length > 0 ? pos - 1 : pos;
            wnaf[length++] = (digit << 16) | zeroes;
            pos = width;
        }

        // Reduce the WNAF array to its actual length
        if (wnaf.length > length)
        {
            wnaf = trim(wnaf, length);
        }

        return wnaf;
    }

    public static byte[] generateJSF(BigInteger g, BigInteger h)
    {
        int digits = Math.max(g.bitLength(), h.bitLength()) + 1;
        byte[] jsf = new byte[digits];

        BigInteger k0 = g, k1 = h;
        int j = 0, d0 = 0, d1 = 0;

        int offset = 0;
        while ((d0 | d1) != 0 || k0.bitLength() > offset || k1.bitLength() > offset)
        {
            int n0 = ((k0.intValue() >>> offset) + d0) & 7, n1 = ((k1.intValue() >>> offset) + d1) & 7;

            int u0 = n0 & 1;
            if (u0 != 0)
            {
                u0 -= (n0 & 2);
                if ((n0 + u0) == 4 && (n1 & 3) == 2)
                {
                    u0 = -u0;
                }
            }

            int u1 = n1 & 1;
            if (u1 != 0)
            {
                u1 -= (n1 & 2);
                if ((n1 + u1) == 4 && (n0 & 3) == 2)
                {
                    u1 = -u1;
                }
            }

            if ((d0 << 1) == 1 + u0)
            {
                d0 ^= 1;
            }
            if ((d1 << 1) == 1 + u1)
            {
                d1 ^= 1;
            }

            if (++offset == 30)
            {
                offset = 0;
                k0 = k0.shiftRight(30);
                k1 = k1.shiftRight(30);
            }

            jsf[j++] = (byte)((u0 << 4) | (u1 & 0xF));
        }

        // Reduce the JSF array to its actual length
        if (jsf.length > j)
        {
            jsf = trim(jsf, j);
        }

        return jsf;
    }

    public static byte[] generateNaf(BigInteger k)
    {
        if (k.signum() == 0)
        {
            return EMPTY_BYTES;
        }

        BigInteger _3k = k.shiftLeft(1).add(k);

        int digits = _3k.bitLength() - 1;
        byte[] naf = new byte[digits];

        BigInteger diff = _3k.xor(k);

        for (int i = 1; i < digits; ++i)
        {
            if (diff.testBit(i))
            {
                naf[i - 1] = (byte)(k.testBit(i) ? -1 : 1);
                ++i;
            }
        }

        naf[digits - 1] = 1;

        return naf;
    }

    /**
     * Computes the Window NAF (non-adjacent Form) of an integer.
     * @param width The width <code>w</code> of the Window NAF. The width is
     * defined as the minimal number <code>w</code>, such that for any
     * <code>w</code> consecutive digits in the resulting representation, at
     * most one is non-zero.
     * @param k The integer of which the Window NAF is computed.
     * @return The Window NAF of the given width, such that the following holds:
     * <code>k = &sum;<sub>i=0</sub><sup>l-1</sup> k<sub>i</sub>2<sup>i</sup>
     * </code>, where the <code>k<sub>i</sub></code> denote the elements of the
     * returned <code>byte[]</code>.
     */
    public static byte[] generateWindowNaf(int width, BigInteger k)
    {
        if (width == 2)
        {
            return generateNaf(k);
        }

        if (width < 2 || width > 8)
        {
            throw new IllegalArgumentException("'width' must be in the range [2, 8]");
        }
        if (k.signum() == 0)
        {
            return EMPTY_BYTES;
        }

        byte[] wnaf = new byte[k.bitLength() + 1];

        // 2^width and a mask and sign bit set accordingly
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;

        boolean carry = false;
        int length = 0, pos = 0;

        while (pos <= k.bitLength())
        {
            if (k.testBit(pos) == carry)
            {
                ++pos;
                continue;
            }

            k = k.shiftRight(pos);

            int digit = k.intValue() & mask;
            if (carry)
            {
                ++digit;
            }

            carry = (digit & sign) != 0;
            if (carry)
            {
                digit -= pow2;
            }

            length += (length > 0) ? pos - 1 : pos;
            wnaf[length++] = (byte)digit;
            pos = width;
        }

        // Reduce the WNAF array to its actual length
        if (wnaf.length > length)
        {
            wnaf = trim(wnaf, length);
        }
        
        return wnaf;
    }

    public static WNafPreCompInfo getWNafPreCompInfo(ECPoint p)
    {
        return getWNafPreCompInfo(p.getCurve().getPreCompInfo(p, PRECOMP_NAME));
    }

    public static WNafPreCompInfo getWNafPreCompInfo(PreCompInfo preCompInfo)
    {
        if ((preCompInfo != null) && (preCompInfo instanceof WNafPreCompInfo))
        {
            return (WNafPreCompInfo)preCompInfo;
        }

        return new WNafPreCompInfo();
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @return the window size to use
     */
    public static int getWindowSize(int bits)
    {
        return getWindowSize(bits, DEFAULT_WINDOW_SIZE_CUTOFFS);
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @param windowSizeCutoffs a monotonically increasing list of bit sizes at which to increment the window width
     * @return the window size to use
     */
    public static int getWindowSize(int bits, int[] windowSizeCutoffs)
    {
        int w = 0;
        for (; w < windowSizeCutoffs.length; ++w)
        {
            if (bits < windowSizeCutoffs[w])
            {
                break;
            }
        }
        return w + 2;
    }

    public static ECPoint mapPointWithPrecomp(ECPoint p, int width, boolean includeNegated,
        ECPointMap pointMap)
    {
        ECCurve c = p.getCurve();
        WNafPreCompInfo wnafPreCompP = precompute(p, width, includeNegated);

        ECPoint q = pointMap.map(p);
        WNafPreCompInfo wnafPreCompQ = getWNafPreCompInfo(c.getPreCompInfo(q, PRECOMP_NAME));

        ECPoint twiceP = wnafPreCompP.getTwice();
        if (twiceP != null)
        {
            ECPoint twiceQ = pointMap.map(twiceP);
            wnafPreCompQ.setTwice(twiceQ);
        }

        ECPoint[] preCompP = wnafPreCompP.getPreComp();
        ECPoint[] preCompQ = new ECPoint[preCompP.length];
        for (int i = 0; i < preCompP.length; ++i)
        {
            preCompQ[i] = pointMap.map(preCompP[i]);
        }
        wnafPreCompQ.setPreComp(preCompQ);

        if (includeNegated)
        {
            ECPoint[] preCompNegQ = new ECPoint[preCompQ.length];
            for (int i = 0; i < preCompNegQ.length; ++i)
            {
                preCompNegQ[i] = preCompQ[i].negate();
            }
            wnafPreCompQ.setPreCompNeg(preCompNegQ);
        }

        c.setPreCompInfo(q, PRECOMP_NAME, wnafPreCompQ);

        return q;
    }

    public static WNafPreCompInfo precompute(ECPoint p, int width, boolean includeNegated)
    {
        ECCurve c = p.getCurve();
        WNafPreCompInfo wnafPreCompInfo = getWNafPreCompInfo(c.getPreCompInfo(p, PRECOMP_NAME));

        ECPoint[] preComp = wnafPreCompInfo.getPreComp();
        if (preComp == null)
        {
            preComp = new ECPoint[]{ p };
        }

        int preCompLen = preComp.length;
        int reqPreCompLen = 1 << Math.max(0, width - 2);

        if (preCompLen < reqPreCompLen)
        {
            preComp = resizeTable(preComp, reqPreCompLen);
            if (reqPreCompLen == 2)
            {
                preComp[1] = preComp[0].threeTimes();
            }
            else
            {
                ECPoint twiceP = wnafPreCompInfo.getTwice();
                if (twiceP == null)
                {
                    twiceP = preComp[0].twice();
                    wnafPreCompInfo.setTwice(twiceP);
                }

                for (int i = preCompLen; i < reqPreCompLen; i++)
                {
                    /*
                     * Compute the new ECPoints for the precomputation array. The values 1, 3, 5, ...,
                     * 2^(width-1)-1 times p are computed
                     */
                    preComp[i] = twiceP.add(preComp[i - 1]);
                }
            }

            /*
             * Having oft-used operands in affine form makes operations faster.
             */
            c.normalizeAll(preComp);
        }

        wnafPreCompInfo.setPreComp(preComp);

        if (includeNegated)
        {
            ECPoint[] preCompNeg = wnafPreCompInfo.getPreCompNeg();
            
            int pos;
            if (preCompNeg == null)
            {
                pos = 0;
                preCompNeg = new ECPoint[reqPreCompLen]; 
            }
            else
            {
                pos = preCompNeg.length;
                if (pos < reqPreCompLen)
                {
                    preCompNeg = resizeTable(preCompNeg, reqPreCompLen);
                }
            }

            while (pos < reqPreCompLen)
            {
                preCompNeg[pos] = preComp[pos].negate();
                ++pos;
            }

            wnafPreCompInfo.setPreCompNeg(preCompNeg);
        }

        c.setPreCompInfo(p, PRECOMP_NAME, wnafPreCompInfo);

        return wnafPreCompInfo;
    }

    private static byte[] trim(byte[] a, int length)
    {
        byte[] result = new byte[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    private static int[] trim(int[] a, int length)
    {
        int[] result = new int[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    private static ECPoint[] resizeTable(ECPoint[] a, int length)
    {
        ECPoint[] result = new ECPoint[length];
        System.arraycopy(a, 0, result, 0, a.length);
        return result;
    }
}
