package org.bouncycastle.pqc.crypto.mceliece;

import java.math.BigInteger;

import org.bouncycastle.pqc.math.linearalgebra.BigIntUtils;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;


/**
 * Provides methods for CCA2-Secure Conversions of McEliece PKCS
 */
final class Conversions
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    
    /**
     * Default constructor (private).
     */
    private Conversions()
    {
    }

    /**
     * Encode a number between 0 and (n|t) (binomial coefficient) into a binary
     * vector of length n with weight t. The number is given as a byte array.
     * Only the first s bits are used, where s = floor[log(n|t)].
     *
     * @param n integer
     * @param t integer
     * @param m the message as a byte array
     * @return the encoded message as {@link GF2Vector}
     */
    public static GF2Vector encode(final int n, final int t, final byte[] m)
    {
        if (n < t)
        {
            throw new IllegalArgumentException("n < t");
        }

        // compute the binomial c = (n|t)
        BigInteger c = IntegerFunctions.binomial(n, t);
        // get the number encoded in m
        BigInteger i = new BigInteger(1, m);
        // compare
        if (i.compareTo(c) >= 0)
        {
            throw new IllegalArgumentException("Encoded number too large.");
        }

        GF2Vector result = new GF2Vector(n);

        int nn = n;
        int tt = t;
        for (int j = 0; j < n; j++)
        {
            c = c.multiply(BigInteger.valueOf(nn - tt)).divide(
                BigInteger.valueOf(nn));
            nn--;
            if (c.compareTo(i) <= 0)
            {
                result.setBit(j);
                i = i.subtract(c);
                tt--;
                if (nn == tt)
                {
                    c = ONE;
                }
                else
                {
                    c = (c.multiply(BigInteger.valueOf(tt + 1)))
                        .divide(BigInteger.valueOf(nn - tt));
                }
            }
        }

        return result;
    }

    /**
     * Decode a binary vector of length n and weight t into a number between 0
     * and (n|t) (binomial coefficient). The result is given as a byte array of
     * length floor[(s+7)/8], where s = floor[log(n|t)].
     *
     * @param n   integer
     * @param t   integer
     * @param vec the binary vector
     * @return the decoded vector as a byte array
     */
    public static byte[] decode(int n, int t, GF2Vector vec)
    {
        if ((vec.getLength() != n) || (vec.getHammingWeight() != t))
        {
            throw new IllegalArgumentException(
                "vector has wrong length or hamming weight");
        }
        int[] vecArray = vec.getVecArray();

        BigInteger bc = IntegerFunctions.binomial(n, t);
        BigInteger d = ZERO;
        int nn = n;
        int tt = t;
        for (int i = 0; i < n; i++)
        {
            bc = bc.multiply(BigInteger.valueOf(nn - tt)).divide(
                BigInteger.valueOf(nn));
            nn--;

            int q = i >> 5;
            int e = vecArray[q] & (1 << (i & 0x1f));
            if (e != 0)
            {
                d = d.add(bc);
                tt--;
                if (nn == tt)
                {
                    bc = ONE;
                }
                else
                {
                    bc = bc.multiply(BigInteger.valueOf(tt + 1)).divide(
                        BigInteger.valueOf(nn - tt));
                }

            }
        }

        return BigIntUtils.toMinimalByteArray(d);
    }

    /**
     * Compute a message representative of a message given as a vector of length
     * <tt>n</tt> bit and of hamming weight <tt>t</tt>. The result is a
     * byte array of length <tt>(s+7)/8</tt>, where
     * <tt>s = floor[log(n|t)]</tt>.
     *
     * @param n integer
     * @param t integer
     * @param m the message vector as a byte array
     * @return a message representative for <tt>m</tt>
     */
    public static byte[] signConversion(int n, int t, byte[] m)
    {
        if (n < t)
        {
            throw new IllegalArgumentException("n < t");
        }

        BigInteger bc = IntegerFunctions.binomial(n, t);
        // finds s = floor[log(binomial(n,t))]
        int s = bc.bitLength() - 1;
        // s = sq*8 + sr;
        int sq = s >> 3;
        int sr = s & 7;
        if (sr == 0)
        {
            sq--;
            sr = 8;
        }

        // n = nq*8+nr;
        int nq = n >> 3;
        int nr = n & 7;
        if (nr == 0)
        {
            nq--;
            nr = 8;
        }
        // take s bit from m
        byte[] data = new byte[nq + 1];
        if (m.length < data.length)
        {
            System.arraycopy(m, 0, data, 0, m.length);
            for (int i = m.length; i < data.length; i++)
            {
                data[i] = 0;
            }
        }
        else
        {
            System.arraycopy(m, 0, data, 0, nq);
            int h = (1 << nr) - 1;
            data[nq] = (byte)(h & m[nq]);
        }

        BigInteger d = ZERO;
        int nn = n;
        int tt = t;
        for (int i = 0; i < n; i++)
        {
            bc = (bc.multiply(new BigInteger(Integer.toString(nn - tt))))
                .divide(new BigInteger(Integer.toString(nn)));
            nn--;

            int q = i >>> 3;
            int r = i & 7;
            r = 1 << r;
            byte e = (byte)(r & data[q]);
            if (e != 0)
            {
                d = d.add(bc);
                tt--;
                if (nn == tt)
                {
                    bc = ONE;
                }
                else
                {
                    bc = (bc
                        .multiply(new BigInteger(Integer.toString(tt + 1))))
                        .divide(new BigInteger(Integer.toString(nn - tt)));
                }
            }
        }

        byte[] result = new byte[sq + 1];
        byte[] help = d.toByteArray();
        if (help.length < result.length)
        {
            System.arraycopy(help, 0, result, 0, help.length);
            for (int i = help.length; i < result.length; i++)
            {
                result[i] = 0;
            }
        }
        else
        {
            System.arraycopy(help, 0, result, 0, sq);
            result[sq] = (byte)(((1 << sr) - 1) & help[sq]);
        }

        return result;
    }

}
