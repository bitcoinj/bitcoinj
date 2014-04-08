package org.bouncycastle.math.ec;

import java.util.Random;

import org.bouncycastle.crypto.util.Pack;

public abstract class Mod
{
    public static void invert(int[] p, int[] x, int[] z)
    {
        int len = p.length;
        if (Nat.isZero(len, x))
        {
            throw new IllegalArgumentException("'x' cannot be 0");
        }
        if (Nat.isOne(len, x))
        {
            System.arraycopy(x, 0, z, 0, len);
            return;
        }

        int[] u = Nat.copy(len, x);
        int[] a = Nat.create(len);
        a[0] = 1;
        int ac = 0;

        if ((u[0] & 1) == 0)
        {
            ac = inversionStep(p, u, len, a, ac);
        }
        if (Nat.isOne(len, u))
        {
            inversionResult(p, ac, a, z);
            return;
        }

        int[] v = Nat.copy(len, p);
        int[] b = Nat.create(len);
        int bc = 0;

        int uvLen = len;

        for (;;)
        {
            while (u[uvLen - 1] == 0 && v[uvLen - 1] == 0)
            {
                --uvLen;
            }

            if (Nat.gte(len, u, v))
            {
                Nat.sub(len, u, v, u);
//              assert (u[0] & 1) == 0;
                ac += Nat.sub(len, a, b, a) - bc;
                ac = inversionStep(p, u, uvLen, a, ac);
                if (Nat.isOne(len, u))
                {
                    inversionResult(p, ac, a, z);
                    return;
                }
            }
            else
            {
                Nat.sub(len, v, u, v);
//              assert (v[0] & 1) == 0;
                bc += Nat.sub(len, b, a, b) - ac;
                bc = inversionStep(p, v, uvLen, b, bc);
                if (Nat.isOne(len, v))
                {
                    inversionResult(p, bc, b, z);
                    return;
                }
            }
        }
    }

    public static int[] random(int[] p)
    {
        int len = p.length;
        Random rand = new Random();
        int[] s = Nat.create(len);

        int m = p[len - 1];
        m |= m >>> 1;
        m |= m >>> 2;
        m |= m >>> 4;
        m |= m >>> 8;
        m |= m >>> 16;

        do
        {
            byte[] bytes = new byte[len << 2];
            rand. nextBytes(bytes);
            Pack.bigEndianToInt(bytes, 0, s);
            s[len - 1] &= m;
        }
        while (Nat.gte(len, s, p));

        return s;
    }

    public static void subtract(int[] p, int[] x, int[] y, int[] z)
    {
        int len = p.length;
        int c = Nat.sub(len, x, y, z);
        if (c != 0)
        {
            Nat.add(len, z, p, z);
        }
    }

    private static void inversionResult(int[] p, int ac, int[] a, int[] z)
    {
        if (ac < 0)
        {
            Nat.add(p.length, a, p, z);
        }
        else
        {
            System.arraycopy(a, 0, z, 0, p.length);
        }
    }

    private static int inversionStep(int[] p, int[] u, int uLen, int[] x, int xc)
    {
        int len = p.length;
        int count = 0;
        while (u[0] == 0)
        {
            Nat.shiftDownWord(uLen, u, 0);
            count += 32;
        }

        {
            int zeroes = getTrailingZeroes(u[0]);
            if (zeroes > 0)
            {
                Nat.shiftDownBits(uLen, u, zeroes, 0);
                count += zeroes;
            }
        }

        for (int i = 0; i < count; ++i)
        {
            if ((x[0] & 1) != 0)
            {
                if (xc < 0)
                {
                    xc += Nat.add(len, x, p, x);
                }
                else
                {
                    xc += Nat.sub(len, x, p, x);
                }
            }

//            assert xc == 0 || xc == 1;
            Nat.shiftDownBit(len, x, xc);
        }
        
        return xc;
    }

    private static int getTrailingZeroes(int x)
    {
//        assert x != 0;

        int count = 0;
        while ((x & 1) == 0)
        {
            x >>>= 1;
            ++count;
        }
        return count;
    }
}
