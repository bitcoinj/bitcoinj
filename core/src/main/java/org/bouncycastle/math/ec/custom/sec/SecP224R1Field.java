package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.Nat;

public class SecP224R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^224 - 2^96 + 1
    static final int[] P = new int[]{ 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF,
        0xFFFFFFFF, 0x00000000, 0x00000002, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0x00000000,
        0x00000000, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001 };
    private static final int P6 = 0xFFFFFFFF;
    private static final int PExt13 = 0xFFFFFFFF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat224.add(x, y, z);
        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.add(14, xx, yy, zz);
        if (c != 0 || (zz[13] == PExt13 && Nat.gte(14, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(14, zz, PExtInv.length);
            }
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(7, x, z);
        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat224.fromBigInteger(x);
        if (z[6] == P6 && Nat224.gte(z, P))
        {
            Nat224.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(7, x, 0, z);
        }
        else
        {
            int c = Nat224.add(x, P, z);
            Nat.shiftDownBit(7, z, c);
        }
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat224.createExt();
        Nat224.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
    {
        int c = Nat224.mulAddTo(x, y, zz);
        if (c != 0 || (zz[13] == PExt13 && Nat.gte(14, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(14, zz, PExtInv.length);
            }
        }
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat224.isZero(x))
        {
            Nat224.zero(z);
        }
        else
        {
            Nat224.sub(P, x, z);
        }
    }

    public static void reduce(int[] xx, int[] z)
    {
        long xx10 = xx[10] & M, xx11 = xx[11] & M, xx12 = xx[12] & M, xx13 = xx[13] & M;

        final long n = 1;

        long t0 = (xx[7] & M) + xx11 - n;
        long t1 = (xx[8] & M) + xx12;
        long t2 = (xx[9] & M) + xx13;

        long cc = 0;
        cc += (xx[0] & M) - t0;
        long z0 = cc & M;
        cc >>= 32;
        cc += (xx[1] & M) - t1;
        z[1] = (int)cc;
        cc >>= 32;
        cc += (xx[2] & M) - t2;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (xx[3] & M) + t0 - xx10;
        long z3 = cc & M;
        cc >>= 32;
        cc += (xx[4] & M) + t1 - xx11;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (xx[5] & M) + t2 - xx12;
        z[5] = (int)cc;
        cc >>= 32;
        cc += (xx[6] & M) + xx10 - xx13;
        z[6] = (int)cc;
        cc >>= 32;
        cc += n;

//        assert cc >= 0;

        z3 += cc;

        z0 -= cc;
        z[0] = (int)z0;
        cc = z0 >> 32;
        if (cc != 0)
        {
            cc += (z[1] & M);
            z[1] = (int)cc;
            cc >>= 32;
            cc += (z[2] & M);
            z[2] = (int)cc;
            z3 += cc >> 32;
        }
        z[3] = (int)z3;
        cc = z3 >> 32;

//        assert cc == 0 || cc == 1;

        if ((cc != 0 && Nat.incAt(7, z, 4) != 0)
            || (z[6] == P6 && Nat224.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void reduce32(int x, int[] z)
    {
        long cc = 0;

        if (x != 0)
        {
            long xx07 = x & M;
    
            cc += (z[0] & M) - xx07;
            z[0] = (int)cc;
            cc >>= 32;
            if (cc != 0)
            {
                cc += (z[1] & M);
                z[1] = (int)cc;
                cc >>= 32;
                cc += (z[2] & M);
                z[2] = (int)cc;
                cc >>= 32;
            }
            cc += (z[3] & M) + xx07;
            z[3] = (int)cc;
            cc >>= 32;

//            assert cc == 0 || cc == 1;
        }

        if ((cc != 0 && Nat.incAt(7, z, 4) != 0)
            || (z[6] == P6 && Nat224.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat224.createExt();
        Nat224.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat224.createExt();
        Nat224.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat224.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat224.sub(x, y, z);
        if (c != 0)
        {
            subPInvFrom(z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(14, xx, yy, zz);
        if (c != 0)
        {
            if (Nat.subFrom(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.decAt(14, zz, PExtInv.length);
            }
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(7, x, 0, z);
        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    private static void addPInvTo(int[] z)
    {
        long c = (z[0] & M) - 1;
        z[0] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[1] & M);
            z[1] = (int)c;
            c >>= 32;
            c += (z[2] & M);
            z[2] = (int)c;
            c >>= 32;
        }
        c += (z[3] & M) + 1;
        z[3] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.incAt(7, z, 4);
        }
    }

    private static void subPInvFrom(int[] z)
    {
        long c = (z[0] & M) + 1;
        z[0] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[1] & M);
            z[1] = (int)c;
            c >>= 32;
            c += (z[2] & M);
            z[2] = (int)c;
            c >>= 32;
        }
        c += (z[3] & M) - 1;
        z[3] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.decAt(7, z, 4);
        }
    }
}
