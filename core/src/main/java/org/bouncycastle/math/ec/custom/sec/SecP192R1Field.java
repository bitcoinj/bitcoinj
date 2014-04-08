package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.Nat;

public class SecP192R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^192 - 2^64 - 1
    static final int[] P = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x00000001, 0x00000000, 0x00000002, 0x00000000, 0x00000001,
        0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFE,
        0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000002 };
    private static final int P5 = 0xFFFFFFFF;
    private static final int PExt11 = 0xFFFFFFFF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat192.add(x, y, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.add(12, xx, yy, zz);
        if (c != 0 || (zz[11] == PExt11 && Nat.gte(12, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(12, zz, PExtInv.length);
            }
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(6, x, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat192.fromBigInteger(x);
        if (z[5] == P5 && Nat192.gte(z, P))
        {
            Nat192.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(6, x, 0, z);
        }
        else
        {
            int c = Nat192.add(x, P, z);
            Nat.shiftDownBit(6, z, c);
        }
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat192.createExt();
        Nat192.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
    {
        int c = Nat192.mulAddTo(x, y, zz);
        if (c != 0 || (zz[11] == PExt11 && Nat.gte(12, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(12, zz, PExtInv.length);
            }
        }
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat192.isZero(x))
        {
            Nat192.zero(z);
        }
        else
        {
            Nat192.sub(P, x, z);
        }
    }

    public static void reduce(int[] xx, int[] z)
    {
        long xx06 = xx[6] & M, xx07 = xx[7] & M, xx08 = xx[8] & M;
        long xx09 = xx[9] & M, xx10 = xx[10] & M, xx11 = xx[11] & M;

        long t0 = xx06 + xx10;
        long t1 = xx07 + xx11;

        long cc = 0;
        cc += (xx[0] & M) + t0;
        int z0 = (int)cc;
        cc >>= 32;
        cc += (xx[1] & M) + t1;
        z[1] = (int)cc;
        cc >>= 32;

        t0 += xx08;
        t1 += xx09;

        cc += (xx[2] & M) + t0;
        long z2 = cc & M;
        cc >>= 32;
        cc += (xx[3] & M) + t1;
        z[3] = (int)cc;
        cc >>= 32;

        t0 -= xx06;
        t1 -= xx07;

        cc += (xx[4] & M) + t0;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (xx[5] & M) + t1;
        z[5] = (int)cc;
        cc >>= 32;

        z2 += cc;

        cc += (z0 & M);
        z[0] = (int)cc;
        cc >>= 32;
        if (cc != 0)
        {
            cc += (z[1] & M);
            z[1] = (int)cc;
            z2 += cc >> 32;
        }
        z[2] = (int)z2;
        cc = z2 >> 32;

//      assert cc == 0 || cc == 1;

        if ((cc != 0 && Nat.incAt(6, z, 3) != 0)
            || (z[5] == P5 && Nat192.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void reduce32(int x, int[] z)
    {
        long cc = 0;

        if (x != 0)
        {
            long xx06 = x & M;
    
            cc += (z[0] & M) + xx06;
            z[0] = (int)cc;
            cc >>= 32;
            if (cc != 0)
            {
                cc += (z[1] & M);
                z[1] = (int)cc;
                cc >>= 32;
            }
            cc += (z[2] & M) + xx06;
            z[2] = (int)cc;
            cc >>= 32;

//            assert cc == 0 || cc == 1;
        }

        if ((cc != 0 && Nat.incAt(6, z, 3) != 0)
            || (z[5] == P5 && Nat192.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat192.createExt();
        Nat192.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat192.createExt();
        Nat192.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat192.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat192.sub(x, y, z);
        if (c != 0)
        {
            subPInvFrom(z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(12, xx, yy, zz);
        if (c != 0)
        {
            if (Nat.subFrom(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.decAt(12, zz, PExtInv.length);
            }
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(6, x, 0, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    private static void addPInvTo(int[] z)
    {
        long c = (z[0] & M) + 1;
        z[0] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[1] & M);
            z[1] = (int)c;
            c >>= 32;
        }
        c += (z[2] & M) + 1;
        z[2] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.incAt(6, z, 3);
        }
    }

    private static void subPInvFrom(int[] z)
    {
        long c = (z[0] & M) - 1;
        z[0] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[1] & M);
            z[1] = (int)c;
            c >>= 32;
        }
        c += (z[2] & M) - 1;
        z[2] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.decAt(6, z, 3);
        }
    }
}
