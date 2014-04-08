package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.Nat;

public class SecP192K1Field
{
    // 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
    static final int[] P = new int[]{ 0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x013C4FD1, 0x00002392, 0x00000001, 0x00000000, 0x00000000,
        0x00000000, 0xFFFFDC6E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFEC3B02F, 0xFFFFDC6D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0x00002391, 0x00000002 };
    private static final int P5 = 0xFFFFFFFF;
    private static final int PExt11 = 0xFFFFFFFF;
    private static final int PInv33 = 0x11C9;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat192.add(x, y, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
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
            Nat.add33To(6, PInv33, z);
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
        long cc = Nat192.mul33Add(PInv33, xx, 6, xx, 0, z, 0);
        int c = Nat192.mul33DWordAdd(PInv33, cc, z, 0);

        // assert c == 0L || c == 1L;

        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
        }
    }

    public static void reduce32(int x, int[] z)
    {
        if ((x != 0 && Nat192.mul33WordAdd(PInv33, x, z, 0) != 0)
            || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
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
            Nat.sub33From(6, PInv33, z);
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
            Nat.add33To(6, PInv33, z);
        }
    }
}
