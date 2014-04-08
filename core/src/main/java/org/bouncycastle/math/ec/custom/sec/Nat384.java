package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.Nat;

public abstract class Nat384
{
    public static void mul(int[] x, int[] y, int[] zz)
    {
        Nat192.mul(x, y, zz);
        Nat192.mul(x, 6, y, 6, zz, 12);

        int c18 = Nat192.addToEachOther(zz, 6, zz, 12);
        int c12 = c18 + Nat192.addTo(zz, 0, zz, 6, 0);
        c18 += Nat192.addTo(zz, 18, zz, 12, c12);

        int[] dx = Nat192.create(), dy = Nat192.create();
        boolean neg = Nat192.diff(x, 6, x, 0, dx, 0) != Nat192.diff(y, 6, y, 0, dy, 0);

        int[] tt = Nat192.createExt();
        Nat192.mul(dx, dy, tt);

        c18 += neg ? Nat.addTo(12, tt, 0, zz, 6) : Nat.subFrom(12, tt, 0, zz, 6);
        Nat.addWordAt(24, c18, zz, 18); 
    }

    public static void square(int[] x, int[] zz)
    {
        Nat192.square(x, zz);
        Nat192.square(x, 6, zz, 12);

        int c18 = Nat192.addToEachOther(zz, 6, zz, 12);
        int c12 = c18 + Nat192.addTo(zz, 0, zz, 6, 0);
        c18 += Nat192.addTo(zz, 18, zz, 12, c12);

        int[] dx = Nat192.create();
        Nat192.diff(x, 6, x, 0, dx, 0);

        int[] tt = Nat192.createExt();
        Nat192.square(dx, tt);

        c18 += Nat.subFrom(12, tt, 0, zz, 6);
        Nat.addWordAt(24, c18, zz, 18); 
    }
}
