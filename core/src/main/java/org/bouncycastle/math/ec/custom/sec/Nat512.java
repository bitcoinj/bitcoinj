package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.Nat;

public abstract class Nat512
{
    public static void mul(int[] x, int[] y, int[] zz)
    {
        Nat256.mul(x, y, zz);
        Nat256.mul(x, 8, y, 8, zz, 16);

        int c24 = Nat256.addToEachOther(zz, 8, zz, 16);
        int c16 = c24 + Nat256.addTo(zz, 0, zz, 8, 0);
        c24 += Nat256.addTo(zz, 24, zz, 16, c16);

        int[] dx = Nat256.create(), dy = Nat256.create();
        boolean neg = Nat256.diff(x, 8, x, 0, dx, 0) != Nat256.diff(y, 8, y, 0, dy, 0);

        int[] tt = Nat256.createExt();
        Nat256.mul(dx, dy, tt);

        c24 += neg ? Nat.addTo(16, tt, 0, zz, 8) : Nat.subFrom(16, tt, 0, zz, 8);
        Nat.addWordAt(32, c24, zz, 24); 
    }

    public static void square(int[] x, int[] zz)
    {
        Nat256.square(x, zz);
        Nat256.square(x, 8, zz, 16);

        int c24 = Nat256.addToEachOther(zz, 8, zz, 16);
        int c16 = c24 + Nat256.addTo(zz, 0, zz, 8, 0);
        c24 += Nat256.addTo(zz, 24, zz, 16, c16);

        int[] dx = Nat256.create();
        Nat256.diff(x, 8, x, 0, dx, 0);

        int[] tt = Nat256.createExt();
        Nat256.square(dx, tt);

        c24 += Nat.subFrom(16, tt, 0, zz, 8);
        Nat.addWordAt(32, c24, zz, 24); 
    }
}
