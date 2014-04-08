package org.bouncycastle.math.ec.custom.sec;

public abstract class Mont256
{
    private static final long M = 0xFFFFFFFFL;

    public static int inverse32(int x)
    {
        // assert (x & 1) == 1;
        int z = x; // x.z == 1 mod 2**3
        z *= 2 - x * z; // x.z == 1 mod 2**6
        z *= 2 - x * z; // x.z == 1 mod 2**12
        z *= 2 - x * z; // x.z == 1 mod 2**24
        z *= 2 - x * z; // x.z == 1 mod 2**48
        // assert x * z == 1;
        return z;
    }

    public static void multAdd(int[] x, int[] y, int[] z, int[] m, int mInv32)
    {
        int z_8 = 0;
        long y_0 = y[0] & M;

        for (int i = 0; i < 8; ++i)
        {
            long z_0 = z[0] & M;
            long x_i = x[i] & M;

            long prod1 = x_i * y_0;
            long carry = (prod1 & M) + z_0;

            long t = ((int)carry * mInv32) & M;

            long prod2 = t * (m[0] & M);
            carry += (prod2 & M);
            // assert (int)carry == 0;
            carry = (carry >>> 32) + (prod1 >>> 32) + (prod2 >>> 32);

            for (int j = 1; j < 8; ++j)
            {
                prod1 = x_i * (y[j] & M);
                prod2 = t * (m[j] & M);

                carry += (prod1 & M) + (prod2 & M) + (z[j] & M);
                z[j - 1] = (int)carry;
                carry = (carry >>> 32) + (prod1 >>> 32) + (prod2 >>> 32);
            }

            carry += (z_8 & M);
            z[7] = (int)carry;
            z_8 = (int)(carry >>> 32);
        }

        if (z_8 != 0 || Nat256.gte(z, m))
        {
            Nat256.sub(z, m, z);
        }
    }

    public static void multAddXF(int[] x, int[] y, int[] z, int[] m)
    {
        // assert m[0] == M;

        int z_8 = 0;
        long y_0 = y[0] & M;

        for (int i = 0; i < 8; ++i)
        {
            long x_i = x[i] & M;

            long carry = x_i * y_0 + (z[0] & M);
            long t = carry & M;
            carry = (carry >>> 32) + t;

            for (int j = 1; j < 8; ++j)
            {
                long prod1 = x_i * (y[j] & M);
                long prod2 = t * (m[j] & M);

                carry += (prod1 & M) + (prod2 & M) + (z[j] & M);
                z[j - 1] = (int)carry;
                carry = (carry >>> 32) + (prod1 >>> 32) + (prod2 >>> 32);
            }

            carry += (z_8 & M);
            z[7] = (int)carry;
            z_8 = (int)(carry >>> 32);
        }

        if (z_8 != 0 || Nat256.gte(z, m))
        {
            Nat256.sub(z, m, z);
        }
    }

    public static void reduce(int[] z, int[] m, int mInv32)
    {
        for (int i = 0; i < 8; ++i)
        {
            int z_0 = z[0];

            long t = (z_0 * mInv32) & M;

            long carry = t * (m[0] & M) + (z_0 & M);
            // assert (int)carry == 0;
            carry >>>= 32;

            for (int j = 1; j < 8; ++j)
            {
                carry += t * (m[j] & M) + (z[j] & M);
                z[j - 1] = (int)carry;
                carry >>>= 32;
            }

            z[7] = (int)carry;
            // assert carry >>> 32 == 0;
        }

        if (Nat256.gte(z, m))
        {
            Nat256.sub(z, m, z);
        }
    }

    public static void reduceXF(int[] z, int[] m)
    {
        // assert m[0] == M;

        for (int i = 0; i < 8; ++i)
        {
            int z_0 = z[0];

            long t = z_0 & M;
            long carry = t;

            for (int j = 1; j < 8; ++j)
            {
                carry += t * (m[j] & M) + (z[j] & M);
                z[j - 1] = (int)carry;
                carry >>>= 32;
            }

            z[7] = (int)carry;
            // assert carry >>> 32 == 0;
        }

        if (Nat256.gte(z, m))
        {
            Nat256.sub(z, m, z);
        }
    }
}
