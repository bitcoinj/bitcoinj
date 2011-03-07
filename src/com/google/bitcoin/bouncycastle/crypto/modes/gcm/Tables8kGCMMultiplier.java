package com.google.bitcoin.bouncycastle.crypto.modes.gcm;

import com.google.bitcoin.bouncycastle.crypto.util.Pack;

public class Tables8kGCMMultiplier implements GCMMultiplier
{
    private final int[][][] M = new int[32][16][];

    public void init(byte[] H)
    {
        M[0][0] = new int[4];
        M[1][0] = new int[4];
        M[1][8] = GCMUtil.asInts(H);

        for (int j = 4; j >= 1; j >>= 1)
        {
            int[] tmp = new int[4];
            System.arraycopy(M[1][j + j], 0, tmp, 0, 4);

            GCMUtil.multiplyP(tmp);
            M[1][j] = tmp;
        }

        {
            int[] tmp = new int[4];
            System.arraycopy(M[1][1], 0, tmp, 0, 4);

            GCMUtil.multiplyP(tmp);
            M[0][8] = tmp;
        }

        for (int j = 4; j >= 1; j >>= 1)
        {
            int[] tmp = new int[4];
            System.arraycopy(M[0][j + j], 0, tmp, 0, 4);

            GCMUtil.multiplyP(tmp);
            M[0][j] = tmp;
        }

        int i = 0;
        for (;;)
        {
            for (int j = 2; j < 16; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    int[] tmp = new int[4];
                    System.arraycopy(M[i][j], 0, tmp, 0, 4);

                    GCMUtil.xor(tmp, M[i][k]);
                    M[i][j + k] = tmp;
                }
            }

            if (++i == 32)
            {
                return;
            }

            if (i > 1)
            {
                M[i][0] = new int[4];
                for(int j = 8; j > 0; j >>= 1)
                {
                  int[] tmp = new int[4];
                  System.arraycopy(M[i - 2][j], 0, tmp, 0, 4);

                  GCMUtil.multiplyP8(tmp);
                  M[i][j] = tmp;
                }
            }
        }
    }

    public void multiplyH(byte[] x)
    {
//      assert x.Length == 16;

        int[] z = new int[4];
        for (int i = 15; i >= 0; --i)
        {
//            GCMUtil.xor(z, M[i + i][x[i] & 0x0f]);
            int[] m = M[i + i][x[i] & 0x0f];
            z[0] ^= m[0];
            z[1] ^= m[1];
            z[2] ^= m[2];
            z[3] ^= m[3];
//            GCMUtil.xor(z, M[i + i + 1][(x[i] & 0xf0) >>> 4]);
            m = M[i + i + 1][(x[i] & 0xf0) >>> 4];
            z[0] ^= m[0];
            z[1] ^= m[1];
            z[2] ^= m[2];
            z[3] ^= m[3];
        }

        Pack.intToBigEndian(z[0], x, 0);
        Pack.intToBigEndian(z[1], x, 4);
        Pack.intToBigEndian(z[2], x, 8);
        Pack.intToBigEndian(z[3], x, 12);
    }
}
