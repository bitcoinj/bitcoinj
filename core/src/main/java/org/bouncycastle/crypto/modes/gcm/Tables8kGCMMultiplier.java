package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Tables8kGCMMultiplier  implements GCMMultiplier
{
    private byte[] H;
    private int[][][] M;

    public void init(byte[] H)
    {
        if (M == null)
        {
            M = new int[32][16][4];
        }
        else if (Arrays.areEqual(this.H, H))
        {
            return;
        }

        this.H = Arrays.clone(H);

        // M[0][0] is ZEROES;
        // M[1][0] is ZEROES;
        GCMUtil.asInts(H, M[1][8]);

        for (int j = 4; j >= 1; j >>= 1)
        {
            GCMUtil.multiplyP(M[1][j + j], M[1][j]);
        }

        GCMUtil.multiplyP(M[1][1], M[0][8]);

        for (int j = 4; j >= 1; j >>= 1)
        {
            GCMUtil.multiplyP(M[0][j + j], M[0][j]);
        }

        int i = 0;
        for (;;)
        {
            for (int j = 2; j < 16; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    GCMUtil.xor(M[i][j], M[i][k], M[i][j + k]);
                }
            }

            if (++i == 32)
            {
                return;
            }

            if (i > 1)
            {
                // M[i][0] is ZEROES;
                for(int j = 8; j > 0; j >>= 1)
                {
                    GCMUtil.multiplyP8(M[i - 2][j], M[i][j]);
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

        Pack.intToBigEndian(z, x, 0);
    }
}