package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Tables64kGCMMultiplier implements GCMMultiplier
{
    private byte[] H;
    private int[][][] M;

    public void init(byte[] H)
    {
        if (M == null)
        {
            M = new int[16][256][4];
        }
        else if (Arrays.areEqual(this.H, H))
        {
            return;
        }

        this.H = Arrays.clone(H);

        // M[0][0] is ZEROES;
        GCMUtil.asInts(H, M[0][128]);

        for (int j = 64; j >= 1; j >>= 1)
        {
            GCMUtil.multiplyP(M[0][j + j], M[0][j]);
        }

        int i = 0;
        for (;;)
        {
            for (int j = 2; j < 256; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    GCMUtil.xor(M[i][j], M[i][k], M[i][j + k]);
                }
            }

            if (++i == 16)
            {
                return;
            }

            // M[i][0] is ZEROES;
            for (int j = 128; j > 0; j >>= 1)
            {
                GCMUtil.multiplyP8(M[i - 1][j], M[i][j]);
            }
        }
    }

    public void multiplyH(byte[] x)
    {
//      assert x.Length == 16;

        int[] z = new int[4];
        for (int i = 15; i >= 0; --i)
        {
//            GCMUtil.xor(z, M[i][x[i] & 0xff]);
            int[] m = M[i][x[i] & 0xff];
            z[0] ^= m[0];
            z[1] ^= m[1];
            z[2] ^= m[2];
            z[3] ^= m[3];
        }

        Pack.intToBigEndian(z, x, 0);
    }
}
