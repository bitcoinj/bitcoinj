package com.google.bitcoin.bouncycastle.crypto.modes.gcm;

import com.google.bitcoin.bouncycastle.util.Arrays;

public class BasicGCMMultiplier implements GCMMultiplier
{
    private byte[] H;

    public void init(byte[] H)
    {
        this.H = Arrays.clone(H);
    }

    public void multiplyH(byte[] x)
    {
        byte[] z = new byte[16];

        for (int i = 0; i < 16; ++i)
        {
            byte h = H[i];
            for (int j = 7; j >= 0; --j)
            {
                if ((h & (1 << j)) != 0)
                {
                    GCMUtil.xor(z, x);
                }

                boolean lsb = (x[15] & 1) != 0;
                GCMUtil.shiftRight(x);
                if (lsb)
                {
                    // R = new byte[]{ 0xe1, ... };
//                    GCMUtil.xor(v, R);
                    x[0] ^= (byte)0xe1;
                }
            }
        }

        System.arraycopy(z, 0, x, 0, 16);        
    }
}
