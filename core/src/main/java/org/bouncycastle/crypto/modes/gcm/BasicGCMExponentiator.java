package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Arrays;

public class BasicGCMExponentiator implements GCMExponentiator
{
    private int[] x;

    public void init(byte[] x)
    {
        this.x = GCMUtil.asInts(x);
    }

    public void exponentiateX(long pow, byte[] output)
    {
        // Initial value is little-endian 1
        int[] y = GCMUtil.oneAsInts();

        if (pow > 0)
        {
            int[] powX = Arrays.clone(x);
            do
            {
                if ((pow & 1L) != 0)
                {
                    GCMUtil.multiply(y, powX);
                }
                GCMUtil.multiply(powX, powX);
                pow >>>= 1;
            }
            while (pow > 0);
        }

        GCMUtil.asBytes(y, output);
    }
}
