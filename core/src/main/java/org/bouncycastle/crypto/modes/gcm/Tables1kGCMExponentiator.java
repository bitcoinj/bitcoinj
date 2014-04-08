package org.bouncycastle.crypto.modes.gcm;

import java.util.Vector;

import org.bouncycastle.util.Arrays;

public class Tables1kGCMExponentiator implements GCMExponentiator
{
    // A lookup table of the power-of-two powers of 'x'
    // - lookupPowX2[i] = x^(2^i)
    private Vector lookupPowX2;

    public void init(byte[] x)
    {
        int[] y = GCMUtil.asInts(x);
        if (lookupPowX2 != null && Arrays.areEqual(y, (int[])lookupPowX2.elementAt(0)))
        {
            return;
        }

        lookupPowX2 = new Vector(8);
        lookupPowX2.addElement(y);
    }

    public void exponentiateX(long pow, byte[] output)
    {
        int[] y = GCMUtil.oneAsInts();
        int bit = 0;
        while (pow > 0)
        {
            if ((pow & 1L) != 0)
            {
                ensureAvailable(bit);
                GCMUtil.multiply(y, (int[])lookupPowX2.elementAt(bit));
            }
            ++bit;
            pow >>>= 1;
        }

        GCMUtil.asBytes(y, output);
    }

    private void ensureAvailable(int bit)
    {
        int count = lookupPowX2.size();
        if (count <= bit)
        {
            int[] tmp = (int[])lookupPowX2.elementAt(count - 1);
            do
            {
                tmp = Arrays.clone(tmp);
                GCMUtil.multiply(tmp, tmp);
                lookupPowX2.addElement(tmp);
            }
            while (++count <= bit);
        }
    }
}
