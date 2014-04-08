package org.bouncycastle.pqc.crypto.gmss.util;

import org.bouncycastle.crypto.Digest;

/**
 * This class provides a PRNG for GMSS
 */
public class GMSSRandom
{
    /**
     * Hash function for the construction of the authentication trees
     */
    private Digest messDigestTree;

    /**
     * Constructor
     *
     * @param messDigestTree2
     */
    public GMSSRandom(Digest messDigestTree2)
    {

        this.messDigestTree = messDigestTree2;
    }

    /**
     * computes the next seed value, returns a random byte array and sets
     * outseed to the next value
     *
     * @param outseed byte array in which ((1 + SEEDin +RAND) mod 2^n) will be
     *                stored
     * @return byte array of H(SEEDin)
     */
    public byte[] nextSeed(byte[] outseed)
    {
        // RAND <-- H(SEEDin)
        byte[] rand = new byte[outseed.length];
        messDigestTree.update(outseed, 0, outseed.length);
        rand = new byte[messDigestTree.getDigestSize()];
        messDigestTree.doFinal(rand, 0);

        // SEEDout <-- (1 + SEEDin +RAND) mod 2^n
        addByteArrays(outseed, rand);
        addOne(outseed);

        // System.arraycopy(outseed, 0, outseed, 0, outseed.length);

        return rand;
    }

    private void addByteArrays(byte[] a, byte[] b)
    {

        byte overflow = 0;
        int temp;

        for (int i = 0; i < a.length; i++)
        {
            temp = (0xFF & a[i]) + (0xFF & b[i]) + overflow;
            a[i] = (byte)temp;
            overflow = (byte)(temp >> 8);
        }
    }

    private void addOne(byte[] a)
    {

        byte overflow = 1;
        int temp;

        for (int i = 0; i < a.length; i++)
        {
            temp = (0xFF & a[i]) + overflow;
            a[i] = (byte)temp;
            overflow = (byte)(temp >> 8);
        }
    }
}
