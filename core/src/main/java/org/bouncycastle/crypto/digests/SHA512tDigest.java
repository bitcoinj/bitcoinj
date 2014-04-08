package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.MemoableResetException;

/**
 * FIPS 180-4 implementation of SHA-512/t
 */
public class SHA512tDigest
    extends LongDigest
{
    private final int digestLength;

    private long  H1t, H2t, H3t, H4t, H5t, H6t, H7t, H8t;

    /**
     * Standard constructor
     */
    public SHA512tDigest(int bitLength)
    {
        if (bitLength >= 512)
        {
            throw new IllegalArgumentException("bitLength cannot be >= 512");
        }

        if (bitLength % 8 != 0)
        {
            throw new IllegalArgumentException("bitLength needs to be a multiple of 8");
        }

        if (bitLength == 384)
        {
            throw new IllegalArgumentException("bitLength cannot be 384 use SHA384 instead");
        }

        this.digestLength = bitLength / 8;

        tIvGenerate(digestLength * 8);

        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    public SHA512tDigest(SHA512tDigest t)
    {
        super(t);

        this.digestLength = t.digestLength;

        reset(t);
    }

    public String getAlgorithmName()
    {
        return "SHA-512/" + Integer.toString(digestLength * 8);
    }

    public int getDigestSize()
    {
        return digestLength;
    }

    public int doFinal(
        byte[]  out,
        int     outOff)
    {
        finish();

        longToBigEndian(H1, out, outOff, digestLength);
        longToBigEndian(H2, out, outOff + 8, digestLength - 8);
        longToBigEndian(H3, out, outOff + 16, digestLength - 16);
        longToBigEndian(H4, out, outOff + 24, digestLength - 24);
        longToBigEndian(H5, out, outOff + 32, digestLength - 32);
        longToBigEndian(H6, out, outOff + 40, digestLength - 40);
        longToBigEndian(H7, out, outOff + 48, digestLength - 48);
        longToBigEndian(H8, out, outOff + 56, digestLength - 56);

        reset();

        return digestLength;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        /*
         * initial hash values use the iv generation algorithm for t.
         */
        H1 = H1t;
        H2 = H2t;
        H3 = H3t;
        H4 = H4t;
        H5 = H5t;
        H6 = H6t;
        H7 = H7t;
        H8 = H8t;
    }

    private void tIvGenerate(int bitLength)
    {
        H1 = 0x6a09e667f3bcc908L ^ 0xa5a5a5a5a5a5a5a5L;
        H2 = 0xbb67ae8584caa73bL ^ 0xa5a5a5a5a5a5a5a5L;
        H3 = 0x3c6ef372fe94f82bL ^ 0xa5a5a5a5a5a5a5a5L;
        H4 = 0xa54ff53a5f1d36f1L ^ 0xa5a5a5a5a5a5a5a5L;
        H5 = 0x510e527fade682d1L ^ 0xa5a5a5a5a5a5a5a5L;
        H6 = 0x9b05688c2b3e6c1fL ^ 0xa5a5a5a5a5a5a5a5L;
        H7 = 0x1f83d9abfb41bd6bL ^ 0xa5a5a5a5a5a5a5a5L;
        H8 = 0x5be0cd19137e2179L ^ 0xa5a5a5a5a5a5a5a5L;

        update((byte)0x53);
        update((byte)0x48);
        update((byte)0x41);
        update((byte)0x2D);
        update((byte)0x35);
        update((byte)0x31);
        update((byte)0x32);
        update((byte)0x2F);

        if (bitLength > 100)
        {
            update((byte)(bitLength / 100 + 0x30));
            bitLength = bitLength % 100;
            update((byte)(bitLength / 10 + 0x30));
            bitLength = bitLength % 10;
            update((byte)(bitLength + 0x30));
        }
        else if (bitLength > 10)
        {
            update((byte)(bitLength / 10 + 0x30));
            bitLength = bitLength % 10;
            update((byte)(bitLength + 0x30));
        }
        else
        {
            update((byte)(bitLength + 0x30));
        }

        finish();

        H1t = H1;
        H2t = H2;
        H3t = H3;
        H4t = H4;
        H5t = H5;
        H6t = H6;
        H7t = H7;
        H8t = H8;
    }

    private static void longToBigEndian(long n, byte[] bs, int off, int max)
    {
        if (max > 0)
        {
            intToBigEndian((int)(n >>> 32), bs, off, max);

            if (max > 4)
            {
                intToBigEndian((int)(n & 0xffffffffL), bs, off + 4, max - 4);
            }
        }
    }

    private static void intToBigEndian(int n, byte[] bs, int off, int max)
    {
        int num = Math.min(4, max);
        while (--num >= 0)
        {
            int shift = 8 * (3 - num);
            bs[off + num] = (byte)(n >>> shift);
        }
    }

    public Memoable copy()
    {
        return new SHA512tDigest(this);
    }

    public void reset(Memoable other)
    {
        SHA512tDigest t = (SHA512tDigest)other;

        if (this.digestLength != t.digestLength)
        {
            throw new MemoableResetException("digestLength inappropriate in other");
        }

        super.copyIn(t);

        this.H1t = t.H1t;
        this.H2t = t.H2t;
        this.H3t = t.H3t;
        this.H4t = t.H4t;
        this.H5t = t.H5t;
        this.H6t = t.H6t;
        this.H7t = t.H7t;
        this.H8t = t.H8t;
    }
}
