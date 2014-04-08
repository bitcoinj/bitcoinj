package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * Wrapper removes exposure to the Memoable interface on an ExtendedDigest implementation.
 */
public class NonMemoableDigest
    implements ExtendedDigest
{
    private ExtendedDigest baseDigest;

    /**
     * Base constructor.
     *
     * @param baseDigest underlying digest to use.
     * @exception IllegalArgumentException if baseDigest is null
     */
    public NonMemoableDigest(
        ExtendedDigest baseDigest)
    {
        if (baseDigest == null)
        {
            throw new IllegalArgumentException("baseDigest must not be null");
        }

        this.baseDigest = baseDigest;
    }
    
    public String getAlgorithmName()
    {
        return baseDigest.getAlgorithmName();
    }

    public int getDigestSize()
    {
        return baseDigest.getDigestSize();
    }

    public void update(byte in)
    {
        baseDigest.update(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        baseDigest.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        return baseDigest.doFinal(out, outOff);
    }

    public void reset()
    {
        baseDigest.reset();
    }

    public int getByteLength()
    {
        return baseDigest.getByteLength();
    }
}
