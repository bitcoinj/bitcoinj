package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * Wrapper class that reduces the output length of a particular digest to
 * only the first n bytes of the digest function.
 */
public class ShortenedDigest 
    implements ExtendedDigest
{
    private ExtendedDigest baseDigest;
    private int            length;
    
    /**
     * Base constructor.
     * 
     * @param baseDigest underlying digest to use.
     * @param length length in bytes of the output of doFinal.
     * @exception IllegalArgumentException if baseDigest is null, or length is greater than baseDigest.getDigestSize().
     */
    public ShortenedDigest(
        ExtendedDigest baseDigest,
        int            length)
    {
        if (baseDigest == null)
        {
            throw new IllegalArgumentException("baseDigest must not be null");
        }
        
        if (length > baseDigest.getDigestSize())
        {
            throw new IllegalArgumentException("baseDigest output not large enough to support length");
        }
        
        this.baseDigest = baseDigest;
        this.length = length;
    }
    
    public String getAlgorithmName()
    {
        return baseDigest.getAlgorithmName() + "(" + length * 8 + ")";
    }

    public int getDigestSize()
    {
        return length;
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
        byte[] tmp = new byte[baseDigest.getDigestSize()];
        
        baseDigest.doFinal(tmp, 0);
        
        System.arraycopy(tmp, 0, out, outOff, length);
        
        return length;
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
