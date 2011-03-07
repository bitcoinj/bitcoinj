package com.google.bitcoin.bouncycastle.crypto.generators;

import com.google.bitcoin.bouncycastle.crypto.DataLengthException;
import com.google.bitcoin.bouncycastle.crypto.DerivationFunction;
import com.google.bitcoin.bouncycastle.crypto.DerivationParameters;
import com.google.bitcoin.bouncycastle.crypto.Digest;
import com.google.bitcoin.bouncycastle.crypto.params.ISO18033KDFParameters;
import com.google.bitcoin.bouncycastle.crypto.params.KDFParameters;

/**
 * Basic KDF generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033
 * <br>
 * This implementation is based on ISO 18033/P1363a.
 */
public class BaseKDFBytesGenerator
    implements DerivationFunction
{
    private int     counterStart;
    private Digest  digest;
    private byte[]  shared;
    private byte[]  iv;

    /**
     * Construct a KDF Parameters generator.
     * <p>
     * @param counterStart value of counter.
     * @param digest the digest to be used as the source of derived keys.
     */
    protected BaseKDFBytesGenerator(
        int     counterStart,
        Digest  digest)
    {
        this.counterStart = counterStart;
        this.digest = digest;
    }

    public void init(
        DerivationParameters    param)
    {
        if (param instanceof KDFParameters)
        {
            KDFParameters   p = (KDFParameters)param;

            shared = p.getSharedSecret();
            iv = p.getIV();
        }
        else if (param instanceof ISO18033KDFParameters)
        {
            ISO18033KDFParameters p = (ISO18033KDFParameters)param;
            
            shared = p.getSeed();
            iv = null;
        }
        else
        {
            throw new IllegalArgumentException("KDF parameters required for KDF2Generator");
        }
    }

    /**
     * return the underlying digest.
     */
    public Digest getDigest()
    {
        return digest;
    }

    /**
     * fill len bytes of the output buffer with bytes generated from
     * the derivation function.
     *
     * @throws IllegalArgumentException if the size of the request will cause an overflow.
     * @throws DataLengthException if the out buffer is too small.
     */
    public int generateBytes(
        byte[]  out,
        int     outOff,
        int     len)
        throws DataLengthException, IllegalArgumentException
    {
        if ((out.length - len) < outOff)
        {
            throw new DataLengthException("output buffer too small");
        }

        long    oBytes = len;
        int     outLen = digest.getDigestSize(); 

        //
        // this is at odds with the standard implementation, the
        // maximum value should be hBits * (2^32 - 1) where hBits
        // is the digest output size in bits. We can't have an
        // array with a long index at the moment...
        //
        if (oBytes > ((2L << 32) - 1))
        {
            throw new IllegalArgumentException("Output length too large");
        }

        int cThreshold = (int)((oBytes + outLen - 1) / outLen);

        byte[] dig = null;

        dig = new byte[digest.getDigestSize()];

        int counter = counterStart;
        
        for (int i = 0; i < cThreshold; i++)
        {
            digest.update(shared, 0, shared.length);

            digest.update((byte)(counter >> 24));
            digest.update((byte)(counter >> 16));
            digest.update((byte)(counter >> 8));
            digest.update((byte)counter);
            
            if (iv != null)
            {
                digest.update(iv, 0, iv.length);
            }

            digest.doFinal(dig, 0);

            if (len > outLen)
            {
                System.arraycopy(dig, 0, out, outOff, outLen);
                outOff += outLen;
                len -= outLen;
            }
            else
            {
                System.arraycopy(dig, 0, out, outOff, len);
            }
            
            counter++;
        }
    
        digest.reset();

        return len;
    }
}
