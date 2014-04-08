package org.bouncycastle.pqc.crypto.ntru;

import java.nio.ByteBuffer;

import org.bouncycastle.crypto.Digest;

/**
 * An implementation of the deterministic pseudo-random generator in EESS section 3.7.3.1
 */
public class NTRUSignerPrng
{
    private int counter;
    private byte[] seed;
    private Digest hashAlg;

    /**
     * Constructs a new PRNG and seeds it with a byte array.
     *
     * @param seed    a seed
     * @param hashAlg the hash algorithm to use
     */
    NTRUSignerPrng(byte[] seed, Digest hashAlg)
    {
        counter = 0;
        this.seed = seed;
        this.hashAlg = hashAlg;
    }

    /**
     * Returns <code>n</code> random bytes
     *
     * @param n number of bytes to return
     * @return the next <code>n</code> random bytes
     */
    byte[] nextBytes(int n)
    {
        ByteBuffer buf = ByteBuffer.allocate(n);

        while (buf.hasRemaining())
        {
            ByteBuffer cbuf = ByteBuffer.allocate(seed.length + 4);
            cbuf.put(seed);
            cbuf.putInt(counter);
            byte[] array = cbuf.array();
            byte[] hash = new byte[hashAlg.getDigestSize()];

            hashAlg.update(array, 0, array.length);

            hashAlg.doFinal(hash, 0);

            if (buf.remaining() < hash.length)
            {
                buf.put(hash, 0, buf.remaining());
            }
            else
            {
                buf.put(hash);
            }
            counter++;
        }

        return buf.array();
    }
}