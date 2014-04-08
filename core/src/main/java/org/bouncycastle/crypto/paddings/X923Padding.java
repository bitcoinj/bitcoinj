package org.bouncycastle.crypto.paddings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * A padder that adds X9.23 padding to a block - if a SecureRandom is
 * passed in random padding is assumed, otherwise padding with zeros is used.
 */
public class X923Padding
    implements BlockCipherPadding
{
    SecureRandom    random = null;

    /**
     * Initialise the padder.
     *
     * @param random a SecureRandom if one is available.
     */
    public void init(SecureRandom random)
        throws IllegalArgumentException
    {
        this.random = random;
    }

    /**
     * Return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public String getPaddingName()
    {
        return "X9.23";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     */
    public int addPadding(
        byte[]  in,
        int     inOff)
    {
        byte code = (byte)(in.length - inOff);

        while (inOff < in.length - 1)
        {
            if (random == null)
            {
                in[inOff] = 0;
            }
            else
            {
                in[inOff] = (byte)random.nextInt();
            }
            inOff++;
        }

        in[inOff] = code;

        return code;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padCount(byte[] in)
        throws InvalidCipherTextException
    {
        int count = in[in.length - 1] & 0xff;

        if (count > in.length)
        {
            throw new InvalidCipherTextException("pad block corrupted");
        }

        return count;
    }
}
