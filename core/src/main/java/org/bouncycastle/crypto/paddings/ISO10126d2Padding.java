package org.bouncycastle.crypto.paddings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * A padder that adds ISO10126-2 padding to a block.
 */
public class ISO10126d2Padding
    implements BlockCipherPadding
{
    SecureRandom    random;

    /**
     * Initialise the padder.
     *
     * @param random a SecureRandom if available.
     */
    public void init(SecureRandom random)
        throws IllegalArgumentException
    {
        if (random != null)
        {
            this.random = random;
        }
        else
        {
            this.random = new SecureRandom();
        }
    }

    /**
     * Return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public String getPaddingName()
    {
        return "ISO10126-2";
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

        while (inOff < (in.length - 1))
        {
            in[inOff] = (byte)random.nextInt();
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
