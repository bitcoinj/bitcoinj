package org.bouncycastle.crypto.paddings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * A padder that adds Trailing-Bit-Compliment padding to a block.
 * <p>
 * This padding pads the block out with the compliment of the last bit
 * of the plain text.
 * </p>
 */
public class TBCPadding
    implements BlockCipherPadding
{
    /**
     * Initialise the padder.
     *
     * @param random - a SecureRandom if available.
     */
    public void init(SecureRandom random)
        throws IllegalArgumentException
    {
        // nothing to do.
    }

    /**
     * Return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public String getPaddingName()
    {
        return "TBC";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     * <p>
     * Note: this assumes that the last block of plain text is always 
     * passed to it inside in. i.e. if inOff is zero, indicating the
     * entire block is to be overwritten with padding the value of in
     * should be the same as the last block of plain text.
     * </p>
     */
    public int addPadding(
        byte[]  in,
        int     inOff)
    {
        int     count = in.length - inOff;
        byte    code;
        
        if (inOff > 0)
        {
            code = (byte)((in[inOff - 1] & 0x01) == 0 ? 0xff : 0x00);
        }
        else
        {
            code = (byte)((in[in.length - 1] & 0x01) == 0 ? 0xff : 0x00);
        }
            
        while (inOff < in.length)
        {
            in[inOff] = code;
            inOff++;
        }

        return count;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padCount(byte[] in)
        throws InvalidCipherTextException
    {
        byte code = in[in.length - 1];

        int index = in.length - 1;
        while (index > 0 && in[index - 1] == code)
        {
            index--;
        }

        return in.length - index;
    }
}
