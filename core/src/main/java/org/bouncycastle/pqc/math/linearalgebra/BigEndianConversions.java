package org.bouncycastle.pqc.math.linearalgebra;


/**
 * This is a utility class containing data type conversions using big-endian
 * byte order.
 *
 * @see LittleEndianConversions
 */
public final class BigEndianConversions
{

    /**
     * Default constructor (private).
     */
    private BigEndianConversions()
    {
        // empty
    }

    /**
     * Convert an integer to an octet string of length 4 according to IEEE 1363,
     * Section 5.5.3.
     *
     * @param x the integer to convert
     * @return the converted integer
     */
    public static byte[] I2OSP(int x)
    {
        byte[] result = new byte[4];
        result[0] = (byte)(x >>> 24);
        result[1] = (byte)(x >>> 16);
        result[2] = (byte)(x >>> 8);
        result[3] = (byte)x;
        return result;
    }

    /**
     * Convert an integer to an octet string according to IEEE 1363, Section
     * 5.5.3. Length checking is performed.
     *
     * @param x    the integer to convert
     * @param oLen the desired length of the octet string
     * @return an octet string of length <tt>oLen</tt> representing the
     *         integer <tt>x</tt>, or <tt>null</tt> if the integer is
     *         negative
     * @throws ArithmeticException if <tt>x</tt> can't be encoded into <tt>oLen</tt>
     * octets.
     */
    public static byte[] I2OSP(int x, int oLen)
        throws ArithmeticException
    {
        if (x < 0)
        {
            return null;
        }
        int octL = IntegerFunctions.ceilLog256(x);
        if (octL > oLen)
        {
            throw new ArithmeticException(
                "Cannot encode given integer into specified number of octets.");
        }
        byte[] result = new byte[oLen];
        for (int i = oLen - 1; i >= oLen - octL; i--)
        {
            result[i] = (byte)(x >>> (8 * (oLen - 1 - i)));
        }
        return result;
    }

    /**
     * Convert an integer to an octet string of length 4 according to IEEE 1363,
     * Section 5.5.3.
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outOff offset in output array where the result is stored
     */
    public static void I2OSP(int input, byte[] output, int outOff)
    {
        output[outOff++] = (byte)(input >>> 24);
        output[outOff++] = (byte)(input >>> 16);
        output[outOff++] = (byte)(input >>> 8);
        output[outOff] = (byte)input;
    }

    /**
     * Convert an integer to an octet string of length 8 according to IEEE 1363,
     * Section 5.5.3.
     *
     * @param input the integer to convert
     * @return the converted integer
     */
    public static byte[] I2OSP(long input)
    {
        byte[] output = new byte[8];
        output[0] = (byte)(input >>> 56);
        output[1] = (byte)(input >>> 48);
        output[2] = (byte)(input >>> 40);
        output[3] = (byte)(input >>> 32);
        output[4] = (byte)(input >>> 24);
        output[5] = (byte)(input >>> 16);
        output[6] = (byte)(input >>> 8);
        output[7] = (byte)input;
        return output;
    }

    /**
     * Convert an integer to an octet string of length 8 according to IEEE 1363,
     * Section 5.5.3.
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outOff offset in output array where the result is stored
     */
    public static void I2OSP(long input, byte[] output, int outOff)
    {
        output[outOff++] = (byte)(input >>> 56);
        output[outOff++] = (byte)(input >>> 48);
        output[outOff++] = (byte)(input >>> 40);
        output[outOff++] = (byte)(input >>> 32);
        output[outOff++] = (byte)(input >>> 24);
        output[outOff++] = (byte)(input >>> 16);
        output[outOff++] = (byte)(input >>> 8);
        output[outOff] = (byte)input;
    }

    /**
     * Convert an integer to an octet string of the specified length according
     * to IEEE 1363, Section 5.5.3. No length checking is performed (i.e., if
     * the integer cannot be encoded into <tt>length</tt> octets, it is
     * truncated).
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outOff offset in output array where the result is stored
     * @param length the length of the encoding
     */
    public static void I2OSP(int input, byte[] output, int outOff, int length)
    {
        for (int i = length - 1; i >= 0; i--)
        {
            output[outOff + i] = (byte)(input >>> (8 * (length - 1 - i)));
        }
    }

    /**
     * Convert an octet string to an integer according to IEEE 1363, Section
     * 5.5.3.
     *
     * @param input the byte array holding the octet string
     * @return an integer representing the octet string <tt>input</tt>, or
     *         <tt>0</tt> if the represented integer is negative or too large
     *         or the byte array is empty
     * @throws ArithmeticException if the length of the given octet string is larger than 4.
     */
    public static int OS2IP(byte[] input)
    {
        if (input.length > 4)
        {
            throw new ArithmeticException("invalid input length");
        }
        if (input.length == 0)
        {
            return 0;
        }
        int result = 0;
        for (int j = 0; j < input.length; j++)
        {
            result |= (input[j] & 0xff) << (8 * (input.length - 1 - j));
        }
        return result;
    }

    /**
     * Convert a byte array of length 4 beginning at <tt>offset</tt> into an
     * integer.
     *
     * @param input the byte array
     * @param inOff the offset into the byte array
     * @return the resulting integer
     */
    public static int OS2IP(byte[] input, int inOff)
    {
        int result = (input[inOff++] & 0xff) << 24;
        result |= (input[inOff++] & 0xff) << 16;
        result |= (input[inOff++] & 0xff) << 8;
        result |= input[inOff] & 0xff;
        return result;
    }

    /**
     * Convert an octet string to an integer according to IEEE 1363, Section
     * 5.5.3.
     *
     * @param input the byte array holding the octet string
     * @param inOff the offset in the input byte array where the octet string
     *              starts
     * @param inLen the length of the encoded integer
     * @return an integer representing the octet string <tt>bytes</tt>, or
     *         <tt>0</tt> if the represented integer is negative or too large
     *         or the byte array is empty
     */
    public static int OS2IP(byte[] input, int inOff, int inLen)
    {
        if ((input.length == 0) || input.length < inOff + inLen - 1)
        {
            return 0;
        }
        int result = 0;
        for (int j = 0; j < inLen; j++)
        {
            result |= (input[inOff + j] & 0xff) << (8 * (inLen - j - 1));
        }
        return result;
    }

    /**
     * Convert a byte array of length 8 beginning at <tt>inOff</tt> into a
     * long integer.
     *
     * @param input the byte array
     * @param inOff the offset into the byte array
     * @return the resulting long integer
     */
    public static long OS2LIP(byte[] input, int inOff)
    {
        long result = ((long)input[inOff++] & 0xff) << 56;
        result |= ((long)input[inOff++] & 0xff) << 48;
        result |= ((long)input[inOff++] & 0xff) << 40;
        result |= ((long)input[inOff++] & 0xff) << 32;
        result |= ((long)input[inOff++] & 0xff) << 24;
        result |= (input[inOff++] & 0xff) << 16;
        result |= (input[inOff++] & 0xff) << 8;
        result |= input[inOff] & 0xff;
        return result;
    }

    /**
     * Convert an int array into a byte array.
     *
     * @param input the int array
     * @return the converted array
     */
    public static byte[] toByteArray(final int[] input)
    {
        byte[] result = new byte[input.length << 2];
        for (int i = 0; i < input.length; i++)
        {
            I2OSP(input[i], result, i << 2);
        }
        return result;
    }

    /**
     * Convert an int array into a byte array of the specified length. No length
     * checking is performed (i.e., if the last integer cannot be encoded into
     * <tt>length % 4</tt> octets, it is truncated).
     *
     * @param input  the int array
     * @param length the length of the converted array
     * @return the converted array
     */
    public static byte[] toByteArray(final int[] input, int length)
    {
        final int intLen = input.length;
        byte[] result = new byte[length];
        int index = 0;
        for (int i = 0; i <= intLen - 2; i++, index += 4)
        {
            I2OSP(input[i], result, index);
        }
        I2OSP(input[intLen - 1], result, index, length - index);
        return result;
    }

    /**
     * Convert a byte array into an int array.
     *
     * @param input the byte array
     * @return the converted array
     */
    public static int[] toIntArray(byte[] input)
    {
        final int intLen = (input.length + 3) / 4;
        final int lastLen = input.length & 0x03;
        int[] result = new int[intLen];

        int index = 0;
        for (int i = 0; i <= intLen - 2; i++, index += 4)
        {
            result[i] = OS2IP(input, index);
        }
        if (lastLen != 0)
        {
            result[intLen - 1] = OS2IP(input, index, lastLen);
        }
        else
        {
            result[intLen - 1] = OS2IP(input, index);
        }

        return result;
    }

}
