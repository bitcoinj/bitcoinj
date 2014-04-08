package org.bouncycastle.pqc.math.linearalgebra;

/**
 * This is a utility class containing data type conversions using little-endian
 * byte order.
 *
 * @see BigEndianConversions
 */
public final class LittleEndianConversions
{

    /**
     * Default constructor (private).
     */
    private LittleEndianConversions()
    {
        // empty
    }

    /**
     * Convert an octet string of length 4 to an integer. No length checking is
     * performed.
     *
     * @param input the byte array holding the octet string
     * @return an integer representing the octet string <tt>input</tt>
     * @throws ArithmeticException if the length of the given octet string is larger than 4.
     */
    public static int OS2IP(byte[] input)
    {
        return ((input[0] & 0xff)) | ((input[1] & 0xff) << 8)
            | ((input[2] & 0xff) << 16) | ((input[3] & 0xff)) << 24;
    }

    /**
     * Convert an byte array of length 4 beginning at <tt>offset</tt> into an
     * integer.
     *
     * @param input the byte array
     * @param inOff the offset into the byte array
     * @return the resulting integer
     */
    public static int OS2IP(byte[] input, int inOff)
    {
        int result = input[inOff++] & 0xff;
        result |= (input[inOff++] & 0xff) << 8;
        result |= (input[inOff++] & 0xff) << 16;
        result |= (input[inOff] & 0xff) << 24;
        return result;
    }

    /**
     * Convert a byte array of the given length beginning at <tt>offset</tt>
     * into an integer.
     *
     * @param input the byte array
     * @param inOff the offset into the byte array
     * @param inLen the length of the encoding
     * @return the resulting integer
     */
    public static int OS2IP(byte[] input, int inOff, int inLen)
    {
        int result = 0;
        for (int i = inLen - 1; i >= 0; i--)
        {
            result |= (input[inOff + i] & 0xff) << (8 * i);
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
        long result = input[inOff++] & 0xff;
        result |= (input[inOff++] & 0xff) << 8;
        result |= (input[inOff++] & 0xff) << 16;
        result |= ((long)input[inOff++] & 0xff) << 24;
        result |= ((long)input[inOff++] & 0xff) << 32;
        result |= ((long)input[inOff++] & 0xff) << 40;
        result |= ((long)input[inOff++] & 0xff) << 48;
        result |= ((long)input[inOff++] & 0xff) << 56;
        return result;
    }

    /**
     * Convert an integer to an octet string of length 4.
     *
     * @param x the integer to convert
     * @return the converted integer
     */
    public static byte[] I2OSP(int x)
    {
        byte[] result = new byte[4];
        result[0] = (byte)x;
        result[1] = (byte)(x >>> 8);
        result[2] = (byte)(x >>> 16);
        result[3] = (byte)(x >>> 24);
        return result;
    }

    /**
     * Convert an integer into a byte array beginning at the specified offset.
     *
     * @param value  the integer to convert
     * @param output the byte array to hold the result
     * @param outOff the integer offset into the byte array
     */
    public static void I2OSP(int value, byte[] output, int outOff)
    {
        output[outOff++] = (byte)value;
        output[outOff++] = (byte)(value >>> 8);
        output[outOff++] = (byte)(value >>> 16);
        output[outOff++] = (byte)(value >>> 24);
    }

    /**
     * Convert an integer to a byte array beginning at the specified offset. No
     * length checking is performed (i.e., if the integer cannot be encoded with
     * <tt>length</tt> octets, it is truncated).
     *
     * @param value  the integer to convert
     * @param output the byte array to hold the result
     * @param outOff the integer offset into the byte array
     * @param outLen the length of the encoding
     */
    public static void I2OSP(int value, byte[] output, int outOff, int outLen)
    {
        for (int i = outLen - 1; i >= 0; i--)
        {
            output[outOff + i] = (byte)(value >>> (8 * i));
        }
    }

    /**
     * Convert an integer to a byte array of length 8.
     *
     * @param input the integer to convert
     * @return the converted integer
     */
    public static byte[] I2OSP(long input)
    {
        byte[] output = new byte[8];
        output[0] = (byte)input;
        output[1] = (byte)(input >>> 8);
        output[2] = (byte)(input >>> 16);
        output[3] = (byte)(input >>> 24);
        output[4] = (byte)(input >>> 32);
        output[5] = (byte)(input >>> 40);
        output[6] = (byte)(input >>> 48);
        output[7] = (byte)(input >>> 56);
        return output;
    }

    /**
     * Convert an integer to a byte array of length 8.
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outOff offset in output array where the result is stored
     */
    public static void I2OSP(long input, byte[] output, int outOff)
    {
        output[outOff++] = (byte)input;
        output[outOff++] = (byte)(input >>> 8);
        output[outOff++] = (byte)(input >>> 16);
        output[outOff++] = (byte)(input >>> 24);
        output[outOff++] = (byte)(input >>> 32);
        output[outOff++] = (byte)(input >>> 40);
        output[outOff++] = (byte)(input >>> 48);
        output[outOff] = (byte)(input >>> 56);
    }

    /**
     * Convert an int array to a byte array of the specified length. No length
     * checking is performed (i.e., if the last integer cannot be encoded with
     * <tt>length % 4</tt> octets, it is truncated).
     *
     * @param input  the int array
     * @param outLen the length of the converted array
     * @return the converted array
     */
    public static byte[] toByteArray(int[] input, int outLen)
    {
        int intLen = input.length;
        byte[] result = new byte[outLen];
        int index = 0;
        for (int i = 0; i <= intLen - 2; i++, index += 4)
        {
            I2OSP(input[i], result, index);
        }
        I2OSP(input[intLen - 1], result, index, outLen - index);
        return result;
    }

    /**
     * Convert a byte array to an int array.
     *
     * @param input the byte array
     * @return the converted array
     */
    public static int[] toIntArray(byte[] input)
    {
        int intLen = (input.length + 3) / 4;
        int lastLen = input.length & 0x03;
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
