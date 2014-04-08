package org.bouncycastle.pqc.crypto.rainbow.util;

/**
 * This class is needed for the conversions while encoding and decoding, as well as for
 * comparison between arrays of some dimensions
 */
public class RainbowUtil
{

    /**
     * This function converts an one-dimensional array of bytes into a
     * one-dimensional array of int
     *
     * @param in the array to be converted
     * @return out
     *         the one-dimensional int-array that corresponds the input
     */
    public static int[] convertArraytoInt(byte[] in)
    {
        int[] out = new int[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = in[i] & GF2Field.MASK;
        }
        return out;
    }

    /**
     * This function converts an one-dimensional array of bytes into a
     * one-dimensional array of type short
     *
     * @param in the array to be converted
     * @return out
     *         one-dimensional short-array that corresponds the input
     */
    public static short[] convertArray(byte[] in)
    {
        short[] out = new short[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (short)(in[i] & GF2Field.MASK);
        }
        return out;
    }

    /**
     * This function converts a matrix of bytes into a matrix of type short
     *
     * @param in the matrix to be converted
     * @return out
     *         short-matrix that corresponds the input
     */
    public static short[][] convertArray(byte[][] in)
    {
        short[][] out = new short[in.length][in[0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                out[i][j] = (short)(in[i][j] & GF2Field.MASK);
            }
        }
        return out;
    }

    /**
     * This function converts a 3-dimensional array of bytes into a 3-dimensional array of type short
     *
     * @param in the array to be converted
     * @return out
     *         short-array that corresponds the input
     */
    public static short[][][] convertArray(byte[][][] in)
    {
        short[][][] out = new short[in.length][in[0].length][in[0][0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                for (int k = 0; k < in[0][0].length; k++)
                {
                    out[i][j][k] = (short)(in[i][j][k] & GF2Field.MASK);
                }
            }
        }
        return out;
    }

    /**
     * This function converts an array of type int into an array of type byte
     *
     * @param in the array to be converted
     * @return out
     *         the byte-array that corresponds the input
     */
    public static byte[] convertIntArray(int[] in)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (byte)in[i];
        }
        return out;
    }


    /**
     * This function converts an array of type short into an array of type byte
     *
     * @param in the array to be converted
     * @return out
     *         the byte-array that corresponds the input
     */
    public static byte[] convertArray(short[] in)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (byte)in[i];
        }
        return out;
    }

    /**
     * This function converts a matrix of type short into a matrix of type byte
     *
     * @param in the matrix to be converted
     * @return out
     *         the byte-matrix that corresponds the input
     */
    public static byte[][] convertArray(short[][] in)
    {
        byte[][] out = new byte[in.length][in[0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                out[i][j] = (byte)in[i][j];
            }
        }
        return out;
    }

    /**
     * This function converts a 3-dimensional array of type short into a 3-dimensional array of type byte
     *
     * @param in the array to be converted
     * @return out
     *         the byte-array that corresponds the input
     */
    public static byte[][][] convertArray(short[][][] in)
    {
        byte[][][] out = new byte[in.length][in[0].length][in[0][0].length];
        for (int i = 0; i < in.length; i++)
        {
            for (int j = 0; j < in[0].length; j++)
            {
                for (int k = 0; k < in[0][0].length; k++)
                {
                    out[i][j][k] = (byte)in[i][j][k];
                }
            }
        }
        return out;
    }

    /**
     * Compare two short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[] left, short[] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= left[i] == right[i];
        }
        return result;
    }

    /**
     * Compare two two-dimensional short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[][] left, short[][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= equals(left[i], right[i]);
        }
        return result;
    }

    /**
     * Compare two three-dimensional short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[][][] left, short[][][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= equals(left[i], right[i]);
        }
        return result;
    }

}
