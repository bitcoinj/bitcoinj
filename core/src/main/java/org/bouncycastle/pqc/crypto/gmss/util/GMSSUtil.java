package org.bouncycastle.pqc.crypto.gmss.util;

/**
 * This class provides several methods that are required by the GMSS classes.
 */
public class GMSSUtil
{
    /**
     * Converts a 32 bit integer into a byte array beginning at
     * <code>offset</code> (little-endian representation)
     *
     * @param value the integer to convert
     */
    public byte[] intToBytesLittleEndian(int value)
    {
        byte[] bytes = new byte[4];

        bytes[0] = (byte)((value) & 0xff);
        bytes[1] = (byte)((value >> 8) & 0xff);
        bytes[2] = (byte)((value >> 16) & 0xff);
        bytes[3] = (byte)((value >> 24) & 0xff);
        return bytes;
    }

    /**
     * Converts a byte array beginning at <code>offset</code> into a 32 bit
     * integer (little-endian representation)
     *
     * @param bytes the byte array
     * @return The resulting integer
     */
    public int bytesToIntLittleEndian(byte[] bytes)
    {

        return ((bytes[0] & 0xff)) | ((bytes[1] & 0xff) << 8)
            | ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff)) << 24;
    }

    /**
     * Converts a byte array beginning at <code>offset</code> into a 32 bit
     * integer (little-endian representation)
     *
     * @param bytes  the byte array
     * @param offset the integer offset into the byte array
     * @return The resulting integer
     */
    public int bytesToIntLittleEndian(byte[] bytes, int offset)
    {
        return ((bytes[offset++] & 0xff)) | ((bytes[offset++] & 0xff) << 8)
            | ((bytes[offset++] & 0xff) << 16)
            | ((bytes[offset] & 0xff)) << 24;
    }

    /**
     * This method concatenates a 2-dimensional byte array into a 1-dimensional
     * byte array
     *
     * @param arraycp a 2-dimensional byte array.
     * @return 1-dimensional byte array with concatenated input array
     */
    public byte[] concatenateArray(byte[][] arraycp)
    {
        byte[] dest = new byte[arraycp.length * arraycp[0].length];
        int indx = 0;
        for (int i = 0; i < arraycp.length; i++)
        {
            System.arraycopy(arraycp[i], 0, dest, indx, arraycp[i].length);
            indx = indx + arraycp[i].length;
        }
        return dest;
    }

    /**
     * This method prints the values of a 2-dimensional byte array
     *
     * @param text  a String
     * @param array a 2-dimensional byte array
     */
    public void printArray(String text, byte[][] array)
    {
        System.out.println(text);
        int counter = 0;
        for (int i = 0; i < array.length; i++)
        {
            for (int j = 0; j < array[0].length; j++)
            {
                System.out.println(counter + "; " + array[i][j]);
                counter++;
            }
        }
    }

    /**
     * This method prints the values of a 1-dimensional byte array
     *
     * @param text  a String
     * @param array a 1-dimensional byte array.
     */
    public void printArray(String text, byte[] array)
    {
        System.out.println(text);
        int counter = 0;
        for (int i = 0; i < array.length; i++)
        {
            System.out.println(counter + "; " + array[i]);
            counter++;
        }
    }

    /**
     * This method tests if an integer is a power of 2.
     *
     * @param testValue an integer
     * @return <code>TRUE</code> if <code>testValue</code> is a power of 2,
     *         <code>FALSE</code> otherwise
     */
    public boolean testPowerOfTwo(int testValue)
    {
        int a = 1;
        while (a < testValue)
        {
            a <<= 1;
        }
        if (testValue == a)
        {
            return true;
        }

        return false;
    }

    /**
     * This method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intValue</code>.
     *
     * @param intValue an integer
     * @return The least integer greater or equal to the logarithm to the base 2
     *         of <code>intValue</code>
     */
    public int getLog(int intValue)
    {
        int log = 1;
        int i = 2;
        while (i < intValue)
        {
            i <<= 1;
            log++;
        }
        return log;
    }
}
