package org.bouncycastle.pqc.math.linearalgebra;

import java.math.BigInteger;

/**
 *
 *
 *
 */
public final class IntUtils
{

    /**
     * Default constructor (private).
     */
    private IntUtils()
    {
        // empty
    }

    /**
     * Compare two int arrays. No null checks are performed.
     *
     * @param left  the first int array
     * @param right the second int array
     * @return the result of the comparison
     */
    public static boolean equals(int[] left, int[] right)
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
     * Return a clone of the given int array. No null checks are performed.
     *
     * @param array the array to clone
     * @return the clone of the given array
     */
    public static int[] clone(int[] array)
    {
        int[] result = new int[array.length];
        System.arraycopy(array, 0, result, 0, array.length);
        return result;
    }

    /**
     * Fill the given int array with the given value.
     *
     * @param array the array
     * @param value the value
     */
    public static void fill(int[] array, int value)
    {
        for (int i = array.length - 1; i >= 0; i--)
        {
            array[i] = value;
        }
    }

    /**
     * Sorts this array of integers according to the Quicksort algorithm. After
     * calling this method this array is sorted in ascending order with the
     * smallest integer taking position 0 in the array.
     * <p>
     * This implementation is based on the quicksort algorithm as described in
     * <code>Data Structures In Java</code> by Thomas A. Standish, Chapter 10,
     * ISBN 0-201-30564-X.
     *
     * @param source the array of integers that needs to be sorted.
     */
    public static void quicksort(int[] source)
    {
        quicksort(source, 0, source.length - 1);
    }

    /**
     * Sort a subarray of a source array. The subarray is specified by its start
     * and end index.
     *
     * @param source the int array to be sorted
     * @param left   the start index of the subarray
     * @param right  the end index of the subarray
     */
    public static void quicksort(int[] source, int left, int right)
    {
        if (right > left)
        {
            int index = partition(source, left, right, right);
            quicksort(source, left, index - 1);
            quicksort(source, index + 1, right);
        }
    }

    /**
     * Split a subarray of a source array into two partitions. The left
     * partition contains elements that have value less than or equal to the
     * pivot element, the right partition contains the elements that have larger
     * value.
     *
     * @param source     the int array whose subarray will be splitted
     * @param left       the start position of the subarray
     * @param right      the end position of the subarray
     * @param pivotIndex the index of the pivot element inside the array
     * @return the new index of the pivot element inside the array
     */
    private static int partition(int[] source, int left, int right,
                                 int pivotIndex)
    {

        int pivot = source[pivotIndex];
        source[pivotIndex] = source[right];
        source[right] = pivot;

        int index = left;

        for (int i = left; i < right; i++)
        {
            if (source[i] <= pivot)
            {
                int tmp = source[index];
                source[index] = source[i];
                source[i] = tmp;
                index++;
            }
        }

        int tmp = source[index];
        source[index] = source[right];
        source[right] = tmp;

        return index;
    }

    /**
     * Generates a subarray of a given int array.
     *
     * @param input -
     *              the input int array
     * @param start -
     *              the start index
     * @param end   -
     *              the end index
     * @return a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
     *         <tt>end</tt>
     */
    public static int[] subArray(final int[] input, final int start,
                                 final int end)
    {
        int[] result = new int[end - start];
        System.arraycopy(input, start, result, 0, end - start);
        return result;
    }

    /**
     * Convert an int array to a {@link FlexiBigInt} array.
     *
     * @param input the int array
     * @return the {@link FlexiBigInt} array
     */
    public static BigInteger[] toFlexiBigIntArray(int[] input)
    {
        BigInteger[] result = new BigInteger[input.length];
        for (int i = 0; i < input.length; i++)
        {
            result[i] = BigInteger.valueOf(input[i]);
        }
        return result;
    }

    /**
     * @param input an int array
     * @return a human readable form of the given int array
     */
    public static String toString(int[] input)
    {
        String result = "";
        for (int i = 0; i < input.length; i++)
        {
            result += input[i] + " ";
        }
        return result;
    }

    /**
     * @param input an int arary
     * @return the int array as hex string
     */
    public static String toHexString(int[] input)
    {
        return ByteUtils.toHexString(BigEndianConversions.toByteArray(input));
    }

}
